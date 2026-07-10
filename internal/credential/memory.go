package credential

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strconv"
	"sync"
	"time"
)

type MemoryRepositoryOptions struct {
	Clock       func() time.Time
	TokenSource func() (string, error)
}

type memoryRevocationRecord struct {
	revocation           Revocation
	protected            ProtectedReference
	actionTokenSHA256    string
	claimTokenSHA256     string
	completedClaimSHA256 string
	completedClaimEpoch  int64
	completedClaimWorker string
	confirmations        map[string]ExternalConfirmation
}

type memoryPreparedClaim struct {
	record   *memoryRevocationRecord
	token    string
	accessor *SensitiveReference
}

type MemoryRepository struct {
	mu           sync.Mutex
	actions      ActionFenceSource
	protector    ReferenceProtector
	clock        func() time.Time
	tokenSource  func() (string, error)
	records      map[string]*memoryRevocationRecord
	actionEpochs map[string]string
}

var _ Repository = (*MemoryRepository)(nil)

func NewMemoryRepository(actions ActionFenceSource, protector ReferenceProtector, options MemoryRepositoryOptions) (*MemoryRepository, error) {
	if actions == nil || protector == nil {
		return nil, ErrInvalidRevocationRequest
	}
	if options.Clock == nil {
		options.Clock = time.Now
	}
	if options.TokenSource == nil {
		options.TokenSource = randomRevocationToken
	}
	if options.Clock().IsZero() {
		return nil, ErrInvalidRevocationRequest
	}
	return &MemoryRepository{
		actions: actions, protector: protector, clock: options.Clock, tokenSource: options.TokenSource,
		records: make(map[string]*memoryRevocationRecord), actionEpochs: make(map[string]string),
	}, nil
}

func (repository *MemoryRepository) Prepare(ctx context.Context, request PrepareRequest) (PrepareResult, error) {
	if err := contextError(ctx); err != nil {
		return PrepareResult{}, err
	}
	request.CredentialExpiresAt = CanonicalCredentialExpiry(request.CredentialExpiresAt)
	now := repository.now()
	if !ValidRevocationID(request.RevocationID) || !validActionFence(request.Fence) ||
		!ValidOpaqueText(request.Issuer, 256) || request.CredentialExpiresAt.IsZero() || !request.CredentialExpiresAt.After(now) ||
		request.CredentialExpiresAt.After(CanonicalCredentialExpiry(now.Add(MaxCredentialTTL))) {
		return PrepareResult{}, ErrInvalidRevocationRequest
	}
	metadata, err := repository.resolvePrepareAction(ctx, request.Fence, now)
	if err != nil {
		return PrepareResult{}, err
	}
	if request.CredentialExpiresAt.After(metadata.AuthorizationExpiresAt) {
		return PrepareResult{}, ErrInvalidRevocationRequest
	}

	revalidated, err := repository.resolvePrepareAction(ctx, request.Fence, repository.now())
	if err != nil {
		return PrepareResult{}, err
	}
	if !sameActionScope(metadata, revalidated) {
		return PrepareResult{}, ErrStaleActionFence
	}
	if request.CredentialExpiresAt.After(revalidated.AuthorizationExpiresAt) {
		return PrepareResult{}, ErrStaleActionFence
	}
	metadata = revalidated
	// The in-memory reference implementation cannot hold an external action
	// source lock across this boundary. Keep the global lock order action then
	// repository to avoid deadlocks; PostgreSQL provides the durable atomic
	// action-row lock used in production.
	repository.mu.Lock()
	defer repository.mu.Unlock()
	key := actionEpochKey(request.Fence.ActionID, request.Fence.Epoch)
	if existingID, ok := repository.actionEpochs[key]; ok {
		existing := repository.records[existingID]
		if existing == nil || !samePrepare(existing.revocation, request, metadata) ||
			existing.actionTokenSHA256 != SHA256Hex([]byte(request.Fence.Token)) {
			return PrepareResult{}, ErrIdempotencyConflict
		}
		if candidate := repository.records[request.RevocationID]; candidate != nil && candidate != existing {
			return PrepareResult{}, ErrIdempotencyConflict
		}
		return PrepareResult{Revocation: publicMemoryRevocation(existing)}, nil
	}
	if existing := repository.records[request.RevocationID]; existing != nil {
		if !samePrepare(existing.revocation, request, metadata) ||
			existing.actionTokenSHA256 != SHA256Hex([]byte(request.Fence.Token)) {
			return PrepareResult{}, ErrIdempotencyConflict
		}
		return PrepareResult{Revocation: publicMemoryRevocation(existing)}, nil
	}

	revocation := Revocation{
		ID: request.RevocationID, TenantID: metadata.TenantID, WorkspaceID: metadata.WorkspaceID,
		EnvironmentID: metadata.EnvironmentID, ActionID: metadata.ActionID, TargetKey: metadata.TargetKey,
		Production: metadata.Production, RunnerID: metadata.RunnerID, ActionLeaseEpoch: metadata.LeaseEpoch,
		Issuer: request.Issuer, ConnectorID: metadata.ConnectorID, Permission: metadata.Permission, Resource: metadata.Resource,
		CredentialExpiresAt: request.CredentialExpiresAt, Status: StatusPrepared, AvailableAt: now,
		CreatedAt: now, UpdatedAt: now, Version: 1,
	}
	record := &memoryRevocationRecord{
		revocation: revocation, actionTokenSHA256: SHA256Hex([]byte(request.Fence.Token)),
		confirmations: make(map[string]ExternalConfirmation),
	}
	repository.records[request.RevocationID] = record
	repository.actionEpochs[key] = request.RevocationID
	return PrepareResult{Revocation: publicMemoryRevocation(record), Created: true}, nil
}

func (repository *MemoryRepository) RecordAnchor(ctx context.Context, request RecordAnchorRequest) (Revocation, error) {
	if err := contextError(ctx); err != nil {
		return Revocation{}, err
	}
	if !ValidRevocationID(request.RevocationID) || !validActionFence(request.Fence) || !ValidSensitiveReference(request.Accessor) {
		return Revocation{}, ErrInvalidRevocationRequest
	}
	inspection, err := repository.actions.InspectAction(ctx, request.Fence.ActionID)
	if err != nil {
		if ctx.Err() != nil {
			return Revocation{}, ctx.Err()
		}
		return Revocation{}, ErrStaleActionFence
	}
	now := repository.now()

	repository.mu.Lock()
	defer repository.mu.Unlock()
	record := repository.records[request.RevocationID]
	if record == nil {
		return Revocation{}, ErrRevocationNotFound
	}
	if !frozenActionFenceMatches(record, request.Fence) || !inspectionScopeMatches(record.revocation, inspection.Metadata) {
		return Revocation{}, ErrStaleActionFence
	}
	current := inspectionFenceCurrent(record, inspection, now, 0)
	if record.revocation.Status != StatusPrepared {
		if record.revocation.Status == StatusNoCredential || record.revocation.Status == StatusRevoked || len(record.protected.Ciphertext) == 0 {
			return Revocation{}, ErrInvalidTransition
		}
		matches, matchErr := repository.protector.Matches(referenceContext(record.revocation), record.protected, request.Accessor)
		if matchErr != nil {
			return Revocation{}, ErrReferenceProtection
		}
		if !matches {
			return Revocation{}, ErrIdempotencyConflict
		}
		if record.revocation.Status == StatusAnchored || record.revocation.Status == StatusActive {
			finalNow := repository.now()
			current = current && inspectionFenceCurrent(record, inspection, finalNow, MinPostChildFenceWindow)
			if !current {
				if err := applyRequestRevocation(record, finalNow); err != nil {
					return Revocation{}, err
				}
			}
		}
		return publicMemoryRevocation(record), nil
	}
	protected, err := repository.protector.Protect(referenceContext(record.revocation), request.Accessor)
	if err != nil {
		return Revocation{}, ErrReferenceProtection
	}
	finalNow := repository.now()
	current = current && inspectionFenceCurrent(record, inspection, finalNow, MinPostChildFenceWindow)
	record.protected = protected.clone()
	record.revocation.Status = StatusAnchored
	record.revocation.AccessorPresent = true
	record.revocation.AccessorHMAC = hex.EncodeToString(protected.AccessorHMAC)
	record.revocation.EncryptionKeyID = protected.KeyID
	record.revocation.AnchoredAt = finalNow
	record.bump(finalNow)
	if !current {
		if err := applyRequestRevocation(record, finalNow); err != nil {
			return Revocation{}, err
		}
	}
	return publicMemoryRevocation(record), nil
}

func (repository *MemoryRepository) Activate(ctx context.Context, request ActionTransitionRequest) (Revocation, error) {
	if err := contextError(ctx); err != nil {
		return Revocation{}, err
	}
	if !ValidRevocationID(request.RevocationID) || !validActionFence(request.Fence) {
		return Revocation{}, ErrInvalidRevocationRequest
	}
	inspection, err := repository.actions.InspectAction(ctx, request.Fence.ActionID)
	if err != nil {
		if ctx.Err() != nil {
			return Revocation{}, ctx.Err()
		}
		return Revocation{}, ErrStaleActionFence
	}
	now := repository.now()
	repository.mu.Lock()
	defer repository.mu.Unlock()
	record := repository.records[request.RevocationID]
	if record == nil {
		return Revocation{}, ErrRevocationNotFound
	}
	if !frozenActionFenceMatches(record, request.Fence) || !inspectionScopeMatches(record.revocation, inspection.Metadata) {
		return Revocation{}, ErrStaleActionFence
	}
	current := inspectionFenceCurrent(record, inspection, now, 0)
	switch record.revocation.Status {
	case StatusAnchored:
		if !current {
			if err := applyRequestRevocation(record, now); err != nil {
				return Revocation{}, err
			}
			return publicMemoryRevocation(record), nil
		}
		record.revocation.Status = StatusActive
		record.revocation.ActivatedAt = now
		record.bump(now)
	case StatusActive:
	case StatusRevocationPending, StatusRevoking, StatusManualRequired, StatusRevoked:
		return publicMemoryRevocation(record), nil
	default:
		return Revocation{}, ErrInvalidTransition
	}
	finalNow := repository.now()
	if !inspectionFenceCurrent(record, inspection, finalNow, MinPostChildFenceWindow) {
		if err := applyRequestRevocation(record, finalNow); err != nil {
			return Revocation{}, err
		}
	}
	return publicMemoryRevocation(record), nil
}

func (repository *MemoryRepository) RecordNoCredential(ctx context.Context, request ActionTransitionRequest) (Revocation, error) {
	return repository.actionTransition(ctx, request, func(record *memoryRevocationRecord, now time.Time) error {
		switch record.revocation.Status {
		case StatusPrepared:
			record.revocation.Status = StatusNoCredential
			record.bump(now)
		case StatusNoCredential:
			return nil
		default:
			return ErrInvalidTransition
		}
		return nil
	})
}

func (repository *MemoryRepository) RecoverPrepared(ctx context.Context, request RecoverPreparedRequest) ([]Revocation, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if request.Limit < 1 || request.Limit > MaxRevocationClaimBatch {
		return nil, ErrInvalidRevocationRequest
	}
	now := repository.now()
	repository.mu.Lock()
	defer repository.mu.Unlock()
	candidates := make([]*memoryRevocationRecord, 0, request.Limit)
	for _, record := range repository.records {
		// Recovery is tied directly to the durable absolute child deadline.
		eligibleAt := record.revocation.CredentialExpiresAt.Add(PreparedRecoveryGrace)
		if record.revocation.Status == StatusPrepared && len(record.protected.Ciphertext) == 0 &&
			!eligibleAt.After(now) {
			candidates = append(candidates, record)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		if !candidates[i].revocation.CredentialExpiresAt.Equal(candidates[j].revocation.CredentialExpiresAt) {
			return candidates[i].revocation.CredentialExpiresAt.Before(candidates[j].revocation.CredentialExpiresAt)
		}
		return candidates[i].revocation.ID < candidates[j].revocation.ID
	})
	if len(candidates) > request.Limit {
		candidates = candidates[:request.Limit]
	}
	recovered := make([]Revocation, 0, len(candidates))
	for _, record := range candidates {
		record.revocation.Status = StatusNoCredential
		record.bump(now)
		recovered = append(recovered, publicMemoryRevocation(record))
	}
	return recovered, nil
}

func (repository *MemoryRepository) RequestRevocation(ctx context.Context, request ActionTransitionRequest) (Revocation, error) {
	if request.Fence == (ActionFence{}) {
		if err := contextError(ctx); err != nil {
			return Revocation{}, err
		}
		if !ValidRevocationID(request.RevocationID) {
			return Revocation{}, ErrInvalidRevocationRequest
		}
		now := repository.now()
		repository.mu.Lock()
		defer repository.mu.Unlock()
		record := repository.records[request.RevocationID]
		if record == nil {
			return Revocation{}, ErrRevocationNotFound
		}
		if err := applyRequestRevocation(record, now); err != nil {
			return Revocation{}, err
		}
		return publicMemoryRevocation(record), nil
	}
	return repository.actionTransition(ctx, request, func(record *memoryRevocationRecord, now time.Time) error {
		return applyRequestRevocation(record, now)
	})
}

func applyRequestRevocation(record *memoryRevocationRecord, now time.Time) error {
	switch record.revocation.Status {
	case StatusAnchored, StatusActive:
		record.revocation.Status = StatusRevocationPending
		record.revocation.AvailableAt = now
		record.revocation.RevocationRequestedAt = now
		record.bump(now)
	case StatusRevocationPending, StatusRevoking, StatusManualRequired, StatusRevoked:
		return nil
	default:
		return ErrInvalidTransition
	}
	return nil
}

func (repository *MemoryRepository) ClaimRevocations(ctx context.Context, request ClaimRevocationsRequest) ([]ClaimedRevocation, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if !ValidIdentifier(request.WorkerID, 256) || request.Limit < 1 || request.Limit > MaxRevocationClaimBatch ||
		!validClaimDuration(request.LeaseDuration) {
		return nil, ErrInvalidRevocationRequest
	}
	now := repository.now()
	repository.mu.Lock()
	defer repository.mu.Unlock()

	candidates := make([]*memoryRevocationRecord, 0, request.Limit)
	for _, record := range repository.records {
		pending := record.revocation.Status == StatusRevocationPending && !record.revocation.AvailableAt.After(now)
		expired := record.revocation.Status == StatusRevoking && !record.revocation.ClaimExpiresAt.After(now)
		if pending || expired {
			candidates = append(candidates, record)
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		left, right := candidates[i].revocation, candidates[j].revocation
		if !left.AvailableAt.Equal(right.AvailableAt) {
			return left.AvailableAt.Before(right.AvailableAt)
		}
		if !left.CreatedAt.Equal(right.CreatedAt) {
			return left.CreatedAt.Before(right.CreatedAt)
		}
		return left.ID < right.ID
	})
	if len(candidates) > request.Limit {
		candidates = candidates[:request.Limit]
	}
	prepared := make([]memoryPreparedClaim, 0, len(candidates))
	for _, record := range candidates {
		if record.revocation.ClaimEpoch == math.MaxInt64 {
			destroyPreparedClaims(prepared)
			return nil, ErrInvalidTransition
		}
		token, err := repository.tokenSource()
		if err != nil || !ValidOpaqueText(token, 4096) {
			destroyPreparedClaims(prepared)
			return nil, fmt.Errorf("generate credential revocation claim token: %w", ErrInvalidRevocationRequest)
		}
		accessor, err := repository.protector.Unprotect(referenceContext(record.revocation), record.protected)
		if err != nil {
			destroyPreparedClaims(prepared)
			return nil, ErrReferenceProtection
		}
		prepared = append(prepared, memoryPreparedClaim{record: record, token: token, accessor: accessor})
	}

	claims := make([]ClaimedRevocation, 0, len(prepared))
	for _, item := range prepared {
		record := item.record
		record.revocation.Status = StatusRevoking
		record.revocation.ClaimEpoch++
		record.revocation.ClaimedBy = request.WorkerID
		record.revocation.ClaimedAt = now
		record.revocation.LastHeartbeatAt = now
		record.revocation.ClaimExpiresAt = now.Add(request.LeaseDuration)
		record.revocation.Attempt++
		record.claimTokenSHA256 = SHA256Hex([]byte(item.token))
		record.bump(now)
		claims = append(claims, ClaimedRevocation{
			Revocation: publicMemoryRevocation(record),
			Fence:      ClaimFence{RevocationID: record.revocation.ID, WorkerID: request.WorkerID, Token: item.token, Epoch: record.revocation.ClaimEpoch},
			Accessor:   item.accessor,
		})
	}
	return claims, nil
}

func (repository *MemoryRepository) Heartbeat(ctx context.Context, request HeartbeatRequest) (Revocation, error) {
	if err := contextError(ctx); err != nil {
		return Revocation{}, err
	}
	if !validClaimFence(request.Fence) || !validClaimDuration(request.Extension) {
		return Revocation{}, ErrInvalidRevocationRequest
	}
	now := repository.now()
	repository.mu.Lock()
	defer repository.mu.Unlock()
	record, err := repository.claimRecord(request.Fence, now)
	if err != nil {
		return Revocation{}, err
	}
	record.revocation.LastHeartbeatAt = now
	record.revocation.ClaimExpiresAt = now.Add(request.Extension)
	record.bump(now)
	return publicMemoryRevocation(record), nil
}

func (repository *MemoryRepository) CompleteRevocation(ctx context.Context, request CompleteRevocationRequest) (Revocation, error) {
	if err := contextError(ctx); err != nil {
		return Revocation{}, err
	}
	if !validClaimFence(request.Fence) {
		return Revocation{}, ErrInvalidRevocationRequest
	}
	now := repository.now()
	repository.mu.Lock()
	defer repository.mu.Unlock()
	record := repository.records[request.Fence.RevocationID]
	if record == nil {
		return Revocation{}, ErrRevocationNotFound
	}
	digest := SHA256Hex([]byte(request.Fence.Token))
	if record.revocation.Status == StatusRevoked {
		if record.completedClaimSHA256 == digest && record.completedClaimEpoch == request.Fence.Epoch &&
			record.completedClaimWorker == request.Fence.WorkerID {
			return publicMemoryRevocation(record), nil
		}
		return Revocation{}, ErrStaleClaim
	}
	if !matchesMemoryClaim(record, request.Fence, digest, now) {
		return Revocation{}, ErrStaleClaim
	}
	record.completedClaimSHA256 = digest
	record.completedClaimEpoch = request.Fence.Epoch
	record.completedClaimWorker = request.Fence.WorkerID
	record.revocation.Status = StatusRevoked
	record.revocation.RevokedAt = now
	record.clearActiveClaim()
	record.clearProtectedReference()
	record.bump(now)
	return publicMemoryRevocation(record), nil
}

func (repository *MemoryRepository) RetryRevocation(ctx context.Context, request RetryRevocationRequest) (Revocation, error) {
	if request.Delay < 0 || request.Delay > MaxRevocationRetryDelay || !validFailure(request.FailureCode, request.FailureDetail) {
		return Revocation{}, ErrInvalidRevocationRequest
	}
	return repository.failClaim(ctx, request.Fence, request.FailureCode, request.FailureDetail, func(record *memoryRevocationRecord, now time.Time) {
		record.revocation.Status = StatusRevocationPending
		record.revocation.AvailableAt = now.Add(request.Delay)
	})
}

func (repository *MemoryRepository) RequireManual(ctx context.Context, request RequireManualRequest) (Revocation, error) {
	if !validFailure(request.FailureCode, request.FailureDetail) {
		return Revocation{}, ErrInvalidRevocationRequest
	}
	return repository.failClaim(ctx, request.Fence, request.FailureCode, request.FailureDetail, func(record *memoryRevocationRecord, now time.Time) {
		record.revocation.Status = StatusManualRequired
		record.revocation.ManualRequiredAt = now
	})
}

func (repository *MemoryRepository) RequeueManual(ctx context.Context, request RequeueManualRequest) (Revocation, error) {
	if err := contextError(ctx); err != nil {
		return Revocation{}, err
	}
	if !ValidRevocationID(request.RevocationID) || !validSubject(request.ActorSubject) {
		return Revocation{}, ErrInvalidRevocationRequest
	}
	now := repository.now()
	repository.mu.Lock()
	defer repository.mu.Unlock()
	record := repository.records[request.RevocationID]
	if record == nil {
		return Revocation{}, ErrRevocationNotFound
	}
	if record.revocation.Status == StatusRevocationPending {
		return publicMemoryRevocation(record), nil
	}
	if record.revocation.Status != StatusManualRequired || record.revocation.EvidenceHash != "" || len(record.confirmations) != 0 {
		return Revocation{}, ErrInvalidTransition
	}
	record.revocation.Status = StatusRevocationPending
	record.revocation.AvailableAt = now
	record.bump(now)
	return publicMemoryRevocation(record), nil
}

func (repository *MemoryRepository) SubmitExternalConfirmation(ctx context.Context, request ExternalConfirmationRequest) (ConfirmationResult, error) {
	if err := contextError(ctx); err != nil {
		return ConfirmationResult{}, err
	}
	if !ValidRevocationID(request.RevocationID) || !validSubject(request.Subject) || !ValidSHA256(request.EvidenceHash) {
		return ConfirmationResult{}, ErrInvalidRevocationRequest
	}
	now := repository.now()
	repository.mu.Lock()
	defer repository.mu.Unlock()
	record := repository.records[request.RevocationID]
	if record == nil {
		return ConfirmationResult{}, ErrRevocationNotFound
	}
	if record.revocation.Status != StatusManualRequired && record.revocation.Status != StatusRevoked {
		return ConfirmationResult{}, ErrInvalidTransition
	}
	if record.revocation.EvidenceHash != "" && record.revocation.EvidenceHash != request.EvidenceHash {
		return ConfirmationResult{}, ErrEvidenceConflict
	}
	if existing, ok := record.confirmations[request.Subject]; ok {
		if existing.EvidenceHash != request.EvidenceHash || existing.PlatformAdmin != request.PlatformAdmin {
			return ConfirmationResult{}, ErrEvidenceConflict
		}
		return confirmationResult(record), nil
	}
	if record.revocation.Status == StatusRevoked {
		return ConfirmationResult{}, ErrInvalidTransition
	}
	if len(record.confirmations) >= 1 && !request.PlatformAdmin && !hasPlatformAdmin(record.confirmations) {
		return ConfirmationResult{}, ErrPlatformAdminRequired
	}
	record.confirmations[request.Subject] = ExternalConfirmation{
		Subject: request.Subject, EvidenceHash: request.EvidenceHash, PlatformAdmin: request.PlatformAdmin, CreatedAt: now,
	}
	record.revocation.EvidenceHash = request.EvidenceHash
	record.bump(now)
	if len(record.confirmations) >= 2 {
		if !hasPlatformAdmin(record.confirmations) {
			delete(record.confirmations, request.Subject)
			return ConfirmationResult{}, ErrPlatformAdminRequired
		}
		record.revocation.Status = StatusRevoked
		record.revocation.RevokedAt = now
		record.clearProtectedReference()
	}
	return confirmationResult(record), nil
}

func (repository *MemoryRepository) Get(ctx context.Context, revocationID string) (Revocation, error) {
	if err := contextError(ctx); err != nil {
		return Revocation{}, err
	}
	if !ValidRevocationID(revocationID) {
		return Revocation{}, ErrInvalidRevocationRequest
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	record := repository.records[revocationID]
	if record == nil {
		return Revocation{}, ErrRevocationNotFound
	}
	return publicMemoryRevocation(record), nil
}

func (repository *MemoryRepository) List(ctx context.Context, filter ListFilter) ([]Revocation, error) {
	if err := contextError(ctx); err != nil {
		return nil, err
	}
	if filter.WorkspaceID != "" && !ValidIdentifier(filter.WorkspaceID, 256) ||
		filter.Status != "" && !ValidRevocationStatus(filter.Status) || filter.Limit < 1 || filter.Limit > 1000 {
		return nil, ErrInvalidRevocationRequest
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	items := make([]Revocation, 0, min(filter.Limit, len(repository.records)))
	for _, record := range repository.records {
		if filter.WorkspaceID != "" && record.revocation.WorkspaceID != filter.WorkspaceID {
			continue
		}
		if filter.Status != "" && record.revocation.Status != filter.Status {
			continue
		}
		items = append(items, publicMemoryRevocation(record))
	}
	sort.Slice(items, func(i, j int) bool {
		if !items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].CreatedAt.Before(items[j].CreatedAt)
		}
		return items[i].ID < items[j].ID
	})
	if len(items) > filter.Limit {
		items = items[:filter.Limit]
	}
	return items, nil
}

func (repository *MemoryRepository) actionTransition(ctx context.Context, request ActionTransitionRequest, transition func(*memoryRevocationRecord, time.Time) error) (Revocation, error) {
	if err := contextError(ctx); err != nil {
		return Revocation{}, err
	}
	if !ValidRevocationID(request.RevocationID) || !validActionFence(request.Fence) {
		return Revocation{}, ErrInvalidRevocationRequest
	}
	now := repository.now()
	metadata, err := repository.resolveAction(ctx, request.Fence, now)
	if err != nil {
		return Revocation{}, err
	}
	repository.mu.Lock()
	defer repository.mu.Unlock()
	record, err := repository.actionRecord(request.RevocationID, request.Fence, metadata)
	if err != nil {
		return Revocation{}, err
	}
	if err := transition(record, now); err != nil {
		return Revocation{}, err
	}
	return publicMemoryRevocation(record), nil
}

func (repository *MemoryRepository) failClaim(ctx context.Context, fence ClaimFence, code FailureCode, detail []byte, transition func(*memoryRevocationRecord, time.Time)) (Revocation, error) {
	if err := contextError(ctx); err != nil {
		return Revocation{}, err
	}
	if !validClaimFence(fence) {
		return Revocation{}, ErrInvalidRevocationRequest
	}
	now := repository.now()
	repository.mu.Lock()
	defer repository.mu.Unlock()
	record, err := repository.claimRecord(fence, now)
	if err != nil {
		return Revocation{}, err
	}
	transition(record, now)
	record.revocation.FailureCount++
	record.revocation.FailureCode = code
	record.revocation.FailureDetailSHA256 = SHA256Hex(detail)
	record.clearActiveClaim()
	record.bump(now)
	return publicMemoryRevocation(record), nil
}

func (repository *MemoryRepository) resolveAction(ctx context.Context, fence ActionFence, now time.Time) (ActionMetadata, error) {
	metadata, err := repository.actions.ResolveActionFence(ctx, fence)
	if err != nil {
		if ctx.Err() != nil {
			return ActionMetadata{}, ctx.Err()
		}
		return ActionMetadata{}, ErrStaleActionFence
	}
	if metadata.ActionID != fence.ActionID || metadata.RunnerID != fence.RunnerID || metadata.LeaseEpoch != fence.Epoch ||
		(metadata.Status != ActionStatusLeased && metadata.Status != ActionStatusRunning) || !metadata.LeaseExpiresAt.After(now) ||
		!metadata.AuthorizationExpiresAt.After(now) ||
		!ValidIdentifier(metadata.TenantID, 256) || !ValidIdentifier(metadata.WorkspaceID, 256) ||
		!ValidIdentifier(metadata.EnvironmentID, 256) || !ValidIdentifier(metadata.TargetKey, 512) ||
		!ValidOpaqueText(metadata.ConnectorID, 256) || !ValidOpaqueText(metadata.Permission, 256) ||
		!ValidOpaqueText(metadata.Resource, 2048) {
		return ActionMetadata{}, ErrStaleActionFence
	}
	return metadata, nil
}

func (repository *MemoryRepository) resolvePrepareAction(ctx context.Context, fence ActionFence, now time.Time) (ActionMetadata, error) {
	metadata, err := repository.resolveAction(ctx, fence, now)
	if err != nil {
		return ActionMetadata{}, err
	}
	minimumExpiry := now.Add(MinPrepareFenceWindow)
	if metadata.LeaseExpiresAt.Before(minimumExpiry) || metadata.AuthorizationExpiresAt.Before(minimumExpiry) {
		return ActionMetadata{}, ErrStaleActionFence
	}
	return metadata, nil
}

func sameActionScope(left, right ActionMetadata) bool {
	return left.ActionID == right.ActionID && left.TenantID == right.TenantID && left.WorkspaceID == right.WorkspaceID &&
		left.EnvironmentID == right.EnvironmentID && left.TargetKey == right.TargetKey && left.Production == right.Production &&
		left.RunnerID == right.RunnerID && left.LeaseEpoch == right.LeaseEpoch && left.ConnectorID == right.ConnectorID &&
		left.Permission == right.Permission && left.Resource == right.Resource
}

func frozenActionFenceMatches(record *memoryRevocationRecord, fence ActionFence) bool {
	return record.revocation.ActionID == fence.ActionID && record.revocation.RunnerID == fence.RunnerID &&
		record.revocation.ActionLeaseEpoch == fence.Epoch && record.actionTokenSHA256 == SHA256Hex([]byte(fence.Token))
}

func inspectionScopeMatches(revocation Revocation, metadata ActionMetadata) bool {
	return revocation.ActionID == metadata.ActionID && revocation.TenantID == metadata.TenantID &&
		revocation.WorkspaceID == metadata.WorkspaceID && revocation.EnvironmentID == metadata.EnvironmentID &&
		revocation.TargetKey == metadata.TargetKey && revocation.Production == metadata.Production &&
		revocation.ConnectorID == metadata.ConnectorID && revocation.Permission == metadata.Permission &&
		revocation.Resource == metadata.Resource
}

func inspectionFenceCurrent(
	record *memoryRevocationRecord,
	inspection ActionInspection,
	now time.Time,
	minimumWindow time.Duration,
) bool {
	metadata := inspection.Metadata
	minimumExpiry := now.Add(minimumWindow)
	return (metadata.Status == ActionStatusLeased || metadata.Status == ActionStatusRunning) &&
		metadata.RunnerID == record.revocation.RunnerID && metadata.LeaseEpoch == record.revocation.ActionLeaseEpoch &&
		inspection.LeaseTokenSHA256 == record.actionTokenSHA256 && metadata.LeaseExpiresAt.After(minimumExpiry) &&
		metadata.AuthorizationExpiresAt.After(minimumExpiry) && record.revocation.CredentialExpiresAt.After(minimumExpiry)
}

func (repository *MemoryRepository) actionRecord(id string, fence ActionFence, metadata ActionMetadata) (*memoryRevocationRecord, error) {
	record := repository.records[id]
	if record == nil {
		return nil, ErrRevocationNotFound
	}
	if record.revocation.ActionID != fence.ActionID || record.revocation.RunnerID != fence.RunnerID ||
		record.revocation.ActionLeaseEpoch != fence.Epoch || record.actionTokenSHA256 != SHA256Hex([]byte(fence.Token)) ||
		record.revocation.TenantID != metadata.TenantID || record.revocation.WorkspaceID != metadata.WorkspaceID ||
		record.revocation.EnvironmentID != metadata.EnvironmentID || record.revocation.TargetKey != metadata.TargetKey ||
		record.revocation.Production != metadata.Production || record.revocation.ConnectorID != metadata.ConnectorID ||
		record.revocation.Permission != metadata.Permission || record.revocation.Resource != metadata.Resource {
		return nil, ErrStaleActionFence
	}
	return record, nil
}

func (repository *MemoryRepository) claimRecord(fence ClaimFence, now time.Time) (*memoryRevocationRecord, error) {
	record := repository.records[fence.RevocationID]
	if record == nil {
		return nil, ErrRevocationNotFound
	}
	if !matchesMemoryClaim(record, fence, SHA256Hex([]byte(fence.Token)), now) {
		return nil, ErrStaleClaim
	}
	return record, nil
}

func matchesMemoryClaim(record *memoryRevocationRecord, fence ClaimFence, digest string, now time.Time) bool {
	return record.revocation.Status == StatusRevoking && record.revocation.ClaimedBy == fence.WorkerID &&
		record.revocation.ClaimEpoch == fence.Epoch && record.claimTokenSHA256 == digest && record.revocation.ClaimExpiresAt.After(now)
}

func samePrepare(existing Revocation, request PrepareRequest, metadata ActionMetadata) bool {
	return existing.ActionID == metadata.ActionID && existing.TenantID == metadata.TenantID &&
		existing.WorkspaceID == metadata.WorkspaceID && existing.EnvironmentID == metadata.EnvironmentID &&
		existing.TargetKey == metadata.TargetKey && existing.Production == metadata.Production && existing.RunnerID == metadata.RunnerID &&
		existing.ActionLeaseEpoch == metadata.LeaseEpoch && existing.Issuer == request.Issuer &&
		existing.ConnectorID == metadata.ConnectorID && existing.Permission == metadata.Permission && existing.Resource == metadata.Resource &&
		existing.CredentialExpiresAt.Equal(CanonicalCredentialExpiry(request.CredentialExpiresAt))
}

func (record *memoryRevocationRecord) bump(now time.Time) {
	record.revocation.Version++
	record.revocation.UpdatedAt = now
}

func (record *memoryRevocationRecord) clearActiveClaim() {
	record.claimTokenSHA256 = ""
	record.revocation.ClaimedBy = ""
	record.revocation.ClaimedAt = time.Time{}
	record.revocation.ClaimExpiresAt = time.Time{}
	record.revocation.LastHeartbeatAt = time.Time{}
}

func (record *memoryRevocationRecord) clearProtectedReference() {
	clear(record.protected.Ciphertext)
	record.protected.Ciphertext = nil
	record.protected.KeyID = ""
	record.revocation.AccessorPresent = false
	record.revocation.EncryptionKeyID = ""
}

func publicMemoryRevocation(record *memoryRevocationRecord) Revocation {
	return redactedRevocation(record.revocation)
}

func referenceContext(revocation Revocation) ReferenceContext {
	return ReferenceContext{
		RevocationID: revocation.ID, ActionID: revocation.ActionID,
		ActionEpoch: revocation.ActionLeaseEpoch, Issuer: revocation.Issuer,
	}
}

func actionEpochKey(actionID string, epoch int64) string {
	return actionID + "\x00" + strconv.FormatInt(epoch, 10)
}

func confirmationResult(record *memoryRevocationRecord) ConfirmationResult {
	confirmations := make([]ExternalConfirmation, 0, len(record.confirmations))
	for _, confirmation := range record.confirmations {
		confirmations = append(confirmations, confirmation)
	}
	sort.Slice(confirmations, func(i, j int) bool {
		if !confirmations[i].CreatedAt.Equal(confirmations[j].CreatedAt) {
			return confirmations[i].CreatedAt.Before(confirmations[j].CreatedAt)
		}
		return confirmations[i].Subject < confirmations[j].Subject
	})
	return ConfirmationResult{Revocation: publicMemoryRevocation(record), Confirmations: confirmations}
}

func hasPlatformAdmin(confirmations map[string]ExternalConfirmation) bool {
	for _, confirmation := range confirmations {
		if confirmation.PlatformAdmin {
			return true
		}
	}
	return false
}

func destroyPreparedClaims(claims []memoryPreparedClaim) {
	for _, claim := range claims {
		claim.accessor.Destroy()
	}
}

func randomRevocationToken() (string, error) {
	value := make([]byte, 32)
	defer clear(value)
	if _, err := cryptorand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func (repository *MemoryRepository) now() time.Time { return repository.clock().UTC() }

func contextError(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalidRevocationRequest
	}
	return ctx.Err()
}
