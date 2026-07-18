package proxmox

import (
	"context"
	"errors"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

func (value *provider) Discover(
	ctx context.Context,
	runtime discoverysource.BoundRuntime,
	request discoverysource.DiscoverRequest,
) (discoverysource.DiscoverOutcome, error) {
	if value == nil || ctx == nil {
		return nil, providerError("DISCOVER_REQUEST_REJECTED")
	}
	if err := request.Validate(); err != nil {
		return nil, err
	}
	if request.Checkpoint.ProfileCode() != profileCode ||
		!discoverRequestMatchesBinding(request, value.factory.binding) {
		return nil, providerError("DISCOVER_BINDING_REJECTED")
	}
	previous, previousPresent, err := decodeProviderCheckpoint(request.Checkpoint)
	if err != nil {
		return nil, providerError("CHECKPOINT_REJECTED")
	}

	callContext, cancel := context.WithTimeout(ctx, providerCallTimeout)
	defer cancel()
	if err := callContext.Err(); err != nil {
		return nil, err
	}
	session, err := value.factory.open(callContext, runtime)
	if err != nil {
		return discoverFailureOrDelay(ctx, request, err, "RUNTIME_OPEN_REJECTED")
	}
	defer session.Close()
	if session.acceptedCheckpointSequence <= 0 {
		return nil, providerError("CHECKPOINT_SEQUENCE_REJECTED")
	}

	version, err := session.client.Version(callContext)
	if err != nil {
		return discoverFailureOrDelay(ctx, request, err, "VERSION_FAILED")
	}
	if !validVersionInfo(version) {
		return nil, providerError("VERSION_REJECTED")
	}
	cluster, err := session.client.ClusterStatus(callContext)
	if err != nil {
		return discoverFailureOrDelay(ctx, request, err, "CLUSTER_STATUS_FAILED")
	}
	if !validClusterStatus(cluster, session.authority) {
		return nil, providerError("CLUSTER_IDENTITY_REJECTED")
	}
	clusterDigest := clusterIdentityDigest(cluster)
	if previousPresent &&
		(previous.ClusterIdentityDigest != clusterDigest ||
			cluster.Generation < previous.ClusterGeneration) {
		return nil, providerError("CHECKPOINT_AUTHORITY_REJECTED")
	}
	nodes, err := session.client.ListNodes(callContext)
	if err != nil {
		return discoverFailureOrDelay(ctx, request, err, "NODE_LIST_FAILED")
	}
	resources, resourceErr := session.client.ListClusterResources(callContext)
	if resourceErr != nil {
		if delay, retryable := providerRetryAfter(resourceErr); retryable {
			return validatedDelay(request, delay)
		}
		if contextErr := callerContextError(ctx, callContext); contextErr != nil {
			return nil, contextErr
		}
		stage := clientErrorStage(resourceErr)
		if stage != clientFailureNetwork && stage != clientFailureIncomplete {
			return nil, providerError("RESOURCE_LIST_REJECTED")
		}
		if err := validateInventory(cluster, nodes, nil); err != nil {
			return nil, providerError("PARTIAL_CLUSTER_REJECTED")
		}
		return value.partialPage(request, session, clusterDigest, cluster.Generation, nodes)
	}
	if err := validateInventory(cluster, nodes, resources); err != nil {
		return nil, providerError("INVENTORY_REJECTED")
	}
	if !lowercaseDigest.MatchString(session.TLSPeerDigest()) {
		return nil, providerError("TLS_EVIDENCE_REJECTED")
	}

	completedAt := value.factory.now().UTC().Truncate(time.Microsecond)
	normalized, nextValue, err := normalizeInventory(
		session.authority.environmentID,
		inventorySnapshot{
			clusterIdentityDigest: clusterDigest,
			clusterGeneration:     cluster.Generation,
			orderSequence:         session.acceptedCheckpointSequence,
			completedAt:           completedAt,
			nodes:                 nodes,
			resources:             resources,
		},
		request.Limits,
	)
	if err != nil {
		return nil, providerError("NORMALIZATION_REJECTED")
	}
	canonical, err := encodeProviderCheckpoint(nextValue)
	if err != nil {
		return nil, providerError("CHECKPOINT_ENCODE_REJECTED")
	}
	nextCheckpoint, err := discoverysource.NewCheckpoint(profileCode, canonical)
	clear(canonical)
	if err != nil {
		return nil, err
	}
	page := discoverysource.Page{
		Items:            normalized.Items,
		Relations:        normalized.Relations,
		NextCheckpoint:   nextCheckpoint,
		FinalPage:        true,
		CompleteSnapshot: true,
	}
	return validatePageOutcome(request, session.authority.environmentID, page)
}

func (value *provider) partialPage(
	request discoverysource.DiscoverRequest,
	session clientSession,
	clusterDigest string,
	clusterGeneration int64,
	nodes []Node,
) (discoverysource.DiscoverOutcome, error) {
	completedAt := value.factory.now().UTC().Truncate(time.Microsecond)
	normalized, _, err := normalizeInventory(
		session.authority.environmentID,
		inventorySnapshot{
			clusterIdentityDigest: clusterDigest,
			clusterGeneration:     clusterGeneration,
			orderSequence:         session.acceptedCheckpointSequence,
			completedAt:           completedAt,
			nodes:                 nodes,
		},
		request.Limits,
	)
	if err != nil {
		return nil, providerError("PARTIAL_NORMALIZATION_REJECTED")
	}
	page := discoverysource.Page{
		Items:          normalized.Items,
		NextCheckpoint: request.Checkpoint.Clone(),
		FinalPage:      true,
	}
	return validatePageOutcome(request, session.authority.environmentID, page)
}

func discoverRequestMatchesBinding(
	request discoverysource.DiscoverRequest,
	binding discoverysource.RuntimeBinding,
) bool {
	return binding.RevisionStatus == assetcatalog.SourceRevisionPublished &&
		request.Locator == binding.Locator &&
		request.SourceRevision == binding.SourceRevision &&
		request.SourceRevisionDigest == binding.SourceRevisionDigest &&
		binding.ProviderKind == providerKind &&
		binding.ProfileCode == profileCode
}

func discoverFailureOrDelay(
	caller context.Context,
	request discoverysource.DiscoverRequest,
	err error,
	code string,
) (discoverysource.DiscoverOutcome, error) {
	if contextErr := callerContextError(caller, nil); contextErr != nil {
		return nil, contextErr
	}
	if delay, retryable := providerRetryAfter(err); retryable {
		return validatedDelay(request, delay)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}
	return nil, providerError(code)
}

func validatedDelay(
	request discoverysource.DiscoverRequest,
	duration time.Duration,
) (discoverysource.DiscoverOutcome, error) {
	delay := discoverysource.Delay{
		Reason:     discoverysource.DelayReasonProviderRetryAfter,
		RetryAfter: duration,
	}
	if err := discoverysource.ValidateDiscoverResult(
		request,
		assetdiscovery.FactPolicy{},
		delay,
		nil,
	); err != nil {
		return nil, err
	}
	return delay, nil
}

func validatePageOutcome(
	request discoverysource.DiscoverRequest,
	environmentID string,
	page discoverysource.Page,
) (discoverysource.DiscoverOutcome, error) {
	if err := discoverysource.ValidateDiscoverResult(
		request,
		normalizedFactPolicy(environmentID),
		page,
		nil,
	); err != nil {
		page.NextCheckpoint.Clear()
		return nil, err
	}
	return page, nil
}

func callerContextError(caller context.Context, child context.Context) error {
	if caller != nil && caller.Err() != nil {
		return caller.Err()
	}
	if child != nil && child.Err() != nil {
		return child.Err()
	}
	return nil
}
