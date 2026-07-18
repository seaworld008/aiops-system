package proxmox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

var (
	versionPattern      = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){1,2}$`)
	nodeNamePattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$`)
	resourceIDPattern   = regexp.MustCompile(`^(?:qemu|lxc)/[1-9][0-9]{0,9}$`)
	repositoryIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
)

type provider struct {
	factory ClientFactory
}

func New(factory ClientFactory) (discoverysource.Provider, error) {
	if factory.binding.ProviderKind != providerKind ||
		factory.binding.ProfileCode != profileCode ||
		factory.binding.RevisionStatus != assetcatalog.SourceRevisionValidating &&
			factory.binding.RevisionStatus != assetcatalog.SourceRevisionPublished ||
		factory.now == nil {
		return nil, providerError("FACTORY_REJECTED")
	}
	return &provider{factory: factory}, nil
}

func (*provider) Kind() assetcatalog.SourceKind {
	return assetcatalog.SourceKindProxmox
}

func (*provider) ProviderKind() string {
	return providerKind
}

func (value *provider) Validate(
	ctx context.Context,
	runtime discoverysource.BoundRuntime,
	request discoverysource.ValidationRequest,
) (discoverysource.ValidationProof, error) {
	if value == nil || ctx == nil {
		return discoverysource.ValidationProof{}, providerError("VALIDATION_REQUEST_REJECTED")
	}
	if err := request.Validate(); err != nil {
		return discoverysource.ValidationProof{}, err
	}
	if !validationRequestMatchesBinding(request, value.factory.binding) {
		return discoverysource.ValidationProof{}, providerError("VALIDATION_BINDING_REJECTED")
	}
	callContext, cancel := context.WithTimeout(ctx, providerCallTimeout)
	defer cancel()
	if err := callContext.Err(); err != nil {
		return discoverysource.ValidationProof{}, err
	}
	session, err := value.factory.open(callContext, runtime)
	if err != nil {
		return validationResultForError(ctx, request, err)
	}
	defer session.Close()

	version, err := session.client.Version(callContext)
	if err != nil {
		return validationResultForError(ctx, request, err)
	}
	if !validVersionInfo(version) {
		return checkedValidationFailure(
			request,
			discoverysource.ValidationCheckSchema,
			"SCHEMA_REJECTED",
			"VALIDATION_REJECTED",
		)
	}
	cluster, err := session.client.ClusterStatus(callContext)
	if err != nil {
		return validationResultForError(ctx, request, err)
	}
	if !validClusterStatus(cluster, session.authority) {
		return checkedValidationFailure(
			request,
			discoverysource.ValidationCheckIdentity,
			"IDENTITY_REJECTED",
			"AUTHORITY_REJECTED",
		)
	}
	nodes, err := session.client.ListNodes(callContext)
	if err != nil {
		return validationResultForError(ctx, request, err)
	}
	resources, err := session.client.ListClusterResources(callContext)
	if err != nil {
		return validationResultForError(ctx, request, err)
	}
	if err := validateInventory(cluster, nodes, resources); err != nil {
		return validationResultForError(ctx, request, err)
	}
	peerDigest := session.TLSPeerDigest()
	if !lowercaseDigest.MatchString(peerDigest) {
		return checkedValidationFailure(
			request,
			discoverysource.ValidationCheckTrustOrSignature,
			"TRUST_OR_SIGNATURE_REJECTED",
			"VALIDATION_REJECTED",
		)
	}
	if !lowercaseDigest.MatchString(session.roleDigest) {
		return checkedValidationFailure(
			request,
			discoverysource.ValidationCheckCredentialOpen,
			"CREDENTIAL_OPEN_REJECTED",
			"VALIDATION_REJECTED",
		)
	}

	clusterDigest := clusterIdentityDigest(cluster)
	probeDigest := inventoryProbeDigest(nodes, resources)
	schemaDigest := digestStringTuple(
		"proxmox-validation-schema.v1",
		version.Version,
		version.Release,
		version.RepoID,
		strconv.Itoa(len(nodes)),
		strconv.Itoa(len(resources)),
	)
	proof := discoverysource.ValidationProof{
		Outcome: assetcatalog.ValidationOutcomeSucceeded,
		Code:    "VALIDATION_SUCCEEDED",
		Checks: []discoverysource.ValidationCheck{
			{
				Kind:         discoverysource.ValidationCheckIdentity,
				Code:         "IDENTITY_VERIFIED",
				Passed:       true,
				Count:        int64(len(cluster.Members)),
				DigestSHA256: clusterDigest,
			},
			{
				Kind:         discoverysource.ValidationCheckTrustOrSignature,
				Code:         "TRUST_OR_SIGNATURE_VERIFIED",
				Passed:       true,
				Count:        1,
				DigestSHA256: peerDigest,
			},
			{
				Kind:         discoverysource.ValidationCheckNetwork,
				Code:         "NETWORK_PASSED",
				Passed:       true,
				Count:        4,
				DigestSHA256: digestStringTuple("proxmox-network-probe.v1", version.Version),
			},
			{
				Kind:         discoverysource.ValidationCheckCredentialOpen,
				Code:         "CREDENTIAL_OPEN_PASSED",
				Passed:       true,
				Count:        1,
				DigestSHA256: session.roleDigest,
			},
			{
				Kind:         discoverysource.ValidationCheckFixedProbe,
				Code:         "FIXED_PROBE_PASSED",
				Passed:       true,
				Count:        int64(len(nodes) + min(len(resources), 1)),
				DigestSHA256: probeDigest,
			},
			{
				Kind:         discoverysource.ValidationCheckSchema,
				Code:         "SCHEMA_PASSED",
				Passed:       true,
				Count:        int64(len(nodes) + len(resources)),
				DigestSHA256: schemaDigest,
			},
			{
				Kind:         discoverysource.ValidationCheckDLP,
				Code:         "DLP_PASSED",
				Passed:       true,
				Count:        int64(len(nodes) + len(resources)),
				DigestSHA256: digestStringTuple("proxmox-dlp-surface.v1", providerKind),
			},
			{
				Kind:         discoverysource.ValidationCheckBudget,
				Code:         "BUDGET_PASSED",
				Passed:       true,
				Count:        int64(len(nodes) + len(resources)),
				DigestSHA256: digestStringTuple("proxmox-budget.v1", strconv.Itoa(maxInventoryResources)),
			},
		},
	}
	if err := discoverysource.ValidateValidationResult(request, proof, nil); err != nil {
		return discoverysource.ValidationProof{}, err
	}
	return proof, nil
}

func validationRequestMatchesBinding(
	request discoverysource.ValidationRequest,
	binding discoverysource.RuntimeBinding,
) bool {
	return binding.RevisionStatus == assetcatalog.SourceRevisionValidating &&
		request.Locator == binding.Locator &&
		request.SourceRevision == binding.SourceRevision &&
		request.SourceRevisionDigest == binding.SourceRevisionDigest &&
		binding.ProviderKind == providerKind &&
		binding.ProfileCode == profileCode
}

func validationResultForError(
	caller context.Context,
	request discoverysource.ValidationRequest,
	err error,
) (discoverysource.ValidationProof, error) {
	if caller != nil && caller.Err() != nil {
		return discoverysource.ValidationProof{}, caller.Err()
	}
	if _, retryable := providerRetryAfter(err); retryable {
		return discoverysource.ValidationProof{}, providerError("VALIDATION_RETRY_AFTER_REJECTED")
	}
	switch clientErrorStage(err) {
	case clientFailureIdentity:
		return checkedValidationFailure(
			request,
			discoverysource.ValidationCheckIdentity,
			"IDENTITY_REJECTED",
			"AUTHORITY_REJECTED",
		)
	case clientFailureTrust:
		return checkedValidationFailure(
			request,
			discoverysource.ValidationCheckTrustOrSignature,
			"TRUST_OR_SIGNATURE_REJECTED",
			"VALIDATION_REJECTED",
		)
	case clientFailureNetwork:
		return checkedValidationFailure(
			request,
			discoverysource.ValidationCheckNetwork,
			"NETWORK_REJECTED",
			"VALIDATION_REJECTED",
		)
	case clientFailureIncomplete:
		return checkedValidationFailure(
			request,
			discoverysource.ValidationCheckNetwork,
			"NETWORK_REJECTED",
			"VALIDATION_REJECTED",
		)
	case clientFailureCredential:
		return checkedValidationFailure(
			request,
			discoverysource.ValidationCheckCredentialOpen,
			"CREDENTIAL_OPEN_REJECTED",
			"VALIDATION_REJECTED",
		)
	case clientFailureDLP:
		return checkedValidationFailure(
			request,
			discoverysource.ValidationCheckDLP,
			"DLP_REJECTED",
			"VALIDATION_REJECTED",
		)
	case clientFailureBudget:
		return checkedValidationFailure(
			request,
			discoverysource.ValidationCheckBudget,
			"BUDGET_REJECTED",
			"VALIDATION_REJECTED",
		)
	case clientFailureProtocol:
		return checkedValidationFailure(
			request,
			discoverysource.ValidationCheckSchema,
			"SCHEMA_REJECTED",
			"VALIDATION_REJECTED",
		)
	case 0:
		return discoverysource.ValidationProof{}, providerError("VALIDATION_FAILED")
	default:
		return discoverysource.ValidationProof{}, providerError("VALIDATION_FAILED")
	}
}

func checkedValidationFailure(
	request discoverysource.ValidationRequest,
	kind discoverysource.ValidationCheckKind,
	checkCode string,
	proofCode string,
) (discoverysource.ValidationProof, error) {
	proof := discoverysource.ValidationProof{
		Outcome: assetcatalog.ValidationOutcomeFailed,
		Code:    proofCode,
		Checks: []discoverysource.ValidationCheck{
			{
				Kind:   kind,
				Code:   checkCode,
				Passed: false,
			},
		},
	}
	if err := discoverysource.ValidateValidationResult(request, proof, nil); err != nil {
		return discoverysource.ValidationProof{}, err
	}
	return proof, nil
}

func validVersionInfo(value VersionInfo) bool {
	return versionPattern.MatchString(value.Version) &&
		safeNormalizedValue(value.Release, 1, 64) &&
		repositoryIDPattern.MatchString(value.RepoID) &&
		!unsafeNormalizedText(value.Version) &&
		!unsafeNormalizedText(value.Release) &&
		!unsafeNormalizedText(value.RepoID)
}

func validClusterStatus(value ClusterStatus, authority authoritySnapshot) bool {
	if !authority.valid() ||
		value.Identity != authority.clusterIdentity ||
		!clusterIdentityCode.MatchString(value.Identity) ||
		!safeNormalizedValue(value.Name, 1, 256) ||
		value.Generation <= 0 ||
		!value.Quorate ||
		len(value.Members) == 0 ||
		len(value.Members) > maxInventoryResources ||
		unsafeNormalizedText(value.Identity) ||
		unsafeNormalizedText(value.Name) {
		return false
	}
	names := make([]string, len(value.Members))
	for index, member := range value.Members {
		if !nodeNamePattern.MatchString(member.Name) ||
			unsafeNormalizedText(member.Name) ||
			index > 0 && slices.Contains(names[:index], member.Name) {
			return false
		}
		names[index] = member.Name
	}
	return true
}

func validateInventory(
	cluster ClusterStatus,
	nodes []Node,
	resources []ClusterResource,
) error {
	if len(nodes) == 0 ||
		len(nodes)+len(resources) > maxInventoryResources ||
		len(nodes) != len(cluster.Members) {
		return clientError(clientFailureBudget, "INVENTORY_LIMIT_REJECTED")
	}
	memberState := make(map[string]bool, len(cluster.Members))
	for _, member := range cluster.Members {
		if _, duplicate := memberState[member.Name]; duplicate {
			return clientError(clientFailureIdentity, "CLUSTER_MEMBER_DUPLICATE")
		}
		memberState[member.Name] = member.Online
	}
	nodeState := make(map[string]struct{}, len(nodes))
	for _, node := range nodes {
		if !validNode(node) {
			return clientError(clientFailureProtocol, "NODE_SCHEMA_REJECTED")
		}
		if _, duplicate := nodeState[node.Name]; duplicate {
			return clientError(clientFailureProtocol, "NODE_DUPLICATE_REJECTED")
		}
		online, found := memberState[node.Name]
		if !found || online != (node.Status == "online") {
			return clientError(clientFailureIdentity, "NODE_MEMBERSHIP_REJECTED")
		}
		nodeState[node.Name] = struct{}{}
	}
	resourceState := make(map[string]struct{}, len(resources))
	for _, resource := range resources {
		if !validResource(resource) {
			return clientError(clientFailureProtocol, "RESOURCE_SCHEMA_REJECTED")
		}
		if _, found := nodeState[resource.Node]; !found {
			return clientError(clientFailureIdentity, "RESOURCE_NODE_REJECTED")
		}
		if _, duplicate := resourceState[resource.ID]; duplicate {
			return clientError(clientFailureProtocol, "RESOURCE_DUPLICATE_REJECTED")
		}
		resourceState[resource.ID] = struct{}{}
	}
	return nil
}

func validNode(value Node) bool {
	return nodeNamePattern.MatchString(value.Name) &&
		slices.Contains([]string{"online", "offline"}, value.Status) &&
		value.CPUCount > 0 &&
		value.CPUCount <= 65_536 &&
		value.MemoryBytes > 0 &&
		value.MemoryBytes <= 1<<60 &&
		!unsafeNormalizedText(value.Name) &&
		!unsafeNormalizedText(value.Status)
}

func validResource(value ClusterResource) bool {
	if !resourceIDPattern.MatchString(value.ID) ||
		!slices.Contains([]string{"qemu", "lxc"}, value.Type) ||
		value.ID != value.Type+"/"+strconv.FormatUint(value.VMID, 10) ||
		!safeNormalizedValue(value.Name, 1, 256) ||
		!nodeNamePattern.MatchString(value.Node) ||
		!slices.Contains([]string{"running", "stopped", "paused"}, value.Status) ||
		value.CPUCount == 0 ||
		value.CPUCount > 65_536 ||
		value.MemoryBytes == 0 ||
		value.MemoryBytes > 1<<60 {
		return false
	}
	for _, text := range []string{value.ID, value.Type, value.Name, value.Node, value.Status} {
		if unsafeNormalizedText(text) {
			return false
		}
	}
	return true
}

func clusterIdentityDigest(value ClusterStatus) string {
	return digestStringTuple(
		"proxmox-cluster-identity.v1",
		value.Identity,
		value.Name,
	)
}

func inventoryProbeDigest(nodes []Node, resources []ClusterResource) string {
	fields := []string{"proxmox-inventory-probe.v1"}
	ownedNodes := slices.Clone(nodes)
	slices.SortFunc(ownedNodes, func(left, right Node) int {
		return strings.Compare(left.Name, right.Name)
	})
	for _, node := range ownedNodes {
		fields = append(fields, node.Name, node.Status)
	}
	if len(resources) > 0 {
		ownedResources := slices.Clone(resources)
		slices.SortFunc(ownedResources, func(left, right ClusterResource) int {
			return strings.Compare(left.ID, right.ID)
		})
		fields = append(fields, ownedResources[0].ID, ownedResources[0].Type)
	}
	return digestStringTuple(fields...)
}

func digestBytes(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
