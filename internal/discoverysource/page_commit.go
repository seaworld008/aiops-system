package discoverysource

import (
	"context"
	"errors"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
)

var (
	ErrPageCommitInvalid     = errors.New("source page commit invalid")
	ErrPageCommitConflict    = errors.New("source page commit conflict")
	ErrPageCommitUnavailable = errors.New("source page commit unavailable")
)

type PageCommitCoordinates struct {
	Locator      assetcatalog.SourceLocator
	RunID        string
	PageSequence int64
}

type PageCommitResult struct {
	RunID                       string
	PageSequence                int64
	CheckpointVersion           int64
	CheckpointSHA256            string
	PageDigestSHA256            string
	RelationPageDigestSHA256    string
	FinalPage, CompleteSnapshot bool
	Replayed                    bool
}

type CrossEnvironmentRelationPolicyCoordinates struct {
	SourceEnvironmentID string
	TargetEnvironmentID string
	RelationshipType    assetcatalog.RelationshipType
	ProviderPathCode    string
}

type PageFactPolicyResolver interface {
	ResolvePageFactPolicy(context.Context, assetcatalog.SourceRevision) (assetdiscovery.FactPolicy, error)
	ResolveCrossEnvironmentRelationPolicy(context.Context, assetcatalog.SourceRevision, CrossEnvironmentRelationPolicyCoordinates) (assetcatalog.PolicyReferenceID, error)
}

type PageCommitter interface {
	ApplyPage(context.Context, assetcatalog.LeaseFence, PageCommitCoordinates, Page) (PageCommitResult, error)
}
