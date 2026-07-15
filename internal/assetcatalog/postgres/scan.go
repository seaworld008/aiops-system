package postgres

import (
	"encoding/json"
	"time"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
)

type rowScanner interface {
	Scan(...any) error
}

type assetScanTarget struct {
	asset      assetcatalog.Asset
	labelsJSON []byte
}

func (target *assetScanTarget) destinations() []any {
	return []any{
		&target.asset.ID,
		&target.asset.Scope.TenantID,
		&target.asset.Scope.WorkspaceID,
		&target.asset.Scope.EnvironmentID,
		&target.asset.SourceID,
		&target.asset.Kind,
		&target.asset.ProviderKind,
		&target.asset.ExternalID,
		&target.asset.DisplayName,
		&target.asset.Lifecycle,
		&target.asset.MappingStatus,
		&target.asset.OwnerGroup,
		&target.asset.Criticality,
		&target.asset.DataClassification,
		&target.labelsJSON,
		&target.asset.LastObservationID,
		&target.asset.LastObservationChainSHA256,
		&target.asset.LastObservedAt,
		&target.asset.LastSourceRevision,
		&target.asset.Version,
		&target.asset.CreatedAt,
		&target.asset.UpdatedAt,
	}
}

func (target *assetScanTarget) finish() (assetcatalog.Asset, error) {
	asset := target.asset
	labelsJSON := target.labelsJSON
	if len(labelsJSON) == 0 || json.Unmarshal(labelsJSON, &asset.Labels) != nil {
		return assetcatalog.Asset{}, assetcatalog.ErrStateConflict
	}
	asset.LastObservedAt = canonicalDatabaseTime(asset.LastObservedAt)
	asset.CreatedAt = canonicalDatabaseTime(asset.CreatedAt)
	asset.UpdatedAt = canonicalDatabaseTime(asset.UpdatedAt)
	if err := asset.Validate(); err != nil {
		return assetcatalog.Asset{}, assetcatalog.ErrStateConflict
	}
	return asset.Clone(), nil
}

func scanAsset(row rowScanner) (assetcatalog.Asset, error) {
	var target assetScanTarget
	if err := row.Scan(target.destinations()...); err != nil {
		return assetcatalog.Asset{}, err
	}
	return target.finish()
}

func canonicalDatabaseTime(value time.Time) time.Time {
	return value.UTC().Truncate(time.Microsecond)
}
