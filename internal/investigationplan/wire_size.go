package investigationplan

import (
	"encoding/json"
	"errors"
	"unicode/utf8"

	"github.com/seaworld008/aiops-system/internal/domain"
)

var errInvalidManifestWire = errors.New("invalid investigation plan manifest wire")

const definitionMaterialOverheadBytes = 64

type manifestWireCounter struct {
	total    int
	limit    int
	overflow bool
}

func definitionWithinBudget(definition Definition) (bool, error) {
	if !rawDefinitionMaterialWithinBudget(definition) {
		return false, nil
	}
	_, overflow, err := countManifestWire(definition, MaximumDefinitionBytes)
	return !overflow, err
}

// rawDefinitionMaterialWithinBudget prevents whitespace-heavy RawMessages and
// aggregate raw fields from being hidden by JSON compaction. It is an
// O(1)-per-field gate and runs before escape scanning.
func rawDefinitionMaterialWithinBudget(definition Definition) bool {
	remaining := MaximumDefinitionBytes
	add := func(size int) bool {
		if size < 0 || size > remaining {
			return false
		}
		remaining -= size
		return true
	}
	if !add(definitionMaterialOverheadBytes) || !add(len(definition.RegistryDigest)) {
		return false
	}
	for _, profile := range definition.Profiles {
		if !add(definitionMaterialOverheadBytes) || !add(len(profile.Scope.TenantID)) ||
			!add(len(profile.Scope.WorkspaceID)) || !add(len(profile.Scope.EnvironmentID)) ||
			!add(len(profile.Scope.ServiceID)) || !add(len(profile.Match.IntegrationID)) ||
			!add(len(profile.Match.Provider)) {
			return false
		}
		for _, label := range profile.Match.Labels {
			if !add(definitionMaterialOverheadBytes) || !add(len(label.Key)) || !add(len(label.Value)) {
				return false
			}
		}
		for _, task := range profile.Tasks {
			if !add(definitionMaterialOverheadBytes) || !add(len(task.Key)) || !add(len(task.ConnectorID)) ||
				!add(len(task.Operation)) || !add(len(task.Input)) {
				return false
			}
		}
	}
	return true
}

// countManifestWire counts the exact compact JSON emitted for manifestDocument
// without materializing the aggregate document. String escaping is counted in
// place; each RawMessage allocation is independently capped at 64 KiB.
func countManifestWire(definition Definition, limit int) (int, bool, error) {
	if limit < 0 {
		return 0, false, errInvalidManifestWire
	}
	counter := manifestWireCounter{limit: limit}
	counter.addLiteral(`{"schema_version":`)
	if err := counter.addString(ManifestSchemaVersion); err != nil {
		return 0, false, err
	}
	counter.addLiteral(`,"registry_digest":`)
	if err := counter.addString(definition.RegistryDigest); err != nil {
		return 0, false, err
	}
	counter.addLiteral(`,"profiles":[`)
	for profileIndex, profile := range definition.Profiles {
		if profileIndex > 0 {
			counter.addLiteral(`,`)
		}
		counter.addLiteral(`{"scope":{"tenant_id":`)
		if err := counter.addString(profile.Scope.TenantID); err != nil {
			return 0, false, err
		}
		counter.addLiteral(`,"workspace_id":`)
		if err := counter.addString(profile.Scope.WorkspaceID); err != nil {
			return 0, false, err
		}
		counter.addLiteral(`,"environment_id":`)
		if err := counter.addString(profile.Scope.EnvironmentID); err != nil {
			return 0, false, err
		}
		counter.addLiteral(`,"service_id":`)
		if err := counter.addString(profile.Scope.ServiceID); err != nil {
			return 0, false, err
		}
		counter.addLiteral(`},"match":{"integration_id":`)
		if err := counter.addString(profile.Match.IntegrationID); err != nil {
			return 0, false, err
		}
		counter.addLiteral(`,"provider":`)
		if err := counter.addString(profile.Match.Provider); err != nil {
			return 0, false, err
		}
		counter.addLiteral(`,"labels":[`)
		for labelIndex, label := range profile.Match.Labels {
			if labelIndex > 0 {
				counter.addLiteral(`,`)
			}
			counter.addLiteral(`{"key":`)
			if err := counter.addString(label.Key); err != nil {
				return 0, false, err
			}
			counter.addLiteral(`,"value":`)
			if err := counter.addString(label.Value); err != nil {
				return 0, false, err
			}
			counter.addLiteral(`}`)
		}
		counter.addLiteral(`]},"tasks":[`)
		for taskIndex, task := range profile.Tasks {
			if taskIndex > 0 {
				counter.addLiteral(`,`)
			}
			counter.addLiteral(`{"key":`)
			if err := counter.addString(task.Key); err != nil {
				return 0, false, err
			}
			counter.addLiteral(`,"connector_id":`)
			if err := counter.addString(task.ConnectorID); err != nil {
				return 0, false, err
			}
			counter.addLiteral(`,"operation":`)
			if err := counter.addString(task.Operation); err != nil {
				return 0, false, err
			}
			counter.addLiteral(`,"input":`)
			if err := counter.addRawMessage(task.Input); err != nil {
				return 0, false, err
			}
			counter.addLiteral(`}`)
		}
		counter.addLiteral(`]}`)
	}
	counter.addLiteral(`]}`)
	return counter.total, counter.overflow, nil
}

func (counter *manifestWireCounter) addLiteral(value string) {
	counter.addSize(len(value))
}

func (counter *manifestWireCounter) addString(value string) error {
	if counter.overflow {
		return nil
	}
	counter.addSize(2)
	if counter.overflow {
		return nil
	}
	// A valid JSON string needs at least one encoded byte per input byte.
	// Reject by this lower bound before UTF-8 validation or escape scanning.
	if len(value) > counter.limit-counter.total {
		counter.overflow = true
		return nil
	}
	if !utf8.ValidString(value) {
		return errInvalidManifestWire
	}
	for offset := 0; offset < len(value); {
		character := value[offset]
		if character < utf8.RuneSelf {
			switch character {
			case '\\', '"', '\b', '\f', '\n', '\r', '\t':
				counter.addSize(2)
			case '<', '>', '&':
				counter.addSize(6)
			default:
				if character < 0x20 {
					counter.addSize(6)
				} else {
					counter.addSize(1)
				}
			}
			offset++
			continue
		}
		runeValue, width := utf8.DecodeRuneInString(value[offset:])
		if runeValue == '\u2028' || runeValue == '\u2029' {
			counter.addSize(6)
		} else {
			counter.addSize(width)
		}
		offset += width
	}
	return nil
}

func (counter *manifestWireCounter) addRawMessage(value json.RawMessage) error {
	if counter.overflow {
		return nil
	}
	if len(value) > domain.MaxInvestigationJSONBytes {
		return errInvalidManifestWire
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return errInvalidManifestWire
	}
	counter.addSize(len(encoded))
	clear(encoded)
	return nil
}

func (counter *manifestWireCounter) addSize(size int) {
	if counter.overflow || size < 0 || size > counter.limit || counter.total > counter.limit-size {
		counter.overflow = true
		return
	}
	counter.total += size
}
