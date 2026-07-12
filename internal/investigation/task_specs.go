package investigation

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/seaworld008/aiops-system/internal/domain"
)

const taskSpecsSemanticsV1 = "investigation.task-specs.v1"

// TaskSpecScope is the trusted Incident identity used to authorize a read
// task. It is derived from repository state; API callers never supply it.
type TaskSpecScope struct {
	TenantID      string
	WorkspaceID   string
	EnvironmentID string
	ServiceID     string
	MappingStatus domain.MappingStatus
}

// Validate requires an exact, fully resolved Incident mapping before a read
// task can be admitted. Ambiguous or unresolved mappings fail closed.
func (scope TaskSpecScope) Validate() error {
	if !domain.ValidResourceID(scope.TenantID) || !domain.ValidResourceID(scope.WorkspaceID) ||
		!domain.ValidResourceID(scope.EnvironmentID) || !domain.ValidResourceID(scope.ServiceID) ||
		scope.MappingStatus != domain.MappingExact {
		return fmt.Errorf("%w: trusted task specification scope must be an exact incident mapping", ErrInvalidRequest)
	}
	return nil
}

// TaskSpecAuthorizer is a trusted server-side registry/schema boundary. It
// authorizes an exact connector/operation pair and validates its typed input.
type TaskSpecAuthorizer func(context.Context, TaskSpecScope, TaskSpec) error

// AuthorizeTaskSpecs applies the trusted server-side registry/schema to
// detached canonical task specifications. Authorizer diagnostics are folded
// into a low-sensitivity repository error.
func AuthorizeTaskSpecs(ctx context.Context, authorizer TaskSpecAuthorizer, scope TaskSpecScope, specs []TaskSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if authorizer == nil {
		return fmt.Errorf("%w: trusted task specification authorizer is required", ErrInvalidRequest)
	}
	if err := scope.Validate(); err != nil {
		return err
	}
	for _, spec := range specs {
		detached := spec
		detached.Input = bytes.Clone(spec.Input)
		if err := authorizer(ctx, scope, detached); err != nil {
			if contextErr := ctx.Err(); contextErr != nil {
				return contextErr
			}
			return fmt.Errorf("%w: task specification is not authorized", ErrInvalidRequest)
		}
		if err := ctx.Err(); err != nil {
			return err
		}
	}
	return nil
}

var taskKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]{0,63}$`)

var (
	targetURISchemePattern        = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://`)
	targetSchemeRelativePattern   = regexp.MustCompile(`(?i)(?:^|[\s"\x27(=])//(?:[a-z0-9._~%!$&()*+,;=:-]+@)?(?:[a-z0-9.-]+|\[[0-9a-f:]+\])(?::[0-9]{1,5})?(?:[/#?]|$)`)
	targetHostPortPattern         = regexp.MustCompile(`(?i)^(?:[a-z0-9.-]+|\[[0-9a-f:]+\]):[0-9]{1,5}(?:[/#?][^\s]*)?$`)
	targetAssignmentPattern       = regexp.MustCompile(`(?i)(^|[^a-z0-9])(host(?:[\s_.-]*name)?|port|dsn|endpoint|url|uri|address|server|target|cluster)[\s_.-]*[:=][\s]*`)
	targetMetricIdentifierPattern = regexp.MustCompile(`^[A-Za-z_:][A-Za-z0-9_:]*$`)
)

func CanonicalTaskSpecs(specs []TaskSpec) ([]TaskSpec, string, error) {
	if len(specs) == 0 || len(specs) > 12 {
		return nil, "", fmt.Errorf("%w: task count must be between 1 and 12", ErrInvalidRequest)
	}
	canonical := make([]TaskSpec, len(specs))
	seen := make(map[string]struct{}, len(specs))
	for index, spec := range specs {
		if !taskKeyPattern.MatchString(spec.Key) || !domain.ValidConnectorID(spec.ConnectorID) ||
			!domain.ValidOperation(spec.Operation) {
			return nil, "", fmt.Errorf("%w: task key, connector and operation must be canonical", ErrInvalidRequest)
		}
		if _, duplicate := seen[spec.Key]; duplicate {
			return nil, "", fmt.Errorf("%w: duplicate task key", ErrInvalidRequest)
		}
		seen[spec.Key] = struct{}{}
		if err := domain.ValidateSafeJSONObject(spec.Input); err != nil {
			return nil, "", fmt.Errorf("%w: unsafe task input: %v", ErrInvalidRequest, err)
		}
		var object map[string]any
		if err := json.Unmarshal(spec.Input, &object); err != nil {
			return nil, "", fmt.Errorf("%w: invalid task input", ErrInvalidRequest)
		}
		if containsTaskTargetMaterial(object) {
			return nil, "", fmt.Errorf("%w: task input contains connection or credential material", ErrInvalidRequest)
		}
		encoded, err := jsoncanonicalizer.Transform(spec.Input)
		if err != nil {
			return nil, "", fmt.Errorf("%w: task input cannot be canonicalized", ErrInvalidRequest)
		}
		canonical[index] = TaskSpec{
			Key: spec.Key, ConnectorID: spec.ConnectorID, Operation: spec.Operation,
			Input: bytes.Clone(encoded),
		}
	}
	sort.Slice(canonical, func(left, right int) bool {
		if canonical[left].Key != canonical[right].Key {
			return canonical[left].Key < canonical[right].Key
		}
		if canonical[left].ConnectorID != canonical[right].ConnectorID {
			return canonical[left].ConnectorID < canonical[right].ConnectorID
		}
		if canonical[left].Operation != canonical[right].Operation {
			return canonical[left].Operation < canonical[right].Operation
		}
		return bytes.Compare(canonical[left].Input, canonical[right].Input) < 0
	})
	hash, err := semanticRequestHash(taskSpecsSemanticsV1, canonical)
	if err != nil {
		return nil, "", err
	}
	return canonical, hash, nil
}

func containsTaskTargetMaterial(value any) bool {
	return containsTaskTargetMaterialAt(value, "")
}

func containsTaskTargetMaterialAt(value any, parentKey string) bool {
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			if normalized := normalizeTaskFieldName(key); normalized == "name" || normalized == "key" {
				if name, ok := child.(string); ok && forbiddenTaskFieldName(name) {
					return true
				}
			}
		}
		for key, child := range item {
			if forbiddenTaskFieldName(key) {
				return true
			}
			if containsTaskTargetMaterialAt(child, key) {
				return true
			}
		}
	case []any:
		for _, child := range item {
			if containsTaskTargetMaterialAt(child, parentKey) {
				return true
			}
		}
	case string:
		if unsafeTaskTargetValue(item) {
			return true
		}
	}
	return false
}

func normalizeTaskFieldName(value string) string {
	var normalized strings.Builder
	for _, character := range value {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			normalized.WriteRune(unicode.ToLower(character))
		}
	}
	return normalized.String()
}

func forbiddenTaskFieldName(value string) bool {
	normalized := normalizeTaskFieldName(value)
	for _, carrier := range []string{
		"args", "arguments", "argv", "env", "environment", "environmentvariables",
		"command", "cmd", "options", "flags",
	} {
		if normalized == carrier {
			return true
		}
	}
	for _, forbidden := range []string{
		"url", "endpoint", "header", "auth", "secret", "token", "password", "credential",
		"host", "hostname", "port", "dsn", "uri", "address", "socket", "proxy", "server", "target", "cluster", "destination",
	} {
		if strings.Contains(normalized, forbidden) {
			return true
		}
	}
	return false
}

func unsafeTaskTargetValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	return containsTaskTargetCLIOption(trimmed) || targetURISchemePattern.MatchString(trimmed) || targetSchemeRelativePattern.MatchString(trimmed) ||
		targetHostPortPattern.MatchString(trimmed) || containsTaskTargetAssignment(trimmed)
}

func containsTaskTargetCLIOption(value string) bool {
	for _, field := range strings.Fields(value) {
		if !strings.HasPrefix(field, "--") {
			continue
		}
		option := strings.TrimPrefix(field, "--")
		if separator := strings.IndexByte(option, '='); separator >= 0 {
			option = option[:separator]
		}
		if forbiddenTaskFieldName(option) {
			return true
		}
	}
	return false
}

func containsTaskTargetAssignment(value string) bool {
	for _, match := range targetAssignmentPattern.FindAllStringSubmatchIndex(value, -1) {
		valueStart := match[1]
		if valueStart >= len(value) {
			continue
		}
		remaining := value[valueStart:]
		if insideAllowedTaskSelector(value, match[4]) &&
			(strings.HasPrefix(remaining, `"`) || strings.HasPrefix(remaining, `~"`)) {
			continue
		}
		return true
	}
	return false
}

func insideAllowedTaskSelector(value string, position int) bool {
	selectorStarts := make([]int, 0, 1)
	quoted := false
	escaped := false
	for index := 0; index < position; index++ {
		switch current := value[index]; {
		case escaped:
			escaped = false
		case quoted && current == '\\':
			escaped = true
		case current == '"':
			quoted = !quoted
		case !quoted && current == '{':
			selectorStarts = append(selectorStarts, index)
		case !quoted && current == '}' && len(selectorStarts) > 0:
			selectorStarts = selectorStarts[:len(selectorStarts)-1]
		}
	}
	if len(selectorStarts) == 0 {
		return false
	}
	selectorStart := selectorStarts[len(selectorStarts)-1]
	if selectorStart == 0 {
		return true
	}
	previous := selectorStart - 1
	for previous >= 0 && strings.ContainsRune(" \t\r\n", rune(value[previous])) {
		previous--
	}
	identifierEnd := previous + 1
	for previous >= 0 && isTaskMetricIdentifierByte(value[previous]) {
		previous--
	}
	return targetMetricIdentifierPattern.MatchString(value[previous+1 : identifierEnd])
}

func isTaskMetricIdentifierByte(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' ||
		value >= '0' && value <= '9' || value == '_' || value == ':'
}
