package readconnector

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"math"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

const (
	maximumLookbackMinutes     = 24 * 60
	maximumDefinitionItems     = readtask.MaxEvidenceItems
	maximumDefinitionSamples   = 1_000_000
	maximumQueryBytes          = 4096
	maximumLabels              = 64
	maximumLabelValueBytes     = 1024
	maximumVictoriaFields      = 32
	maximumVictoriaStringBytes = 16 << 10
	evidenceClockTolerance     = 30 * time.Second
	prometheusStepTolerance    = time.Millisecond
)

var (
	fieldNamePattern        = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]{0,127}$`)
	prometheusLabelPattern  = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	prometheusNumberPattern = regexp.MustCompile(`^[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$`)
)

type lookbackInput struct {
	LookbackMinutes int `json:"lookback_minutes"`
}

func validatePrometheusDefinition(definition PrometheusRangeQueryV1) error {
	if !validFixedQuery(definition.Expression) || definition.StepSeconds <= 0 || definition.StepSeconds > 3600 ||
		definition.MaxLookbackMinutes <= 0 || definition.MaxLookbackMinutes > maximumLookbackMinutes ||
		definition.MaxItems <= 0 || definition.MaxItems > maximumDefinitionItems ||
		definition.MaxSamples <= 0 || definition.MaxSamples > maximumDefinitionSamples {
		return ErrInvalidDefinition
	}
	estimatedSamples := definition.MaxLookbackMinutes*60/definition.StepSeconds + 1
	if estimatedSamples > definition.MaxSamples {
		return ErrInvalidDefinition
	}
	return nil
}

func validateVictoriaDefinition(definition VictoriaLogsSearchV1) error {
	if !validFixedQuery(definition.Query) || definition.Limit <= 0 || definition.Limit > maximumDefinitionItems ||
		definition.MaxLookbackMinutes <= 0 || definition.MaxLookbackMinutes > maximumLookbackMinutes ||
		len(definition.Fields) == 0 || len(definition.Fields) > maximumVictoriaFields {
		return ErrInvalidDefinition
	}
	seen := make(map[string]struct{}, len(definition.Fields))
	hasRequiredTime := false
	for _, field := range definition.Fields {
		if !fieldNamePattern.MatchString(field.Name) || readtask.EvidenceFieldReserved(field.Name) ||
			!domain.ValidSafeMetadata(field.Name, "safe") {
			return ErrInvalidDefinition
		}
		if _, duplicate := seen[field.Name]; duplicate {
			return ErrInvalidDefinition
		}
		seen[field.Name] = struct{}{}
		switch field.Type {
		case FieldString:
			if field.MaxBytes <= 0 || field.MaxBytes > maximumVictoriaStringBytes {
				return ErrInvalidDefinition
			}
		case FieldNumber, FieldBoolean, FieldNull:
			if field.MaxBytes != 0 {
				return ErrInvalidDefinition
			}
		default:
			return ErrInvalidDefinition
		}
		if field.Name == "_time" {
			hasRequiredTime = field.Required && field.Type == FieldString && field.MaxBytes >= len(time.RFC3339)
		}
	}
	if !hasRequiredTime {
		return ErrInvalidDefinition
	}
	return nil
}

func validFixedQuery(value string) bool {
	return strings.TrimSpace(value) == value && value != "" && len(value) <= maximumQueryBytes &&
		!strings.ContainsAny(value, "\r\n\x00") && domain.ValidSafeText(value)
}

func validateInput(item entry, raw json.RawMessage) error {
	_, err := parseLookback(item, raw)
	return err
}

func parseLookback(item entry, raw json.RawMessage) (time.Duration, error) {
	if domain.ValidateSafeJSONObject(raw) != nil {
		return 0, ErrContractRejected
	}
	var input lookbackInput
	if strictDecodeObject(raw, &input) != nil {
		return 0, ErrContractRejected
	}
	maximum := 0
	switch {
	case item.prometheus != nil && item.victoria == nil:
		maximum = item.prometheus.MaxLookbackMinutes
	case item.victoria != nil && item.prometheus == nil:
		maximum = item.victoria.MaxLookbackMinutes
	default:
		return 0, ErrContractRejected
	}
	if input.LookbackMinutes <= 0 || input.LookbackMinutes > maximum {
		return 0, ErrContractRejected
	}
	return time.Duration(input.LookbackMinutes) * time.Minute, nil
}

func strictDecodeObject(raw []byte, target any) error {
	if exactTopLevelJSONFields(raw, target) != nil {
		return ErrContractRejected
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrContractRejected
	}
	return nil
}

func exactTopLevelJSONFields(raw []byte, target any) error {
	if target == nil {
		return ErrContractRejected
	}
	targetType := reflect.TypeOf(target)
	for targetType.Kind() == reflect.Pointer {
		targetType = targetType.Elem()
	}
	if targetType.Kind() != reflect.Struct {
		return ErrContractRejected
	}
	var object map[string]json.RawMessage
	if json.Unmarshal(raw, &object) != nil || object == nil {
		return ErrContractRejected
	}
	allowed := make(map[string]struct{}, targetType.NumField())
	for index := 0; index < targetType.NumField(); index++ {
		field := targetType.Field(index)
		if field.PkgPath != "" {
			continue
		}
		name, _, _ := strings.Cut(field.Tag.Get("json"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = field.Name
		}
		allowed[name] = struct{}{}
	}
	for name := range object {
		if _, exists := allowed[name]; !exists {
			return ErrContractRejected
		}
	}
	return nil
}

func validateEvidence(item entry, evidence readtask.EvidenceCompletion, lookback time.Duration) error {
	if evidence.CollectedAt.IsZero() || evidence.CollectedAt.Year() < 1 || evidence.CollectedAt.Year() > 9999 ||
		evidence.Items == nil || len(evidence.Items) > readtask.MaxEvidenceItems {
		return ErrContractRejected
	}
	totalBytes := 0
	for _, raw := range evidence.Items {
		totalBytes += len(raw)
		if totalBytes > readtask.MaxEvidencePayloadBytes {
			return ErrContractRejected
		}
	}
	switch {
	case item.prometheus != nil && item.victoria == nil:
		return validatePrometheusEvidence(*item.prometheus, evidence, lookback)
	case item.victoria != nil && item.prometheus == nil:
		return validateVictoriaEvidence(*item.victoria, evidence, lookback)
	default:
		return ErrContractRejected
	}
}

func validatePrometheusEvidence(
	contract PrometheusRangeQueryV1,
	evidence readtask.EvidenceCompletion,
	lookback time.Duration,
) error {
	if len(evidence.Items) > contract.MaxItems {
		return ErrContractRejected
	}
	totalSamples := 0
	for _, raw := range evidence.Items {
		if domain.ValidateSafeJSONObject(raw) != nil {
			return ErrContractRejected
		}
		var series struct {
			Metric map[string]json.RawMessage `json:"metric"`
			Values []json.RawMessage          `json:"values"`
		}
		if strictDecodeObject(raw, &series) != nil || series.Metric == nil || len(series.Metric) > maximumLabels || len(series.Values) == 0 {
			return ErrContractRejected
		}
		for name, rawValue := range series.Metric {
			var value string
			if bytes.Equal(rawValue, []byte("null")) || json.Unmarshal(rawValue, &value) != nil ||
				!prometheusLabelPattern.MatchString(name) || readtask.EvidenceFieldReserved(name) ||
				len(value) > maximumLabelValueBytes || !domain.ValidSafeText(value) {
				return ErrContractRejected
			}
			if readtask.EvidenceFieldValueReserved(name, value) {
				return ErrContractRejected
			}
		}
		previous := math.Inf(-1)
		for _, sampleRaw := range series.Values {
			var pair []json.RawMessage
			if json.Unmarshal(sampleRaw, &pair) != nil || len(pair) != 2 {
				return ErrContractRejected
			}
			timestamp, err := parseCanonicalJSONNumber(pair[0])
			if err != nil || !validPrometheusSampleStep(previous, timestamp, contract.StepSeconds) ||
				!timestampInWindow(timestamp, evidence.CollectedAt, lookback) {
				return ErrContractRejected
			}
			previous = timestamp
			var value string
			if json.Unmarshal(pair[1], &value) != nil || !validPrometheusValue(value) {
				return ErrContractRejected
			}
			totalSamples++
			if totalSamples > contract.MaxSamples {
				return ErrContractRejected
			}
		}
	}
	return nil
}

func validPrometheusSampleStep(previous, current float64, stepSeconds int) bool {
	if math.IsInf(previous, -1) {
		return true
	}
	if current <= previous || stepSeconds <= 0 {
		return false
	}
	ratio := (current - previous) / float64(stepSeconds)
	nearest := math.Round(ratio)
	return nearest >= 1 && math.Abs(ratio-nearest) <= prometheusStepTolerance.Seconds()/float64(stepSeconds)
}

func validateVictoriaEvidence(
	contract VictoriaLogsSearchV1,
	evidence readtask.EvidenceCompletion,
	lookback time.Duration,
) error {
	if len(evidence.Items) > contract.Limit {
		return ErrContractRejected
	}
	fields := make(map[string]FieldSpec, len(contract.Fields))
	for _, field := range contract.Fields {
		fields[field.Name] = field
	}
	for _, raw := range evidence.Items {
		if domain.ValidateSafeJSONObject(raw) != nil {
			return ErrContractRejected
		}
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil || len(object) == 0 || len(object) > len(fields) {
			return ErrContractRejected
		}
		for name, field := range fields {
			if field.Required {
				if _, exists := object[name]; !exists {
					return ErrContractRejected
				}
			}
		}
		for name, value := range object {
			field, exists := fields[name]
			if !exists || validateVictoriaValue(field, value, evidence.CollectedAt, lookback) != nil {
				return ErrContractRejected
			}
		}
	}
	return nil
}

func validateVictoriaValue(field FieldSpec, raw json.RawMessage, collectedAt time.Time, lookback time.Duration) error {
	switch field.Type {
	case FieldString:
		var value string
		if bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, &value) != nil ||
			len(value) > field.MaxBytes || !domain.ValidSafeText(value) {
			return ErrContractRejected
		}
		if field.Name == "_time" {
			parsed, err := time.Parse(time.RFC3339Nano, value)
			if err != nil || parsed.Location() != time.UTC || parsed.Format(time.RFC3339Nano) != value ||
				!timeInWindow(parsed, collectedAt, lookback) {
				return ErrContractRejected
			}
		}
		if readtask.EvidenceFieldValueReserved(field.Name, value) {
			return ErrContractRejected
		}
	case FieldNumber:
		if _, err := parseCanonicalJSONNumber(raw); err != nil {
			return ErrContractRejected
		}
	case FieldBoolean:
		if string(raw) != "true" && string(raw) != "false" {
			return ErrContractRejected
		}
	case FieldNull:
		if string(raw) != "null" {
			return ErrContractRejected
		}
	default:
		return ErrContractRejected
	}
	return nil
}

func parseCanonicalJSONNumber(raw []byte) (float64, error) {
	if len(raw) == 0 || raw[0] == '"' || raw[0] == '[' || raw[0] == '{' || bytes.Equal(raw, []byte("null")) {
		return 0, ErrContractRejected
	}
	value, err := strconv.ParseFloat(string(raw), 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, ErrContractRejected
	}
	canonical, err := jsoncanonicalizer.NumberToJSON(value)
	if err != nil || canonical != string(raw) || math.Trunc(value) == value && math.Abs(value) > 1<<53-1 {
		return 0, ErrContractRejected
	}
	return value, nil
}

func validPrometheusValue(value string) bool {
	if len(value) == 0 || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	if value == "NaN" || value == "+Inf" || value == "-Inf" {
		return true
	}
	if !prometheusNumberPattern.MatchString(value) {
		return false
	}
	parsed, err := strconv.ParseFloat(value, 64)
	return err == nil && !math.IsNaN(parsed) && !math.IsInf(parsed, 0)
}

func timestampInWindow(timestamp float64, collectedAt time.Time, lookback time.Duration) bool {
	seconds, fraction := math.Modf(timestamp)
	if seconds < -62135596800 || seconds > 253402300799 {
		return false
	}
	nanoseconds := int64(math.Round(fraction * float64(time.Second)))
	parsed := time.Unix(int64(seconds), nanoseconds).UTC()
	return timeInWindow(parsed, collectedAt, lookback)
}

func timeInWindow(value, collectedAt time.Time, lookback time.Duration) bool {
	minimum := collectedAt.UTC().Add(-lookback - evidenceClockTolerance)
	maximum := collectedAt.UTC().Add(evidenceClockTolerance)
	value = value.UTC()
	return !value.Before(minimum) && !value.After(maximum)
}
