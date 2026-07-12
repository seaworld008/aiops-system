package readexecutor

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/cyberphone/json-canonicalization/go/src/webpki.org/jsoncanonicalizer"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

type responseFailure uint8

const (
	responseAccepted responseFailure = iota
	responseInvalid
	responseRejected
)

func strictDecodeJSONObject(encoded []byte, target any) bool {
	if target == nil || !strictJSONValue(encoded) || len(encoded) == 0 || firstNonSpace(encoded) != '{' {
		return false
	}
	if !exactJSONFieldNames(encoded, reflect.TypeOf(target)) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return false
	}
	var trailing any
	return errors.Is(decoder.Decode(&trailing), io.EOF)
}

var jsonUnmarshalerType = reflect.TypeOf((*json.Unmarshaler)(nil)).Elem()

func exactJSONFieldNames(encoded []byte, targetType reflect.Type) bool {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var value any
	if decoder.Decode(&value) != nil {
		return false
	}
	return validateExactJSONFields(value, targetType)
}

func validateExactJSONFields(value any, targetType reflect.Type) bool {
	if targetType == nil {
		return false
	}
	for targetType.Kind() == reflect.Pointer {
		if targetType.Implements(jsonUnmarshalerType) {
			return true
		}
		targetType = targetType.Elem()
	}
	if targetType.Implements(jsonUnmarshalerType) ||
		(targetType.Kind() != reflect.Pointer && reflect.PointerTo(targetType).Implements(jsonUnmarshalerType)) {
		return true
	}
	if value == nil {
		return false
	}
	switch targetType.Kind() {
	case reflect.Struct:
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		fields := make(map[string]reflect.Type, targetType.NumField())
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
			fields[name] = field.Type
		}
		for name, child := range object {
			fieldType, exists := fields[name]
			if !exists || !validateExactJSONFields(child, fieldType) {
				return false
			}
		}
	case reflect.Slice, reflect.Array:
		values, ok := value.([]any)
		if !ok {
			return false
		}
		for _, child := range values {
			if !validateExactJSONFields(child, targetType.Elem()) {
				return false
			}
		}
	case reflect.Map:
		object, ok := value.(map[string]any)
		if !ok || targetType.Key().Kind() != reflect.String {
			return false
		}
		for _, child := range object {
			if !validateExactJSONFields(child, targetType.Elem()) {
				return false
			}
		}
	}
	return true
}

func strictJSONValue(encoded []byte) bool {
	if len(encoded) == 0 || !utf8.Valid(encoded) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil || !consumeStrictJSONToken(decoder, token, 1) {
		return false
	}
	_, err = decoder.Token()
	return errors.Is(err, io.EOF)
}

func consumeStrictJSONToken(decoder *json.Decoder, token json.Token, depth int) bool {
	if decoder == nil || depth > readtask.MaxEvidenceJSONDepth || !validUpstreamJSONStringToken(token) {
		return false
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return true
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok || !validUpstreamJSONString(key) {
				return false
			}
			if _, duplicate := seen[key]; duplicate {
				return false
			}
			seen[key] = struct{}{}
			child, err := decoder.Token()
			if err != nil || !consumeStrictJSONToken(decoder, child, depth+1) {
				return false
			}
		}
		closing, err := decoder.Token()
		return err == nil && closing == json.Delim('}')
	case '[':
		for decoder.More() {
			child, err := decoder.Token()
			if err != nil || !consumeStrictJSONToken(decoder, child, depth+1) {
				return false
			}
		}
		closing, err := decoder.Token()
		return err == nil && closing == json.Delim(']')
	default:
		return false
	}
}

func validUpstreamJSONStringToken(token json.Token) bool {
	value, ok := token.(string)
	return !ok || validUpstreamJSONString(value)
}

func validUpstreamJSONString(value string) bool {
	return utf8.ValidString(value) && !bytes.ContainsRune([]byte(value), utf8.RuneError) &&
		!containsUnsafeUnicode(value)
}

func containsUnsafeUnicode(value string) bool {
	for _, character := range value {
		if unicode.IsControl(character) || unicode.Is(unicode.Cf, character) {
			return true
		}
	}
	return false
}

func canonicalJSONObject(encoded []byte) ([]byte, bool) {
	if !strictJSONValue(encoded) || firstNonSpace(encoded) != '{' {
		return nil, false
	}
	canonical, err := jsoncanonicalizer.Transform(encoded)
	if err != nil || len(canonical) == 0 {
		return nil, false
	}
	return canonical, true
}

func evidenceFitsProjectionBudget(evidence readtask.EvidenceCompletion) bool {
	wire, err := json.Marshal(struct {
		Source      string            `json:"source"`
		CollectedAt time.Time         `json:"collected_at"`
		ItemCount   int               `json:"item_count"`
		Truncated   bool              `json:"truncated"`
		Items       []json.RawMessage `json:"items"`
	}{
		Source: strings.Repeat("x", 128), CollectedAt: evidence.CollectedAt,
		ItemCount: len(evidence.Items), Truncated: false, Items: evidence.Items,
	})
	if err != nil || len(wire) > readtask.MaxEvidencePayloadBytes {
		return false
	}
	canonical, err := jsoncanonicalizer.Transform(wire)
	return err == nil && len(canonical) <= readtask.MaxEvidencePayloadBytes
}

func firstNonSpace(encoded []byte) byte {
	trimmed := bytes.TrimSpace(encoded)
	if len(trimmed) == 0 {
		return 0
	}
	return trimmed[0]
}
