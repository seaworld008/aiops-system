package externalcmdb

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"reflect"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

const (
	catalogProtocolVersion = "cmdb-catalog/v1"
	catalogContentType     = "application/json"

	capabilitiesPath = "/v1/capabilities"
	assetsPath       = "/v1/assets"
	relationsPath    = "/v1/relations"

	maxCapabilitiesBodyBytes int64 = 64 << 10
	maxPageBodyBytes         int64 = 4 << 20
)

var (
	errProtocolContract       = errors.New("external cmdb protocol contract violation")
	wireTimestampPattern      = regexp.MustCompile(`^[0-9]{4}-(0[1-9]|1[0-2])-([0-2][0-9]|3[01])T([01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](\.[0-9]{1,6})?Z$`)
	wireTimeType              = reflect.TypeOf(time.Time{})
	protocolDestinationMaxPtr = 8
)

type protocolContractError struct {
	code string
}

func (err *protocolContractError) Error() string {
	return errProtocolContract.Error() + ": " + err.code
}

func (*protocolContractError) Unwrap() error {
	return errProtocolContract
}

type catalogCapabilities struct {
	ProtocolVersion   string    `json:"protocol_version"`
	AuthorityID       string    `json:"authority_id"`
	SnapshotEpoch     string    `json:"snapshot_epoch"`
	MaxPageSize       int       `json:"max_page_size"`
	SupportsDelta     bool      `json:"supports_delta"`
	SupportsTombstone bool      `json:"supports_tombstone"`
	ServerTime        time.Time `json:"server_time"`
	Permissions       []string  `json:"permissions"`
}

type catalogAsset struct {
	ExternalID      string            `json:"external_id"`
	TypeCode        string            `json:"type_code"`
	DisplayName     string            `json:"display_name"`
	ObjectRevision  int64             `json:"object_revision"`
	UpdatedAt       time.Time         `json:"updated_at"`
	Deleted         bool              `json:"deleted"`
	TombstoneReason string            `json:"tombstone_reason"`
	Attributes      map[string]string `json:"attributes"`
}

type catalogRelation struct {
	ExternalID     string    `json:"external_id"`
	FromExternalID string    `json:"from_external_id"`
	ToExternalID   string    `json:"to_external_id"`
	TypeCode       string    `json:"type_code"`
	ObjectRevision int64     `json:"object_revision"`
	UpdatedAt      time.Time `json:"updated_at"`
	Deleted        bool      `json:"deleted"`
}

type catalogPage[T any] struct {
	Items            []T    `json:"items"`
	NextCursor       string `json:"next_cursor"`
	SnapshotEpoch    string `json:"snapshot_epoch"`
	FinalPage        bool   `json:"final_page"`
	CompleteSnapshot bool   `json:"complete_snapshot"`
}

func decodeStrictJSON(reader io.Reader, maxBytes int64, destination any) error {
	if reader == nil || destination == nil || maxBytes <= 0 {
		return protocolError("INVALID_DECODER_INPUT")
	}
	payload, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return protocolError("BODY_READ_FAILED")
	}
	if int64(len(payload)) > maxBytes {
		return protocolError("BODY_LIMIT_EXCEEDED")
	}
	if !utf8.Valid(payload) {
		return protocolError("INVALID_UTF8")
	}
	if len(bytes.TrimSpace(payload)) == 0 {
		return protocolError("EMPTY_BODY")
	}
	if err := rejectDuplicateJSONKeys(payload); err != nil {
		return err
	}
	if err := validateRequiredJSONShape(payload, reflect.TypeOf(destination), 0); err != nil {
		return err
	}

	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return protocolError("SCHEMA_MISMATCH")
	}
	if err := requireJSONEOF(decoder); err != nil {
		return err
	}
	return nil
}

func rejectDuplicateJSONKeys(payload []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	first, err := decoder.Token()
	if err != nil {
		return protocolError("INVALID_JSON")
	}
	if err := scanJSONValue(decoder, first, 0); err != nil {
		return err
	}
	return requireJSONTokenEOF(decoder)
}

func scanJSONValue(decoder *json.Decoder, first json.Token, depth int) error {
	if depth > 64 {
		return protocolError("JSON_DEPTH_EXCEEDED")
	}
	delimiter, isDelimiter := first.(json.Delim)
	if !isDelimiter {
		return nil
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return protocolError("INVALID_JSON")
			}
			key, ok := keyToken.(string)
			if !ok {
				return protocolError("INVALID_JSON")
			}
			if _, duplicate := seen[key]; duplicate {
				return protocolError("DUPLICATE_JSON_KEY")
			}
			seen[key] = struct{}{}
			valueToken, err := decoder.Token()
			if err != nil {
				return protocolError("INVALID_JSON")
			}
			if err := scanJSONValue(decoder, valueToken, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return protocolError("INVALID_JSON")
		}
	case '[':
		for decoder.More() {
			valueToken, err := decoder.Token()
			if err != nil {
				return protocolError("INVALID_JSON")
			}
			if err := scanJSONValue(decoder, valueToken, depth+1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return protocolError("INVALID_JSON")
		}
	default:
		return protocolError("INVALID_JSON")
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	return protocolError("TRAILING_JSON")
}

func requireJSONTokenEOF(decoder *json.Decoder) error {
	_, err := decoder.Token()
	if errors.Is(err, io.EOF) {
		return nil
	}
	return protocolError("TRAILING_JSON")
}

func validateRequiredJSONShape(payload []byte, destinationType reflect.Type, depth int) error {
	if destinationType == nil || depth > 64 {
		return protocolError("SCHEMA_MISMATCH")
	}
	for destinationType.Kind() == reflect.Pointer {
		depth++
		if depth > protocolDestinationMaxPtr {
			return protocolError("SCHEMA_MISMATCH")
		}
		destinationType = destinationType.Elem()
	}
	trimmed := bytes.TrimSpace(payload)
	if bytes.Equal(trimmed, []byte("null")) {
		return protocolError("REQUIRED_FIELD_MISSING")
	}
	if destinationType == wireTimeType {
		var value string
		if err := json.Unmarshal(trimmed, &value); err != nil ||
			!wireTimestampPattern.MatchString(value) {
			return protocolError("TIMESTAMP_FORMAT_REJECTED")
		}
		if _, err := time.Parse(time.RFC3339Nano, value); err != nil {
			return protocolError("TIMESTAMP_FORMAT_REJECTED")
		}
		return nil
	}

	switch destinationType.Kind() {
	case reflect.Struct:
		var object map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &object); err != nil || object == nil {
			return protocolError("SCHEMA_MISMATCH")
		}
		allowed := make(map[string]reflect.StructField, destinationType.NumField())
		for index := 0; index < destinationType.NumField(); index++ {
			field := destinationType.Field(index)
			if !field.IsExported() {
				continue
			}
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name == "" || name == "-" {
				return protocolError("SCHEMA_MISMATCH")
			}
			if _, duplicate := allowed[name]; duplicate {
				return protocolError("SCHEMA_MISMATCH")
			}
			allowed[name] = field
		}
		for name := range object {
			if _, exact := allowed[name]; !exact {
				return protocolError("UNKNOWN_FIELD")
			}
		}
		for name, field := range allowed {
			raw, present := object[name]
			if !present {
				return protocolError("REQUIRED_FIELD_MISSING")
			}
			if err := validateRequiredJSONShape(raw, field.Type, depth+1); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		var elements []json.RawMessage
		if err := json.Unmarshal(trimmed, &elements); err != nil || elements == nil {
			return protocolError("SCHEMA_MISMATCH")
		}
		for _, element := range elements {
			if err := validateRequiredJSONShape(element, destinationType.Elem(), depth+1); err != nil {
				return err
			}
		}
	case reflect.Map:
		var entries map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &entries); err != nil || entries == nil {
			return protocolError("SCHEMA_MISMATCH")
		}
		for _, entry := range entries {
			if err := validateRequiredJSONShape(entry, destinationType.Elem(), depth+1); err != nil {
				return err
			}
		}
	default:
		var value any
		if err := json.Unmarshal(trimmed, &value); err != nil || value == nil {
			return protocolError("SCHEMA_MISMATCH")
		}
	}
	return nil
}

func protocolError(code string) error {
	return &protocolContractError{code: code}
}

func protocolErrorHasCode(err error, code string) bool {
	var contractError *protocolContractError
	return errors.As(err, &contractError) && contractError.code == code
}
