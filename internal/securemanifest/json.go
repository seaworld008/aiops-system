package securemanifest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

const maximumJSONDepth = 16

// DecodeStrict accepts one UTF-8 JSON value, rejects unknown struct fields,
// duplicate object members (including escaped aliases), non-canonical object
// field names and trailing data, and decodes it into target.
func DecodeStrict(encoded []byte, target any) error {
	if len(encoded) == 0 || target == nil || !utf8.Valid(encoded) || !validJSON(encoded) {
		return ErrJSON
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return ErrJSON
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return ErrJSON
	}
	return nil
}

func validJSON(encoded []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if !walkJSONValue(decoder, 0) {
		return false
	}
	_, err := decoder.Token()
	return errors.Is(err, io.EOF)
}

func walkJSONValue(decoder *json.Decoder, depth int) bool {
	if decoder == nil || depth > maximumJSONDepth {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		switch token.(type) {
		case nil, bool, string, json.Number:
			return true
		default:
			return false
		}
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			key, ok := keyToken.(string)
			if keyErr != nil || !ok || !canonicalFieldName(key) {
				return false
			}
			if _, duplicate := seen[key]; duplicate {
				return false
			}
			seen[key] = struct{}{}
			if !walkJSONValue(decoder, depth+1) {
				return false
			}
		}
		closing, closeErr := decoder.Token()
		return closeErr == nil && closing == json.Delim('}')
	case '[':
		for decoder.More() {
			if !walkJSONValue(decoder, depth+1) {
				return false
			}
		}
		closing, closeErr := decoder.Token()
		return closeErr == nil && closing == json.Delim(']')
	default:
		return false
	}
}

func canonicalFieldName(value string) bool {
	if value == "" || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if (character < 'a' || character > 'z') && (character < '0' || character > '9') && character != '_' {
			return false
		}
	}
	return true
}
