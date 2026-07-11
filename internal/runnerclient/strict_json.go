package runnerclient

import (
	"bytes"
	"encoding/json"
	"io"
	"unicode/utf8"
)

const maximumJSONDepth = 32

func validStrictJSONDocument(encoded []byte) bool {
	if len(encoded) == 0 || !utf8.Valid(encoded) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if !readStrictJSONValue(decoder, 0) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func readStrictJSONValue(decoder *json.Decoder, depth int) bool {
	if decoder == nil || depth > maximumJSONDepth {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
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
			if keyErr != nil || !ok || !canonicalJSONName(key) {
				return false
			}
			if _, duplicate := seen[key]; duplicate {
				return false
			}
			seen[key] = struct{}{}
			if !readStrictJSONValue(decoder, depth+1) {
				return false
			}
		}
		closing, closeErr := decoder.Token()
		return closeErr == nil && closing == json.Delim('}')
	case '[':
		for decoder.More() {
			if !readStrictJSONValue(decoder, depth+1) {
				return false
			}
		}
		closing, closeErr := decoder.Token()
		return closeErr == nil && closing == json.Delim(']')
	default:
		return false
	}
}

func canonicalJSONName(value string) bool {
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
