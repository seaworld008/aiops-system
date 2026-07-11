package domain

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

const MaxInvestigationJSONBytes = 64 * 1024
const MaxResourceIDBytes = 256
const maxInvestigationJSONDepth = 32

var (
	sha256HexPattern      = regexp.MustCompile(`^[a-f0-9]{64}$`)
	identifierPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]*$`)
	idempotencyKeyPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._:/-]{0,127}$`)
	lowCardinalityPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)
)

func ValidSHA256Hex(value string) bool {
	return sha256HexPattern.MatchString(value)
}

func ValidResourceID(value string) bool {
	return validIdentifier(value, MaxResourceIDBytes)
}

func ValidIdempotencyKey(value string) bool {
	return idempotencyKeyPattern.MatchString(value)
}

func ValidFailureCode(value string) bool {
	return len(value) <= 128 && lowCardinalityPattern.MatchString(value)
}

func ValidConnectorID(value string) bool {
	return len(value) <= 128 && lowCardinalityPattern.MatchString(value)
}

func ValidOperation(value string) bool {
	return len(value) <= 64 && lowCardinalityPattern.MatchString(value)
}

func ValidateSafeJSONObject(value json.RawMessage) error {
	if len(value) == 0 || len(value) > MaxInvestigationJSONBytes || !utf8.Valid(value) {
		return fmt.Errorf("JSON must be a valid object of at most %d bytes", MaxInvestigationJSONBytes)
	}
	if !json.Valid(value) {
		return fmt.Errorf("JSON must be a valid object of at most %d bytes", MaxInvestigationJSONBytes)
	}
	if err := validateStrictJSONTokens(value); err != nil {
		return err
	}
	var object map[string]any
	if err := json.Unmarshal(value, &object); err != nil || object == nil {
		return fmt.Errorf("JSON must be an object")
	}
	if err := rejectSensitiveJSON(object, nil); err != nil {
		return err
	}
	return nil
}

func ValidateSafeAttributes(attributes map[string]string) error {
	if len(attributes) > 32 {
		return fmt.Errorf("evidence attributes exceed limit")
	}
	for key, value := range attributes {
		if !lowCardinalityPattern.MatchString(key) || len(key) > 64 || len(value) > 512 ||
			!ValidSafeMetadata(key, value) {
			return fmt.Errorf("evidence attributes contain invalid or sensitive metadata")
		}
	}
	return nil
}

func ValidSafeMetadata(name, value string) bool {
	return validSafeUnicode(name) && validSafeUnicode(value) &&
		!unsafeSecurityName(name) && !unsafeSecurityValue(value) &&
		(normalizeSecurityName(name) != "name" || !unsafeSecurityName(value))
}

func ValidSafeText(value string) bool {
	return validSafeUnicode(value) && !unsafeSecurityValue(value)
}

func validSafeUnicode(value string) bool {
	return utf8.ValidString(value) && !strings.ContainsRune(value, utf8.RuneError) &&
		strings.IndexFunc(value, func(character rune) bool {
			return unicode.IsControl(character) || unicode.Is(unicode.Cf, character)
		}) < 0
}

func validateHashedJSONObject(value json.RawMessage, hash string) error {
	if err := ValidateSafeJSONObject(value); err != nil {
		return err
	}
	if !ValidSHA256Hex(hash) {
		return fmt.Errorf("SHA-256 hash must be lowercase hexadecimal")
	}
	digest := sha256.Sum256(value)
	if fmt.Sprintf("%x", digest[:]) != hash {
		return fmt.Errorf("SHA-256 hash does not match JSON")
	}
	return nil
}

func validIdentifier(value string, maxBytes int) bool {
	return len(value) > 0 && len(value) <= maxBytes && identifierPattern.MatchString(value)
}

func rejectSensitiveJSON(value any, path []string) error {
	switch item := value.(type) {
	case map[string]any:
		for key, child := range item {
			if normalized := normalizeSecurityName(key); normalized == "name" || normalized == "key" {
				if name, ok := child.(string); ok && unsafeSecurityName(name) {
					return fmt.Errorf("JSON contains forbidden sensitive metadata")
				}
			}
		}
		for key, child := range item {
			nextPath := append(append([]string(nil), path...), key)
			if unsafeSecurityName(key) || unsafeSecurityPath(nextPath) {
				return fmt.Errorf("JSON contains forbidden sensitive metadata")
			}
			if err := rejectSensitiveJSON(child, nextPath); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range item {
			if err := rejectSensitiveJSON(child, path); err != nil {
				return err
			}
		}
	case string:
		if unsafeSecurityValue(item) {
			return fmt.Errorf("JSON contains forbidden sensitive metadata")
		}
	}
	return nil
}

func validateStrictJSONTokens(value []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("JSON contains invalid structure")
	}
	if err := consumeJSONToken(decoder, token, 1); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return fmt.Errorf("JSON contains invalid trailing data")
	}
	return nil
}

func consumeJSONToken(decoder *json.Decoder, token json.Token, depth int) error {
	if depth > maxInvestigationJSONDepth {
		return fmt.Errorf("JSON nesting exceeds limit")
	}
	if text, ok := token.(string); ok {
		if !validStrictJSONString(text) {
			return fmt.Errorf("JSON contains invalid Unicode")
		}
		if unsafeSecurityValue(text) {
			return fmt.Errorf("JSON contains forbidden sensitive metadata")
		}
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("JSON contains invalid object")
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("JSON contains invalid object key")
			}
			if !validStrictJSONString(key) {
				return fmt.Errorf("JSON contains invalid Unicode")
			}
			if unsafeSecurityValue(key) {
				return fmt.Errorf("JSON contains forbidden sensitive metadata")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("JSON contains duplicate object field")
			}
			seen[key] = struct{}{}
			child, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("JSON contains invalid object value")
			}
			if err := consumeJSONToken(decoder, child, depth+1); err != nil {
				return err
			}
		}
	case '[':
		for decoder.More() {
			child, err := decoder.Token()
			if err != nil {
				return fmt.Errorf("JSON contains invalid array value")
			}
			if err := consumeJSONToken(decoder, child, depth+1); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("JSON contains invalid delimiter")
	}
	if _, err := decoder.Token(); err != nil {
		return fmt.Errorf("JSON contains unterminated structure")
	}
	return nil
}

func validStrictJSONString(value string) bool {
	return validSafeUnicode(value)
}

func unsafeSecurityPath(path []string) bool {
	hasErrorContext := false
	for _, segment := range path {
		normalized := normalizeSecurityName(segment)
		if strings.Contains(normalized, "error") || strings.Contains(normalized, "response") {
			hasErrorContext = true
			continue
		}
		if hasErrorContext && (strings.Contains(normalized, "body") || strings.Contains(normalized, "details") ||
			strings.Contains(normalized, "message")) {
			return true
		}
	}
	return unsafeSecurityName(strings.Join(path, "."))
}

func normalizeSecurityName(value string) string {
	var normalized strings.Builder
	for _, character := range value {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			normalized.WriteRune(unicode.ToLower(character))
		}
	}
	return normalized.String()
}

func unsafeSecurityName(value string) bool {
	normalized := normalizeSecurityName(value)
	for _, marker := range []string{
		"authorization", "authentication", "auth", "apikey", "accessor", "credential",
		"rawerror", "errorbody", "secret", "token", "password", "cookie", "privatekey",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func unsafeSecurityValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	if strings.HasPrefix(trimmed, "--") {
		option := strings.TrimPrefix(trimmed, "--")
		if separator := strings.IndexByte(option, '='); separator >= 0 {
			option = option[:separator]
		}
		if unsafeSecurityName(option) {
			return true
		}
	}
	if containsUnsafeSecurityAssignment(value) {
		return true
	}
	normalized := strings.ToLower(trimmed)
	for _, marker := range []string{
		"bearer ", "authorization", "cookie", "set-cookie", "begin private key", "begin rsa private key",
		"private key", "private-key", "private_key", "raw error body", "raw_error_body", "raw-error-body",
	} {
		if strings.Contains(normalized, marker) {
			return true
		}
	}
	return false
}

func containsUnsafeSecurityAssignment(value string) bool {
	for index, character := range value {
		if character != ':' && character != '=' {
			continue
		}
		skeleton := normalizeSecurityName(value[:index])
		for _, marker := range []string{
			"authorization", "authentication", "auth", "apikey", "accessor", "credential",
			"rawerror", "errorbody", "secret", "token", "password", "cookie", "privatekey",
		} {
			if strings.HasSuffix(skeleton, marker) {
				return true
			}
		}
	}
	return false
}
