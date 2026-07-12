package readrunnerclient

import (
	"encoding/base64"
	"regexp"
)

var readTaskTokenPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$`)

func validLeaseToken(value []byte) bool {
	if !readTaskTokenPattern.Match(value) {
		return false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(string(value))
	if decoded != nil {
		defer clear(decoded)
	}
	return err == nil && len(decoded) == 32 && base64.RawURLEncoding.EncodeToString(decoded) == string(value)
}
