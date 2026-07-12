package readexecutor

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestStrictJSONRejectsAmbiguousOrUnsafeStructures(t *testing.T) {
	t.Parallel()
	valid := []byte(`{"status":"success","data":{"resultType":"matrix","result":[]}}`)
	var decoded struct {
		Status string `json:"status"`
		Data   struct {
			ResultType string            `json:"resultType"`
			Result     []json.RawMessage `json:"result"`
		} `json:"data"`
	}
	if !strictDecodeJSONObject(valid, &decoded) || decoded.Status != "success" || decoded.Data.ResultType != "matrix" {
		t.Fatal("strict decoder rejected valid response")
	}

	tooDeep := strings.Repeat(`{"a":`, readtaskJSONDepthForTest()) + `0` + strings.Repeat(`}`, readtaskJSONDepthForTest())
	for name, encoded := range map[string][]byte{
		"empty":             nil,
		"array root":        []byte(`[]`),
		"duplicate":         []byte(`{"a":1,"a":2}`),
		"escaped duplicate": []byte(`{"resultType":"matrix","result\u0054ype":"matrix"}`),
		"case-folded field": []byte(`{"STATUS":"success"}`),
		"case-fold alias":   []byte(`{"status":"error","STATUS":"success"}`),
		"unknown":           []byte(`{"status":"success","unknown":true}`),
		"trailing":          []byte(`{} {}`),
		"invalid UTF-8":     {0xff},
		"control string":    []byte(`{"a":"\u0000"}`),
		"format string":     []byte(`{"a":"\u202e"}`),
		"too deep":          []byte(tooDeep),
	} {
		t.Run(name, func(t *testing.T) {
			var target struct {
				Status string `json:"status"`
			}
			if strictDecodeJSONObject(encoded, &target) {
				t.Fatalf("strictDecodeJSONObject(%s) accepted invalid JSON", name)
			}
		})
	}
}

func readtaskJSONDepthForTest() int { return 18 }

func FuzzStrictJSONNeverPanics(f *testing.F) {
	f.Add([]byte(`{"status":"success"}`))
	f.Add([]byte(`{"a":1,"a":2}`))
	f.Fuzz(func(t *testing.T, encoded []byte) {
		var target struct {
			Status string `json:"status"`
		}
		_ = strictDecodeJSONObject(encoded, &target)
		_, _ = canonicalJSONObject(encoded)
	})
}

func TestPinnedProfileDigestMatchesCanonicalContract(t *testing.T) {
	digest, err := currentProfileContractDigest()
	if err != nil || digest != CurrentProfileDigest {
		t.Fatalf("current profile digest = %q, %v; update audited pin %q", digest, err, CurrentProfileDigest)
	}
}
