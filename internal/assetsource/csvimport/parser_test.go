package csvimport

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/assetdiscovery"
)

const (
	testEnvironmentID      = "11111111-1111-4111-8111-111111111111"
	testOtherEnvironmentID = "22222222-2222-4222-8222-222222222222"
)

func TestCSVImportRequiresElevenColumnsAndResumesWithoutDuplicatingRows(t *testing.T) {
	input := csvFile(t, 2001, func(index int) []string {
		return ordinaryRow(testEnvironmentID, fmt.Sprintf("vm-%04d", index), fmt.Sprint(index))
	})
	limits := testLimits(testEnvironmentID)

	first, err := Parse(strings.NewReader(input), limits)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(first.Items); got != 2000 {
		t.Fatalf("first page item count = %d, want 2000", got)
	}
	if first.FinalPage {
		t.Fatal("first page unexpectedly final")
	}
	if first.Next.SchemaVersion != SchemaVersion || first.Next.RowNumber != 2001 ||
		len(first.Next.FileSHA256) != 64 {
		t.Fatalf("first checkpoint = %#v", first.Next)
	}

	second, err := Resume(strings.NewReader(input), first.Next, limits)
	if err != nil {
		t.Fatal(err)
	}
	if got := len(second.Items); got != 1 {
		t.Fatalf("second page item count = %d, want 1", got)
	}
	if second.Items[0].ExternalID != "vm-2001" || !second.FinalPage {
		t.Fatalf("second page = %#v", second)
	}
	if second.Next.RowNumber != 2002 || second.Next.FileSHA256 != first.Next.FileSHA256 {
		t.Fatalf("second checkpoint = %#v, first = %#v", second.Next, first.Next)
	}

	badHeader := strings.Replace(input, Header, strings.TrimSuffix(Header, ",relation_target_external_id"), 1)
	if _, err := Parse(strings.NewReader(badHeader), limits); !errors.Is(err, ErrInvalidSchema) {
		t.Fatalf("ten-column header error = %v", err)
	}
	for name, mutate := range map[string]func(Checkpoint) Checkpoint{
		"file sha": func(checkpoint Checkpoint) Checkpoint {
			checkpoint.FileSHA256 = strings.Repeat("0", 64)
			return checkpoint
		},
		"schema": func(checkpoint Checkpoint) Checkpoint {
			checkpoint.SchemaVersion = "CSV_RFC4180_V2"
			return checkpoint
		},
		"row": func(checkpoint Checkpoint) Checkpoint {
			checkpoint.RowNumber = 0
			return checkpoint
		},
		"first row replay": func(checkpoint Checkpoint) Checkpoint {
			checkpoint.RowNumber = 1
			return checkpoint
		},
		"non-boundary row": func(checkpoint Checkpoint) Checkpoint {
			checkpoint.RowNumber = 2
			return checkpoint
		},
	} {
		t.Run("rejects checkpoint "+name+" drift", func(t *testing.T) {
			if _, err := Resume(strings.NewReader(input), mutate(first.Next), limits); !errors.Is(err, ErrCheckpointMismatch) {
				t.Fatalf("Resume error = %v", err)
			}
		})
	}
}

func TestCSVImportRejectsFormulaAndSecretShapedFields(t *testing.T) {
	for _, value := range []string{
		`=WEBSERVICE("https://example.invalid")`,
		`+cmd|' /C calc'!A0`,
		"password=hidden",
		"Bearer abcdefghijklmnopqrstuvwxyz",
	} {
		t.Run(value, func(t *testing.T) {
			input := csvFile(t, 1, func(int) []string {
				row := ordinaryRow(testEnvironmentID, "vm-safe", "1")
				row[4] = value
				return row
			})
			if _, err := Parse(strings.NewReader(input), testLimits(testEnvironmentID)); !errors.Is(err, ErrUnsafeField) {
				t.Fatalf("Parse error = %v", err)
			}
		})
	}
}

func TestCSVImportRejectsUppercaseWrongProviderForItemsAndTombstones(t *testing.T) {
	for _, deleted := range []bool{false, true} {
		t.Run(fmt.Sprintf("deleted=%t", deleted), func(t *testing.T) {
			row := ordinaryRow(testEnvironmentID, "vm-wrong-provider", "1")
			row[1] = "OTHER_PROVIDER_V1"
			if deleted {
				row[4], row[6], row[7] = "", "true", "PROVIDER_DELETED"
			}
			if _, err := Parse(strings.NewReader(csvRows(t, row)), testLimits(testEnvironmentID)); !errors.Is(err, ErrInvalidField) {
				t.Fatalf("Parse error = %v", err)
			}
		})
	}
}

func TestCSVImportEnforcesAuthorityAndEmitsRelationOrTombstone(t *testing.T) {
	input := csvRows(t,
		[]string{
			testEnvironmentID, "CSV_RFC4180_V1", "vm-source", "LINUX_VM", "source vm", "7", "false", "",
			"RUNS_ON", testEnvironmentID, "host-target",
		},
		[]string{
			testEnvironmentID, "CSV_RFC4180_V1", "vm-deleted", "LINUX_VM", "", "8", "true", "PROVIDER_DELETED",
			"", "", "",
		},
	)

	page, err := Parse(strings.NewReader(input), testLimits(testEnvironmentID))
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 2 || len(page.Relations) != 1 || !page.FinalPage {
		t.Fatalf("page shape = %#v", page)
	}
	item := page.Items[0]
	if got, want := item.Freshness.ProviderVersionSHA256,
		framedDigest("csv-object-version.v1", "7"); got != want {
		t.Fatalf("object version digest = %q, want %q", got, want)
	}
	if item.Freshness.Kind != assetcatalog.FreshnessObjectSequence ||
		item.Freshness.OrderSequence != 7 {
		t.Fatalf("object freshness = %#v", item.Freshness)
	}
	for _, provenance := range item.FieldProvenance {
		if strings.Contains(provenance.ProviderPathCode, item.ExternalID) ||
			provenance.Ownership != assetcatalog.FieldOwnershipSource {
			t.Fatalf("unsafe provenance = %#v", provenance)
		}
	}

	relation := page.Relations[0]
	if relation.FromExternalID != "vm-source" || relation.ToExternalID != "host-target" ||
		relation.Type != assetcatalog.RelationshipRunsOn {
		t.Fatalf("relation = %#v", relation)
	}
	if got, want := relation.Freshness.ProviderVersionSHA256,
		framedDigest("csv-relation-version.v1", "7", "RUNS_ON", testEnvironmentID, "host-target"); got != want {
		t.Fatalf("relation version digest = %q, want %q", got, want)
	}

	tombstone := page.Items[1]
	if !tombstone.Tombstone || tombstone.TombstoneReason != "PROVIDER_DELETED" ||
		tombstone.Kind != "" || tombstone.DisplayName != "" {
		t.Fatalf("tombstone = %#v", tombstone)
	}

	outsideAuthority := strings.Replace(input, testEnvironmentID+",host-target", testOtherEnvironmentID+",host-target", 1)
	if _, err := Parse(strings.NewReader(outsideAuthority), testLimits(testEnvironmentID)); !errors.Is(err, ErrAuthorityMismatch) {
		t.Fatalf("relation target authority error = %v", err)
	}
	badTombstone := strings.Replace(input, ",true,PROVIDER_DELETED,", ",true,UNREVIEWED_REASON,", 1)
	if _, err := Parse(strings.NewReader(badTombstone), testLimits(testEnvironmentID)); !errors.Is(err, ErrInvalidTombstone) {
		t.Fatalf("tombstone reason error = %v", err)
	}
}

func TestCSVImportFixturesProduceValidM1CFacts(t *testing.T) {
	policy := assetcatalogPolicy()
	for _, fixture := range []string{"valid-v1.csv", "tombstone-v1.csv"} {
		t.Run(fixture, func(t *testing.T) {
			payload, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "asset-source", "csv", fixture))
			if err != nil {
				t.Fatal(err)
			}
			page, err := Parse(strings.NewReader(string(payload)), testLimits(testEnvironmentID))
			if err != nil {
				t.Fatal(err)
			}
			if err := assetdiscovery.ValidateFacts(page.Items, page.Relations, policy); err != nil {
				t.Fatalf("M1C fact validation error = %v", err)
			}
		})
	}
}

func TestCSVImportBoundaryMatrix(t *testing.T) {
	if MaxFileBytes != 32<<20 || MaxRows != 100_000 || MaxFieldBytes != 512 || MaxRowsPerPage != 2_000 {
		t.Fatalf("hard limits = (%d, %d, %d, %d)", MaxFileBytes, MaxRows, MaxFieldBytes, MaxRowsPerPage)
	}

	t.Run("accepts one leading UTF-8 BOM and hashes raw file", func(t *testing.T) {
		input := "\ufeff" + csvFile(t, 1, func(int) []string {
			return ordinaryRow(testEnvironmentID, "vm-bom", "1")
		})
		page, err := Parse(strings.NewReader(input), testLimits(testEnvironmentID))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256([]byte(input))
		if page.Next.FileSHA256 != hex.EncodeToString(digest[:]) {
			t.Fatalf("file sha = %q", page.Next.FileSHA256)
		}
	})

	t.Run("rejects misplaced BOM and invalid UTF-8", func(t *testing.T) {
		input := csvFile(t, 1, func(int) []string {
			row := ordinaryRow(testEnvironmentID, "vm-bom", "1")
			row[4] = "vm\ufeffname"
			return row
		})
		if _, err := Parse(strings.NewReader(input), testLimits(testEnvironmentID)); !errors.Is(err, ErrInvalidEncoding) {
			t.Fatalf("misplaced BOM error = %v", err)
		}
		invalidUTF8 := []byte(Header + "\n")
		invalidUTF8 = append(invalidUTF8, []byte(testEnvironmentID+",CSV_RFC4180_V1,vm,LINUX_VM,")...)
		invalidUTF8 = append(invalidUTF8, 0xff)
		invalidUTF8 = append(invalidUTF8, []byte(",1,false,,,,\n")...)
		if _, err := Parse(strings.NewReader(string(invalidUTF8)), testLimits(testEnvironmentID)); !errors.Is(err, ErrInvalidEncoding) {
			t.Fatalf("invalid UTF-8 error = %v", err)
		}
	})

	t.Run("enforces byte field and file limits", func(t *testing.T) {
		input := csvFile(t, 1, func(int) []string {
			row := ordinaryRow(testEnvironmentID, strings.Repeat("x", MaxFieldBytes), "1")
			row[4] = "bounded"
			return row
		})
		if _, err := Parse(strings.NewReader(input), testLimits(testEnvironmentID)); err != nil {
			t.Fatalf("512-byte field error = %v", err)
		}
		oversizeField := strings.Replace(input, strings.Repeat("x", MaxFieldBytes), strings.Repeat("x", MaxFieldBytes+1), 1)
		if _, err := Parse(strings.NewReader(oversizeField), testLimits(testEnvironmentID)); !errors.Is(err, ErrLimitExceeded) {
			t.Fatalf("513-byte field error = %v", err)
		}
		limits := testLimits(testEnvironmentID)
		limits.MaxBytes = int64(len(input) - 1)
		if _, err := Parse(strings.NewReader(input), limits); !errors.Is(err, ErrLimitExceeded) {
			t.Fatalf("file limit error = %v", err)
		}
		limits = testLimits(testEnvironmentID)
		limits.MaxRowsPerPage = MaxRowsPerPage + 1
		if _, err := Parse(strings.NewReader(input), limits); !errors.Is(err, ErrLimitExceeded) {
			t.Fatalf("page limit error = %v", err)
		}
	})

	t.Run("rejects more than 100000 rows", func(t *testing.T) {
		input := csvFile(t, MaxRows+1, func(index int) []string {
			return ordinaryRow(testEnvironmentID, fmt.Sprintf("vm-%06d", index), fmt.Sprint(index))
		})
		if _, err := Parse(strings.NewReader(input), testLimits(testEnvironmentID)); !errors.Is(err, ErrLimitExceeded) {
			t.Fatalf("row limit error = %v", err)
		}
	})

	t.Run("rejects full-file duplicate after first page", func(t *testing.T) {
		input := csvFile(t, MaxRowsPerPage+1, func(index int) []string {
			externalID := fmt.Sprintf("vm-%04d", index)
			if index == MaxRowsPerPage+1 {
				externalID = "vm-0001"
			}
			return ordinaryRow(testEnvironmentID, externalID, fmt.Sprint(index))
		})
		if _, err := Parse(strings.NewReader(input), testLimits(testEnvironmentID)); !errors.Is(err, ErrDuplicateObject) {
			t.Fatalf("duplicate error = %v", err)
		}
	})

	t.Run("rejects non-canonical object versions and unknown enums", func(t *testing.T) {
		for name, mutate := range map[string]func([]string){
			"zero version":     func(row []string) { row[5] = "0" },
			"leading zero":     func(row []string) { row[5] = "01" },
			"positive sign":    func(row []string) { row[5] = "+1" },
			"overflow":         func(row []string) { row[5] = "9223372036854775808" },
			"unknown kind":     func(row []string) { row[3] = "VIRTUAL_MACHINE" },
			"unknown deleted":  func(row []string) { row[6] = "FALSE" },
			"unknown relation": func(row []string) { row[8], row[9], row[10] = "CONNECTED_TO", testEnvironmentID, "target" },
			"invalid provider": func(row []string) { row[1] = "csv-v1" },
			"partial relation": func(row []string) { row[8] = "RUNS_ON" },
		} {
			t.Run(name, func(t *testing.T) {
				row := ordinaryRow(testEnvironmentID, "vm-enum", "1")
				mutate(row)
				input := csvRows(t, row)
				if _, err := Parse(strings.NewReader(input), testLimits(testEnvironmentID)); err == nil {
					t.Fatal("Parse unexpectedly succeeded")
				}
			})
		}
		extraHeader := strings.Replace(
			csvRows(t, ordinaryRow(testEnvironmentID, "vm-extra", "1")),
			Header,
			Header+",owner_group",
			1,
		)
		if _, err := Parse(strings.NewReader(extraHeader), testLimits(testEnvironmentID)); !errors.Is(err, ErrInvalidSchema) {
			t.Fatalf("governance column error = %v", err)
		}
	})

	t.Run("rejects unsafe controls without echoing values", func(t *testing.T) {
		for _, value := range []string{"vm\x00name", "vm\rname", "vm\nname", "client_secret=do-not-echo"} {
			row := ordinaryRow(testEnvironmentID, "vm-control", "1")
			row[4] = value
			input := csvRows(t, row)
			_, err := Parse(strings.NewReader(input), testLimits(testEnvironmentID))
			if !errors.Is(err, ErrUnsafeField) {
				t.Fatalf("unsafe field error = %v", err)
			}
			if strings.Contains(err.Error(), value) {
				t.Fatalf("error leaked rejected value: %v", err)
			}
		}
	})

	t.Run("rejects source or target outside authority and cross-environment relation without policy", func(t *testing.T) {
		sourceOutside := csvRows(t, ordinaryRow(testOtherEnvironmentID, "vm-outside", "1"))
		if _, err := Parse(strings.NewReader(sourceOutside), testLimits(testEnvironmentID)); !errors.Is(err, ErrAuthorityMismatch) {
			t.Fatalf("source authority error = %v", err)
		}
		row := ordinaryRow(testEnvironmentID, "vm-cross", "1")
		row[8], row[9], row[10] = "RUNS_ON", testOtherEnvironmentID, "host-target"
		crossEnvironment := csvRows(t, row)
		limits := testLimits(testEnvironmentID, testOtherEnvironmentID)
		if _, err := Parse(strings.NewReader(crossEnvironment), limits); !errors.Is(err, ErrInvalidRelation) {
			t.Fatalf("cross-environment relation error = %v", err)
		}
		self := ordinaryRow(testEnvironmentID, "vm-self", "1")
		self[8], self[9], self[10] = "RUNS_ON", testEnvironmentID, "vm-self"
		if _, err := Parse(strings.NewReader(csvRows(t, self)), testLimits(testEnvironmentID)); !errors.Is(err, ErrInvalidRelation) {
			t.Fatalf("self relation error = %v", err)
		}
	})

	t.Run("rejects malformed tombstones", func(t *testing.T) {
		for name, mutate := range map[string]func([]string){
			"display": func(row []string) { row[4] = "must-be-empty" },
			"relation": func(row []string) {
				row[8], row[9], row[10] = "RUNS_ON", testEnvironmentID, "target"
			},
			"missing reason": func(row []string) { row[7] = "" },
			"unknown reason": func(row []string) { row[7] = "UNREVIEWED_REASON" },
		} {
			t.Run(name, func(t *testing.T) {
				row := ordinaryRow(testEnvironmentID, "vm-deleted", "1")
				row[4], row[6], row[7] = "", "true", "PROVIDER_DELETED"
				mutate(row)
				if _, err := Parse(strings.NewReader(csvRows(t, row)), testLimits(testEnvironmentID)); !errors.Is(err, ErrInvalidTombstone) {
					t.Fatalf("tombstone error = %v", err)
				}
			})
		}
	})

	t.Run("checkpoint is safe JSON and changed input cannot resume", func(t *testing.T) {
		input := csvFile(t, MaxRowsPerPage+1, func(index int) []string {
			return ordinaryRow(testEnvironmentID, fmt.Sprintf("vm-%04d", index), fmt.Sprint(index))
		})
		first, err := Parse(strings.NewReader(input), testLimits(testEnvironmentID))
		if err != nil {
			t.Fatal(err)
		}
		wire, err := json.Marshal(first.Next)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(wire), "vm-") || strings.Contains(string(wire), Header) {
			t.Fatalf("checkpoint contains raw file data: %s", wire)
		}
		var decoded Checkpoint
		if err := json.Unmarshal(wire, &decoded); err != nil || decoded != first.Next {
			t.Fatalf("checkpoint round trip = (%#v, %v)", decoded, err)
		}
		changed := strings.Replace(input, "vm-2001", "vm-changed", 1)
		if _, err := Resume(strings.NewReader(changed), first.Next, testLimits(testEnvironmentID)); !errors.Is(err, ErrCheckpointMismatch) {
			t.Fatalf("changed file resume error = %v", err)
		}
	})
}

func assetcatalogPolicy() assetdiscovery.FactPolicy {
	return assetdiscovery.FactPolicy{
		ProviderKind:            "CSV_RFC4180_V1",
		FreshnessKind:           assetcatalog.FreshnessObjectSequence,
		EnvironmentMapping:      assetcatalog.EnvironmentMappingExplicitItem,
		AuthorityEnvironmentIDs: []string{testEnvironmentID},
		TrustedPathCodes: []string{
			"CSV_V1_DISPLAY_NAME_COLUMN",
			"CSV_V1_ENVIRONMENT_ID_COLUMN",
			"CSV_V1_EXTERNAL_ID_COLUMN",
			"CSV_V1_KIND_COLUMN",
			"CSV_V1_PROVIDER_KIND_COLUMN",
			"CSV_V1_RELATION_COLUMNS",
			"CSV_V1_TYPE_DETAILS_EMPTY",
		},
		RelationshipTypes: []assetcatalog.RelationshipType{assetcatalog.RelationshipRunsOn},
		AllowedDocumentFields: map[assetcatalog.Kind][]string{
			assetcatalog.KindLinuxVM:       {},
			assetcatalog.KindBareMetalHost: {},
		},
	}
}

func testLimits(authorityEnvironmentIDs ...string) Limits {
	return Limits{
		MaxRowsPerPage:          2000,
		MaxBytes:                32 << 20,
		AuthorityEnvironmentIDs: authorityEnvironmentIDs,
	}
}

func ordinaryRow(environmentID, externalID, objectVersion string) []string {
	return []string{
		environmentID, "CSV_RFC4180_V1", externalID, "LINUX_VM", externalID, objectVersion, "false", "",
		"", "", "",
	}
}

func csvFile(t *testing.T, rows int, row func(int) []string) string {
	t.Helper()
	var output strings.Builder
	writer := csv.NewWriter(&output)
	if err := writer.Write(strings.Split(Header, ",")); err != nil {
		t.Fatal(err)
	}
	for index := 1; index <= rows; index++ {
		if err := writer.Write(row(index)); err != nil {
			t.Fatal(err)
		}
	}
	writer.Flush()
	if err := writer.Error(); err != nil {
		t.Fatal(err)
	}
	return output.String()
}

func csvRows(t *testing.T, rows ...[]string) string {
	t.Helper()
	var output strings.Builder
	writer := csv.NewWriter(&output)
	if err := writer.Write(strings.Split(Header, ",")); err != nil {
		t.Fatal(err)
	}
	if err := writer.WriteAll(rows); err != nil {
		t.Fatal(err)
	}
	return output.String()
}

func framedDigest(fields ...string) string {
	hash := sha256.New()
	var length [4]byte
	for _, field := range fields {
		hash.Write([]byte{1})
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		hash.Write(length[:])
		hash.Write([]byte(field))
	}
	return hex.EncodeToString(hash.Sum(nil))
}
