package externalcmdb

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/seaworld008/aiops-system/internal/assetcatalog"
	"github.com/seaworld008/aiops-system/internal/discoverysource"
)

const (
	maxCatalogPageSize = 500
	maxClockSkew       = 60 * time.Second
)

var (
	safeProtocolIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,127}$`)
	canonicalUUIDPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	stableReasonPattern    = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
	sensitiveValuePattern  = regexp.MustCompile(`(?i)(?:\bAKIA[0-9A-Z]{16}\b|\bgh[pousr]_[A-Za-z0-9]{20,}\b|\bsk-[A-Za-z0-9_-]{16,}\b|eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})`)
	sensitiveNamePattern   = regexp.MustCompile(`(?i)(?:secret|token|password|passwd|credential|private[_-]?key|client[_-]?secret|authorization|cookie)`)
)

type capabilityValidation struct {
	Passed bool
	Code   string
}

func validateCapabilities(capabilities catalogCapabilities, expectedAuthority string, now time.Time) capabilityValidation {
	if capabilities.ProtocolVersion != catalogProtocolVersion {
		return capabilityRejected("PROTOCOL_MISMATCH")
	}
	if capabilities.AuthorityID != expectedAuthority {
		return capabilityRejected("AUTHORITY_MISMATCH")
	}
	if !slices.Equal(capabilities.Permissions, []string{"assets.read", "relations.read"}) {
		return capabilityRejected("PERMISSION_SCOPE_MISMATCH")
	}
	if !validCapabilitySchema(capabilities, expectedAuthority) {
		return capabilityRejected("CAPABILITY_SCHEMA_MISMATCH")
	}
	if capabilities.ServerTime.Before(now.Add(-maxClockSkew)) || capabilities.ServerTime.After(now.Add(maxClockSkew)) {
		return capabilityRejected("CLOCK_SKEW")
	}
	return capabilityValidation{Passed: true, Code: "CAPABILITIES_ACCEPTED"}
}

func validCapabilitySchema(capabilities catalogCapabilities, expectedAuthority string) bool {
	return safeIdentifier(expectedAuthority) &&
		safeIdentifier(capabilities.AuthorityID) &&
		safeIdentifier(capabilities.SnapshotEpoch) &&
		capabilities.MaxPageSize == maxCatalogPageSize &&
		capabilities.SupportsDelta &&
		capabilities.SupportsTombstone &&
		!capabilities.ServerTime.IsZero() &&
		!containsSensitiveText(capabilities.ProtocolVersion) &&
		!containsSensitiveText(capabilities.AuthorityID) &&
		!containsSensitiveText(capabilities.SnapshotEpoch)
}

func capabilityRejected(code string) capabilityValidation {
	return capabilityValidation{Code: code}
}

type assetProbeValidation struct {
	Passed    bool
	Kind      discoverysource.ValidationCheckKind
	CheckCode string
	ProofCode string
}

func validateAssetProbe(
	page catalogPage[catalogAsset],
	capabilities catalogCapabilities,
	environmentID string,
	limits discoverysource.Limits,
) assetProbeValidation {
	if page.SnapshotEpoch != capabilities.SnapshotEpoch || !safeIdentifier(page.SnapshotEpoch) ||
		!canonicalUUIDPattern.MatchString(environmentID) ||
		page.Items == nil ||
		page.CompleteSnapshot && !page.FinalPage {
		return rejectedProbe(discoverysource.ValidationCheckSchema, "SCHEMA_REJECTED")
	}
	if len(page.Items) > maxCatalogPageSize || int64(len(page.Items)) > limits.MaxPageItems {
		return rejectedProbe(discoverysource.ValidationCheckBudget, "BUDGET_REJECTED")
	}
	for _, item := range page.Items {
		code := validateCatalogAssetSchema(item, limits.MaxDocumentBytes)
		switch code {
		case "":
		case "DLP_REJECTED":
			return rejectedProbe(discoverysource.ValidationCheckDLP, "DLP_REJECTED")
		default:
			return rejectedProbe(discoverysource.ValidationCheckSchema, "SCHEMA_REJECTED")
		}
		normalized, err := normalizeAsset(environmentID, item)
		if err != nil {
			return rejectedProbe(discoverysource.ValidationCheckSchema, "SCHEMA_REJECTED")
		}
		if int64(len(normalized.Document)) > limits.MaxDocumentBytes {
			return rejectedProbe(discoverysource.ValidationCheckBudget, "BUDGET_REJECTED")
		}
	}
	return assetProbeValidation{Passed: true}
}

func validateCatalogAssetSchema(asset catalogAsset, maxDocumentBytes int64) string {
	if !safeText(asset.ExternalID, 1, 512) || asset.ObjectRevision <= 0 || asset.UpdatedAt.IsZero() ||
		asset.Attributes == nil ||
		len(asset.Attributes) > 64 || maxDocumentBytes <= 0 {
		return "SCHEMA_REJECTED"
	}
	if containsSensitiveText(asset.ExternalID) || containsSensitiveText(asset.DisplayName) ||
		containsSensitiveText(asset.TypeCode) || containsSensitiveText(asset.TombstoneReason) {
		return "DLP_REJECTED"
	}
	if unsafeExecutableText(asset.ExternalID) || unsafeExecutableText(asset.DisplayName) ||
		unsafeExecutableText(asset.TypeCode) || unsafeExecutableText(asset.TombstoneReason) {
		return "DLP_REJECTED"
	}
	if asset.Deleted {
		if !safeText(asset.TypeCode, 0, 64) ||
			!safeText(asset.DisplayName, 0, 256) ||
			!stableReasonPattern.MatchString(asset.TombstoneReason) {
			return "SCHEMA_REJECTED"
		}
		if asset.TypeCode != "" {
			if _, allowed := catalogAssetKind(asset.TypeCode); !allowed {
				return "SCHEMA_REJECTED"
			}
		}
	} else if asset.TombstoneReason != "" || !safeText(asset.TypeCode, 1, 64) ||
		!safeText(asset.DisplayName, 1, 256) {
		return "SCHEMA_REJECTED"
	}
	documentBytes := int64(2)
	for key, value := range asset.Attributes {
		if !safeText(key, 1, 64) || !safeText(value, 0, 1_024) || !allowedAttributeCode(key) {
			return "SCHEMA_REJECTED"
		}
		if sensitiveNamePattern.MatchString(key) || containsSensitiveText(value) {
			return "DLP_REJECTED"
		}
		if unsafeExecutableText(key) || unsafeExecutableText(value) {
			return "DLP_REJECTED"
		}
		documentBytes += int64(len(key) + len(value) + 6)
		if documentBytes > maxDocumentBytes {
			return "SCHEMA_REJECTED"
		}
	}
	return ""
}

func rejectedProbe(kind discoverysource.ValidationCheckKind, code string) assetProbeValidation {
	return assetProbeValidation{
		Kind:      kind,
		CheckCode: code,
		ProofCode: "VALIDATION_REJECTED",
	}
}

func proofForCapabilityFailure(code string) discoverysource.ValidationProof {
	switch code {
	case "AUTHORITY_MISMATCH", "CLOCK_SKEW":
		return validationFailure(
			discoverysource.ValidationCheckIdentity,
			"IDENTITY_REJECTED",
			"AUTHORITY_REJECTED",
		)
	case "PROTOCOL_MISMATCH":
		return validationFailure(
			discoverysource.ValidationCheckIdentity,
			"IDENTITY_INCOMPATIBLE",
			"AUTHORITY_INCOMPATIBLE",
		)
	case "PERMISSION_SCOPE_MISMATCH":
		return validationFailure(
			discoverysource.ValidationCheckFixedProbe,
			"FIXED_PROBE_REJECTED",
			"VALIDATION_REJECTED",
		)
	default:
		return validationFailure(
			discoverysource.ValidationCheckSchema,
			"SCHEMA_REJECTED",
			"VALIDATION_REJECTED",
		)
	}
}

func validationFailure(
	kind discoverysource.ValidationCheckKind,
	checkCode string,
	proofCode string,
) discoverysource.ValidationProof {
	return discoverysource.ValidationProof{
		Outcome: assetcatalog.ValidationOutcomeFailed,
		Code:    proofCode,
		Checks: []discoverysource.ValidationCheck{{
			Kind:   kind,
			Code:   checkCode,
			Passed: false,
		}},
	}
}

func successfulValidationProof(
	capabilities catalogCapabilities,
	probeItems int,
) discoverysource.ValidationProof {
	capabilitySHA := digestFramedTuple(
		"cmdb-capabilities-proof.v1",
		capabilities.ProtocolVersion,
		capabilities.AuthorityID,
		capabilities.SnapshotEpoch,
		strconv.Itoa(capabilities.MaxPageSize),
		strconv.FormatBool(capabilities.SupportsDelta),
		strconv.FormatBool(capabilities.SupportsTombstone),
		capabilities.ServerTime.UTC().Format(time.RFC3339Nano),
		strings.Join(capabilities.Permissions, "\x00"),
	)
	checks := []discoverysource.ValidationCheck{
		{
			Kind:         discoverysource.ValidationCheckIdentity,
			Code:         "IDENTITY_VERIFIED",
			Passed:       true,
			Count:        1,
			DigestSHA256: capabilitySHA,
		},
		{
			Kind:   discoverysource.ValidationCheckTrustOrSignature,
			Code:   "TRUST_OR_SIGNATURE_VERIFIED",
			Passed: true,
			Count:  1,
		},
		{
			Kind:   discoverysource.ValidationCheckNetwork,
			Code:   "NETWORK_VERIFIED",
			Passed: true,
			Count:  2,
		},
		{
			Kind:   discoverysource.ValidationCheckCredentialOpen,
			Code:   "CREDENTIAL_OPEN_VERIFIED",
			Passed: true,
			Count:  1,
		},
		{
			Kind:         discoverysource.ValidationCheckFixedProbe,
			Code:         "FIXED_PROBE_VERIFIED",
			Passed:       true,
			Count:        int64(probeItems),
			DigestSHA256: digestFramedTuple("cmdb-asset-probe.v1", capabilities.SnapshotEpoch, strconv.Itoa(probeItems)),
		},
		{
			Kind:   discoverysource.ValidationCheckSchema,
			Code:   "SCHEMA_VERIFIED",
			Passed: true,
			Count:  int64(probeItems + 1),
		},
		{
			Kind:   discoverysource.ValidationCheckDLP,
			Code:   "DLP_VERIFIED",
			Passed: true,
			Count:  int64(probeItems + 1),
		},
		{
			Kind:   discoverysource.ValidationCheckBudget,
			Code:   "BUDGET_VERIFIED",
			Passed: true,
			Count:  int64(probeItems),
		},
	}
	return discoverysource.ValidationProof{
		Outcome: assetcatalog.ValidationOutcomeSucceeded,
		Code:    "VALIDATION_SUCCEEDED",
		Checks:  checks,
	}
}

func digestFramedTuple(fields ...string) string {
	hasher := sha256.New()
	var length [4]byte
	for _, field := range fields {
		_, _ = hasher.Write([]byte{1})
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		_, _ = hasher.Write(length[:])
		_, _ = hasher.Write([]byte(field))
	}
	return hex.EncodeToString(hasher.Sum(nil))
}

func safeIdentifier(value string) bool {
	return safeProtocolIdentifier.MatchString(value) && !containsSensitiveText(value)
}

func safeText(value string, minimum int, maximum int) bool {
	if len(value) < minimum || len(value) > maximum || !utf8.ValidString(value) {
		return false
	}
	for _, character := range value {
		if unicode.IsControl(character) || character == '\u2028' || character == '\u2029' {
			return false
		}
	}
	return true
}

func containsSensitiveText(value string) bool {
	return sensitiveValuePattern.MatchString(value)
}

func unsafeExecutableText(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	switch trimmed[0] {
	case '=', '+', '-', '@':
		return true
	}
	lower := strings.ToLower(trimmed)
	for _, marker := range []string{
		"<script", "</script", "<html", "</html", "javascript:", "data:text/html",
		"onerror=", "onload=",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	if strings.Contains(lower, "<") && strings.Contains(lower, ">") {
		return true
	}
	return false
}
