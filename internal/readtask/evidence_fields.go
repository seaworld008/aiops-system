package readtask

import (
	"strings"
	"unicode"
)

// EvidenceFieldReserved is the single field-name contract shared by the HTTP
// ingress and connector-specific completion validators. It rejects semantic
// identity, target, credential, error-body and server-owned receipt metadata,
// including separator, camel-case, plural and Unicode skeleton variants.
func EvidenceFieldReserved(value string) bool {
	normalized := evidenceFieldSkeleton(value)
	tokens := evidenceFieldTokens(value)
	for _, token := range tokens {
		switch token {
		case "source", "connector", "operation", "tenant", "workspace", "environment", "service",
			"incident", "investigation", "task", "runner", "lease", "epoch",
			"certificate", "cert", "truncated", "target", "url", "uri", "endpoint",
			"header", "credential", "hash", "sha256":
			return true
		}
	}
	if evidenceTokensContain(tokens, "scope", "revision") ||
		evidenceTokensContain(tokens, "item", "count") ||
		evidenceTokensContain(tokens, "idempotency", "key") ||
		evidenceTokensContain(tokens, "raw", "error") ||
		evidenceTokensContain(tokens, "error", "body") {
		return true
	}
	for _, reserved := range []string{
		"source", "connector", "connectorid", "operation", "tenant", "tenantid", "workspace", "workspaceid",
		"environment", "environmentid", "service", "serviceid", "incident", "incidentid",
		"investigation", "investigationid", "task", "taskid", "runner", "runnerid",
		"lease", "leaseid", "leaseepoch", "epoch", "scoperevision",
		"certificate", "certificatesha256", "itemcount", "idempotencykey", "truncated",
		"target", "url", "uri", "endpoint", "header", "headers", "credential",
		"rawerror", "errorbody", "sourceurl", "sourceuri", "sourceendpoint", "datasource",
		"targeturl", "targeturi", "targetendpoint", "requestheader", "requestheaders",
		"connectorname", "rawerrormessage", "sources", "credentials", "targeturls",
		"scoperevisions", "rawerrors", "errorbodies", "urls", "contenthash", "requesthash",
		"receipthash", "inputhash", "tokenhash", "certificatehash", "sha256",
	} {
		if normalized == reserved {
			return true
		}
	}
	return false
}

// EvidenceFieldValueReserved handles the generic {name|key: <metadata-name>}
// carrier pattern without rejecting ordinary human-facing name/key values.
func EvidenceFieldValueReserved(fieldName, value string) bool {
	normalized := evidenceFieldSkeleton(fieldName)
	return (normalized == "name" || normalized == "key") && EvidenceFieldReserved(value)
}

func evidenceFieldTokens(value string) []string {
	runes := []rune(value)
	tokens := make([]string, 0, 4)
	current := make([]rune, 0, len(runes))
	flush := func() {
		if len(current) == 0 {
			return
		}
		tokens = append(tokens, string(current))
		current = current[:0]
	}
	for index, character := range runes {
		if !unicode.IsLetter(character) && !unicode.IsDigit(character) {
			flush()
			continue
		}
		if len(current) != 0 && unicode.IsUpper(character) {
			previous := runes[index-1]
			nextIsLower := index+1 < len(runes) && unicode.IsLower(runes[index+1])
			acronymPlural := nextIsLower && runes[index+1] == 's' &&
				(index+2 == len(runes) || !unicode.IsLetter(runes[index+2]) && !unicode.IsDigit(runes[index+2]))
			if unicode.IsLower(previous) || unicode.IsDigit(previous) || unicode.IsUpper(previous) && nextIsLower && !acronymPlural {
				flush()
			}
		}
		current = append(current, unicode.ToLower(character))
	}
	flush()
	for index := range tokens {
		tokens[index] = evidenceSingularToken(tokens[index])
	}
	return tokens
}

func evidenceSingularToken(token string) string {
	switch token {
	case "sources":
		return "source"
	case "connectors":
		return "connector"
	case "operations":
		return "operation"
	case "tenants":
		return "tenant"
	case "workspaces":
		return "workspace"
	case "environments":
		return "environment"
	case "services":
		return "service"
	case "incidents":
		return "incident"
	case "investigations":
		return "investigation"
	case "tasks":
		return "task"
	case "runners":
		return "runner"
	case "leases":
		return "lease"
	case "epochs":
		return "epoch"
	case "certificates":
		return "certificate"
	case "certs":
		return "cert"
	case "targets":
		return "target"
	case "urls":
		return "url"
	case "uris":
		return "uri"
	case "endpoints":
		return "endpoint"
	case "headers":
		return "header"
	case "credentials":
		return "credential"
	case "hashes":
		return "hash"
	case "scopes":
		return "scope"
	case "revisions":
		return "revision"
	case "items":
		return "item"
	case "counts":
		return "count"
	case "keys":
		return "key"
	case "errors":
		return "error"
	case "bodies":
		return "body"
	default:
		return token
	}
}

func evidenceTokensContain(tokens []string, required ...string) bool {
	for _, want := range required {
		found := false
		for _, token := range tokens {
			if token == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func evidenceFieldSkeleton(value string) string {
	var normalized strings.Builder
	for _, character := range value {
		if unicode.IsLetter(character) || unicode.IsDigit(character) {
			normalized.WriteRune(unicode.ToLower(character))
		}
	}
	return normalized.String()
}
