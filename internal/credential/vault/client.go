package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime"
	"net"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/seaworld008/aiops-system/internal/credential"
)

const (
	maxSuccessBodyBytes = 64 << 10
	maxErrorBodyBytes   = 8 << 10
	maxRequestBodyBytes = 8 << 10
	maxResponseHeaders  = 32 << 10
	maxJSONDepth        = 32
	connectTimeout      = 5 * time.Second
	tlsHandshakeTimeout = 5 * time.Second
	responseTimeout     = 10 * time.Second
	totalRequestTimeout = 20 * time.Second
	minimumManagerTTL   = credential.MaxCredentialTTL + credential.PreparedRecoveryGrace
)

var ErrInvalidClient = errors.New("invalid Vault profile client")

type ErrorClass string

const (
	ErrorProtocol           ErrorClass = "PROTOCOL"
	ErrorAuthentication     ErrorClass = "AUTHENTICATION"
	ErrorPermission         ErrorClass = "PERMISSION"
	ErrorRateLimited        ErrorClass = "RATE_LIMITED"
	ErrorUnavailable        ErrorClass = "UNAVAILABLE"
	ErrorTimeout            ErrorClass = "TIMEOUT"
	ErrorInvalidReference   ErrorClass = "INVALID_REFERENCE"
	ErrorUnexpectedResponse ErrorClass = "UNEXPECTED_RESPONSE"
)

type ClientError struct {
	Operation  string
	Class      ErrorClass
	StatusCode int
	Ambiguous  bool
	cause      error
}

func (failure *ClientError) Error() string {
	if failure == nil {
		return "Vault operation failed"
	}
	if failure.StatusCode > 0 {
		return fmt.Sprintf("Vault %s failed: class=%s status=%d ambiguous=%t",
			failure.Operation, failure.Class, failure.StatusCode, failure.Ambiguous)
	}
	return fmt.Sprintf("Vault %s failed: class=%s ambiguous=%t", failure.Operation, failure.Class, failure.Ambiguous)
}

func (failure *ClientError) Unwrap() error {
	if failure == nil {
		return nil
	}
	return failure.cause
}

func (failure *ClientError) MarshalJSON() ([]byte, error) {
	if failure == nil {
		return []byte(`{"redacted":true}`), nil
	}
	return json.Marshal(struct {
		Operation  string     `json:"operation"`
		Class      ErrorClass `json:"class"`
		StatusCode int        `json:"status_code,omitempty"`
		Ambiguous  bool       `json:"ambiguous"`
		Redacted   bool       `json:"redacted"`
	}{failure.Operation, failure.Class, failure.StatusCode, failure.Ambiguous, true})
}

type TokenSource interface {
	SourceID() string
	Token(context.Context) (credential.SensitiveValue, error)
}

type clientCore struct {
	profile *Profile
}

type IssuerClient struct {
	clientCore
	manager TokenSource
}

type RevocationClient struct {
	clientCore
	revoker TokenSource
}

var _ credential.DurableIssuer = (*IssuerClient)(nil)

func NewIssuerClient(profile *Profile, manager TokenSource) (*IssuerClient, error) {
	if !validClientInputs(profile, manager) {
		return nil, ErrInvalidClient
	}
	return &IssuerClient{clientCore: clientCore{profile: profile}, manager: manager}, nil
}

func NewRevocationClient(profile *Profile, revoker TokenSource) (*RevocationClient, error) {
	if !validClientInputs(profile, revoker) {
		return nil, ErrInvalidClient
	}
	return &RevocationClient{clientCore: clientCore{profile: profile}, revoker: revoker}, nil
}

func validClientInputs(profile *Profile, source TokenSource) bool {
	return profile != nil && profile.rootCAs != nil && !nilTokenSource(source) && validProfileID(source.SourceID())
}

func (client *IssuerClient) String() string {
	if client == nil || client.profile == nil {
		return "VaultIssuerClient{Invalid:true Security:[REDACTED]}"
	}
	return fmt.Sprintf("VaultIssuerClient{IssuerID:%q Revision:%q Security:[REDACTED]}",
		client.profile.issuerID, client.profile.revision)
}

func (client *IssuerClient) GoString() string { return client.String() }

func (client *IssuerClient) MarshalJSON() ([]byte, error) {
	if client == nil || client.profile == nil {
		return []byte(`{"redacted":true,"invalid":true}`), nil
	}
	return json.Marshal(struct {
		IssuerID string `json:"issuer_id"`
		Revision string `json:"revision"`
		Redacted bool   `json:"redacted"`
	}{client.profile.issuerID, client.profile.revision, true})
}

func (client *RevocationClient) String() string {
	if client == nil || client.profile == nil {
		return "VaultRevocationClient{Invalid:true Security:[REDACTED]}"
	}
	return fmt.Sprintf("VaultRevocationClient{IssuerID:%q Revision:%q Security:[REDACTED]}",
		client.profile.issuerID, client.profile.revision)
}

func (client *RevocationClient) GoString() string { return client.String() }

func (client *RevocationClient) MarshalJSON() ([]byte, error) {
	if client == nil || client.profile == nil {
		return []byte(`{"redacted":true,"invalid":true}`), nil
	}
	return json.Marshal(struct {
		IssuerID string `json:"issuer_id"`
		Revision string `json:"revision"`
		Redacted bool   `json:"redacted"`
	}{client.profile.issuerID, client.profile.revision, true})
}

func (client *IssuerClient) ValidateManager(ctx context.Context) error {
	if client == nil || client.profile == nil || ctx == nil {
		return ErrInvalidClient
	}
	managerToken, err := client.manager.Token(ctx)
	if err != nil {
		managerToken.Destroy()
		return sourceFailure(ctx, "manager_lookup_self")
	}
	defer managerToken.Destroy()
	tokenBytes := managerToken.Bytes()
	defer clear(tokenBytes)
	if !validBearer(tokenBytes) {
		return &ClientError{Operation: "manager_lookup_self", Class: ErrorAuthentication}
	}
	body, err := client.request(ctx, requestSpec{
		operation: "manager_lookup_self", method: http.MethodGet,
		path: "/v1/auth/token/lookup-self", token: tokenBytes, expectedStatus: http.StatusOK,
	})
	if err != nil {
		return err
	}
	defer clear(body)
	var response vaultEnvelope
	responseDecodeErr := decodeStrictJSON(body, &response)
	defer response.destroy()
	if responseDecodeErr != nil || !requiredObjectFields(body, envelopeRequiredFields) || !validEnvelope(response, "token", true) {
		return &ClientError{Operation: "manager_lookup_self", Class: ErrorProtocol}
	}
	var data tokenLookupData
	decodeErr := decodeStrictJSON(response.Data, &data)
	defer data.destroy()
	if decodeErr != nil ||
		!requiredObjectFields(response.Data, tokenLookupRequiredFields) ||
		!client.validManagerLookup(data, tokenBytes) {
		return &ClientError{Operation: "manager_lookup_self", Class: ErrorProtocol}
	}
	return nil
}

func (client *IssuerClient) InspectChild(
	ctx context.Context,
	accessor *credential.SensitiveReference,
	request credential.DurableChildInspectionRequest,
) error {
	if client == nil || client.profile == nil || ctx == nil || accessor == nil ||
		!validChildInspectionRequest(client.profile, request) {
		return ErrInvalidClient
	}
	accessorBytes := accessor.Bytes()
	defer clear(accessorBytes)
	if !validBearer(accessorBytes) {
		return &ClientError{Operation: "inspect_child", Class: ErrorInvalidReference}
	}
	managerToken, err := client.manager.Token(ctx)
	if err != nil {
		managerToken.Destroy()
		return sourceFailure(ctx, "inspect_child")
	}
	defer managerToken.Destroy()
	tokenBytes := managerToken.Bytes()
	defer clear(tokenBytes)
	if !validBearer(tokenBytes) {
		return &ClientError{Operation: "inspect_child", Class: ErrorAuthentication}
	}
	requestBody := make([]byte, 0, len(accessorBytes)+15)
	requestBody = append(requestBody, `{"accessor":"`...)
	requestBody = append(requestBody, accessorBytes...)
	requestBody = append(requestBody, `"}`...)
	defer clear(requestBody)
	body, err := client.request(ctx, requestSpec{
		operation: "inspect_child", method: http.MethodPost, path: "/v1/auth/token/lookup-accessor",
		token: tokenBytes, body: requestBody, expectedStatus: http.StatusOK,
	})
	if err != nil {
		return err
	}
	defer clear(body)
	var response vaultEnvelope
	responseDecodeErr := decodeStrictJSON(body, &response)
	defer response.destroy()
	if responseDecodeErr != nil || !requiredObjectFields(body, envelopeRequiredFields) ||
		!validEnvelope(response, "token", true) {
		return &ClientError{Operation: "inspect_child", Class: ErrorProtocol}
	}
	var data tokenLookupData
	decodeErr := decodeStrictJSON(response.Data, &data)
	defer data.destroy()
	if decodeErr != nil || !requiredObjectFields(response.Data, tokenLookupRequiredFields) ||
		!client.validChildLookup(data, accessorBytes, request) {
		return &ClientError{Operation: "inspect_child", Class: ErrorProtocol}
	}
	return nil
}

func (client *IssuerClient) IssueDynamic(
	ctx context.Context,
	childToken credential.SensitiveValue,
	request credential.DurableDynamicIssueRequest,
) (credential.DurableDynamicSecret, error) {
	if client == nil || client.profile == nil || ctx == nil || !validDynamicIssueRequest(client.profile, request) {
		return credential.DurableDynamicSecret{}, ErrInvalidClient
	}
	tokenBytes := childToken.Bytes()
	defer clear(tokenBytes)
	if !validBearer(tokenBytes) {
		return credential.DurableDynamicSecret{}, &ClientError{Operation: "issue_dynamic", Class: ErrorAuthentication}
	}
	dispatchedAt := time.Now()
	body, err := client.request(ctx, requestSpec{
		operation: "issue_dynamic", method: http.MethodGet, path: "/v1/" + client.profile.dynamicPath,
		token: tokenBytes, expectedStatus: http.StatusOK, ambiguous: true,
	})
	if err != nil {
		return credential.DurableDynamicSecret{}, err
	}
	defer clear(body)
	responseObservedAt := time.Now()
	var response vaultEnvelope
	responseDecodeErr := decodeStrictJSON(body, &response)
	defer response.destroy()
	expiresAt, expiryValid := conservativeLeaseExpiry(
		dispatchedAt,
		responseObservedAt,
		response.LeaseDuration,
		request.CredentialExpiresAt,
	)
	if responseDecodeErr != nil || !requiredObjectFields(body, envelopeRequiredFields) ||
		!validDynamicEnvelope(response, client.profile.mountType) || !expiryValid ||
		!client.validSecretData(response.Data) {
		return credential.DurableDynamicSecret{}, &ClientError{Operation: "issue_dynamic", Class: ErrorProtocol, Ambiguous: true}
	}
	secret, err := credential.NewSensitiveValue(response.Data)
	if err != nil {
		return credential.DurableDynamicSecret{}, &ClientError{Operation: "issue_dynamic", Class: ErrorProtocol, Ambiguous: true}
	}
	return credential.DurableDynamicSecret{Secret: secret, ExpiresAt: expiresAt}, nil
}

func (client *RevocationClient) RevokeAccessor(ctx context.Context, accessor *credential.SensitiveReference) error {
	if client == nil || client.profile == nil || ctx == nil || accessor == nil {
		return ErrInvalidClient
	}
	accessorBytes := accessor.Bytes()
	defer clear(accessorBytes)
	if !validBearer(accessorBytes) {
		return &ClientError{Operation: "revoke_accessor", Class: ErrorInvalidReference}
	}
	revokerToken, err := client.revoker.Token(ctx)
	if err != nil {
		revokerToken.Destroy()
		return sourceFailure(ctx, "revoke_accessor")
	}
	defer revokerToken.Destroy()
	tokenBytes := revokerToken.Bytes()
	defer clear(tokenBytes)
	if !validBearer(tokenBytes) {
		return &ClientError{Operation: "revoke_accessor", Class: ErrorAuthentication}
	}
	requestBody := accessorJSONBody(accessorBytes)
	defer clear(requestBody)
	body, err := client.request(ctx, requestSpec{
		operation: "revoke_accessor", method: http.MethodPost, path: "/v1/auth/token/revoke-accessor",
		token: tokenBytes, body: requestBody, expectedStatus: http.StatusNoContent,
		alternateStatus: http.StatusOK, allowEmptySuccess: true, ambiguous: true,
	})
	if err != nil {
		return err
	}
	defer clear(body)
	if len(body) == 0 {
		return nil
	}
	var response vaultEnvelope
	responseDecodeErr := decodeStrictJSON(body, &response)
	defer response.destroy()
	if responseDecodeErr != nil || !requiredObjectFields(body, envelopeRequiredFields) || !validRevokeEnvelope(response) {
		return &ClientError{Operation: "revoke_accessor", Class: ErrorProtocol, Ambiguous: true}
	}
	return nil
}

func accessorJSONBody(accessor []byte) []byte {
	body := make([]byte, 0, len(accessor)+15)
	body = append(body, `{"accessor":"`...)
	body = append(body, accessor...)
	body = append(body, `"}`...)
	return body
}

func (client *IssuerClient) CreateChild(
	ctx context.Context,
	request credential.DurableChildCreateRequest,
) (credential.DurableChild, error) {
	if client == nil || client.profile == nil || ctx == nil || !validChildCreateRequest(client.profile, request) {
		return credential.DurableChild{}, ErrInvalidClient
	}
	managerToken, err := client.manager.Token(ctx)
	if err != nil {
		managerToken.Destroy()
		return credential.DurableChild{}, sourceFailure(ctx, "create_child")
	}
	defer managerToken.Destroy()
	tokenBytes := managerToken.Bytes()
	defer clear(tokenBytes)
	if !validBearer(tokenBytes) {
		return credential.DurableChild{}, &ClientError{Operation: "create_child", Class: ErrorAuthentication}
	}
	ttl := fmt.Sprintf("%ds", int64(request.TTL/time.Second))
	requestBody, err := json.Marshal(childCreateBody{
		Policies: []string{client.profile.childPolicy}, TTL: ttl, ExplicitMaxTTL: ttl,
		NoDefaultPolicy: true, DisplayName: "aiops-job", NumUses: 2,
		Renewable: false, Type: "service", Meta: cloneStringMap(client.profile.metadata),
	})
	if err != nil || len(requestBody) > maxRequestBodyBytes {
		clear(requestBody)
		return credential.DurableChild{}, &ClientError{Operation: "create_child", Class: ErrorProtocol}
	}
	defer clear(requestBody)
	dispatchedAt := time.Now()
	body, err := client.request(ctx, requestSpec{
		operation: "create_child", method: http.MethodPost,
		path:  "/v1/auth/token/create/" + client.profile.tokenRole,
		token: tokenBytes, body: requestBody, expectedStatus: http.StatusOK, ambiguous: true,
	})
	if err != nil {
		return credential.DurableChild{}, err
	}
	defer clear(body)
	responseObservedAt := time.Now()
	var response vaultEnvelope
	responseDecodeErr := decodeStrictJSON(body, &response)
	defer response.destroy()
	if responseDecodeErr != nil || !requiredObjectFields(body, envelopeRequiredFields) ||
		!validCreateEnvelope(response, request.TTL) || !isJSONObject(response.Auth) {
		return childWithSalvagedAccessor(body), ambiguousChildCreateFailure()
	}
	var auth childAuthResponse
	authDecodeErr := decodeStrictJSON(response.Auth, &auth)
	if authDecodeErr != nil {
		auth.destroy()
		return childWithSalvagedAccessor(body), ambiguousChildCreateFailure()
	}
	defer auth.destroy()
	expiresAt, expiryValid := conservativeLeaseExpiry(
		dispatchedAt,
		responseObservedAt,
		auth.LeaseDuration,
		request.CredentialExpiresAt,
	)
	if !requiredObjectFields(response.Auth, childAuthRequiredFields) || !client.validChildAuth(auth, request) || !expiryValid {
		return childWithSalvagedAccessor(body), ambiguousChildCreateFailure()
	}
	accessor, err := credential.NewSensitiveReference(auth.Accessor)
	if err != nil {
		return credential.DurableChild{}, ambiguousChildCreateFailure()
	}
	child := credential.DurableChild{Accessor: accessor}
	childToken, err := credential.NewSensitiveValue(auth.ClientToken)
	if err != nil {
		return child, ambiguousChildCreateFailure()
	}
	child.Token = childToken
	child.ExpiresAt = expiresAt
	return child, nil
}

func ambiguousChildCreateFailure() error {
	return &ClientError{Operation: "create_child", Class: ErrorProtocol, Ambiguous: true}
}

func childWithSalvagedAccessor(body []byte) credential.DurableChild {
	if len(body) == 0 || len(body) > maxSuccessBodyBytes || rejectDuplicateJSONKeys(body, maxJSONDepth) != nil {
		return credential.DurableChild{}
	}
	authRaw, ok := exactJSONObjectField(body, []byte("auth"))
	if !ok || !isJSONObject(authRaw) {
		clear(authRaw)
		return credential.DurableChild{}
	}
	defer clear(authRaw)
	accessorRaw, ok := exactJSONObjectField(authRaw, []byte("accessor"))
	if !ok {
		clear(accessorRaw)
		return credential.DurableChild{}
	}
	defer clear(accessorRaw)
	var accessorValue sensitiveASCII
	if err := json.Unmarshal(accessorRaw, &accessorValue); err != nil {
		accessorValue.destroy()
		return credential.DurableChild{}
	}
	defer accessorValue.destroy()
	accessor, err := credential.NewSensitiveReference(accessorValue)
	if err != nil {
		return credential.DurableChild{}
	}
	return credential.DurableChild{Accessor: accessor}
}

type childCreateBody struct {
	Policies        []string          `json:"policies"`
	TTL             string            `json:"ttl"`
	ExplicitMaxTTL  string            `json:"explicit_max_ttl"`
	NoDefaultPolicy bool              `json:"no_default_policy"`
	DisplayName     string            `json:"display_name"`
	NumUses         int               `json:"num_uses"`
	Renewable       bool              `json:"renewable"`
	Type            string            `json:"type"`
	Meta            map[string]string `json:"meta"`
}

type sensitiveASCII []byte

func (value *sensitiveASCII) UnmarshalJSON(encoded []byte) error {
	if value == nil || len(encoded) < 2 || encoded[0] != '"' || encoded[len(encoded)-1] != '"' {
		return errors.New("invalid sensitive JSON text")
	}
	plaintext := encoded[1 : len(encoded)-1]
	if (len(plaintext) > 0 && !validBearer(plaintext)) || bytes.ContainsRune(plaintext, '\\') || bytes.ContainsRune(plaintext, '"') {
		return errors.New("invalid sensitive JSON text")
	}
	*value = append((*value)[:0], plaintext...)
	return nil
}

func (value *sensitiveASCII) destroy() {
	if value == nil {
		return
	}
	clear(*value)
	*value = nil
}

type childAuthResponse struct {
	ClientToken      sensitiveASCII    `json:"client_token"`
	Accessor         sensitiveASCII    `json:"accessor"`
	Policies         []string          `json:"policies"`
	TokenPolicies    []string          `json:"token_policies"`
	IdentityPolicies []string          `json:"identity_policies,omitempty"`
	Metadata         map[string]string `json:"metadata"`
	LeaseDuration    int64             `json:"lease_duration"`
	Renewable        bool              `json:"renewable"`
	EntityID         string            `json:"entity_id"`
	TokenType        string            `json:"token_type"`
	Orphan           bool              `json:"orphan"`
	MFARequirement   json.RawMessage   `json:"mfa_requirement"`
	NumUses          int64             `json:"num_uses"`
}

func (response *childAuthResponse) destroy() {
	if response == nil {
		return
	}
	response.ClientToken.destroy()
	response.Accessor.destroy()
}

var (
	envelopeRequiredFields = []string{
		"request_id", "lease_id", "renewable", "lease_duration", "data", "wrap_info", "warnings", "auth", "mount_type",
	}
	childAuthRequiredFields = []string{
		"client_token", "accessor", "policies", "token_policies", "metadata", "lease_duration",
		"renewable", "entity_id", "token_type", "orphan", "mfa_requirement", "num_uses",
	}
)

func validChildCreateRequest(profile *Profile, request credential.DurableChildCreateRequest) bool {
	return profile != nil && credential.ValidRevocationID(request.RevocationID) &&
		request.ProfileRevision == profile.revision && canonicalTime(request.DatabaseAuthorizedAt) && request.TTL >= time.Second &&
		request.TTL <= credential.MaxCredentialTTL && request.TTL%time.Second == 0 &&
		canonicalTime(request.CredentialExpiresAt) &&
		!request.DatabaseAuthorizedAt.Add(request.TTL+credential.ChildCreateExpiryReserve).After(request.CredentialExpiresAt)
}

func validCreateEnvelope(response vaultEnvelope, requestedTTL time.Duration) bool {
	// Vault 2.0.3 emits this warning whenever both the fixed token role and
	// the request set explicit_max_ttl. Requiring the exact lesser value binds
	// the response to the database-authorized per-job TTL without accepting
	// unrelated server warnings.
	expectedWarning := fmt.Sprintf(
		"Explicit max TTL specified both during creation call and in role; using the lesser value of %d seconds",
		int64(requestedTTL/time.Second),
	)
	return validOpaqueIdentifier(response.RequestID, 256) && len(response.LeaseID) == 0 && !response.Renewable &&
		response.LeaseDuration == 0 && isJSONNull(response.Data) && isJSONNull(response.WrapInfo) &&
		len(response.Warnings) == 1 && response.Warnings[0] == expectedWarning &&
		isJSONObject(response.Auth) && response.MountType == "token"
}

func (client *IssuerClient) validChildAuth(auth childAuthResponse, request credential.DurableChildCreateRequest) bool {
	return validBearer(auth.ClientToken) && validBearer(auth.Accessor) &&
		subtle.ConstantTimeCompare(auth.ClientToken, auth.Accessor) == 0 &&
		exactStringSet(auth.Policies, []string{client.profile.childPolicy}) &&
		exactStringSet(auth.TokenPolicies, []string{client.profile.childPolicy}) && len(auth.IdentityPolicies) == 0 &&
		maps.Equal(auth.Metadata, client.profile.metadata) && auth.LeaseDuration > 0 &&
		auth.LeaseDuration <= int64(request.TTL/time.Second) && !auth.Renewable && auth.EntityID == "" &&
		auth.TokenType == "service" && !auth.Orphan && isJSONNull(auth.MFARequirement) && auth.NumUses == 2
}

func validDynamicIssueRequest(profile *Profile, request credential.DurableDynamicIssueRequest) bool {
	return profile != nil && credential.ValidRevocationID(request.RevocationID) &&
		request.ProfileRevision == profile.revision && canonicalTime(request.CredentialExpiresAt) &&
		request.CredentialExpiresAt.After(time.Now().UTC())
}

func validDynamicEnvelope(response vaultEnvelope, mountType string) bool {
	return validOpaqueIdentifier(response.RequestID, 256) && validBearer(response.LeaseID) &&
		response.LeaseDuration > 0 && response.LeaseDuration <= int64(credential.MaxCredentialTTL/time.Second) &&
		isJSONObject(response.Data) && isJSONNull(response.WrapInfo) && len(response.Warnings) == 0 &&
		isJSONNull(response.Auth) && response.MountType == mountType
}

func conservativeLeaseExpiry(
	dispatchedAt time.Time,
	responseObservedAt time.Time,
	leaseDurationSeconds int64,
	databaseDeadline time.Time,
) (time.Time, bool) {
	if dispatchedAt.IsZero() || responseObservedAt.Before(dispatchedAt) || leaseDurationSeconds <= 0 ||
		leaseDurationSeconds > int64(credential.MaxCredentialTTL/time.Second) || !canonicalTime(databaseDeadline) {
		return time.Time{}, false
	}
	monotonicExpiry := dispatchedAt.Add(time.Duration(leaseDurationSeconds) * time.Second)
	if !monotonicExpiry.After(responseObservedAt) {
		return time.Time{}, false
	}
	expiresAt := credential.CanonicalCredentialExpiry(monotonicExpiry.UTC())
	if expiresAt.After(databaseDeadline) {
		return time.Time{}, false
	}
	return expiresAt, true
}

func validRevokeEnvelope(response vaultEnvelope) bool {
	warningsValid := len(response.Warnings) == 0 ||
		(len(response.Warnings) == 1 && response.Warnings[0] == "No token found with this accessor")
	return validOpaqueIdentifier(response.RequestID, 256) && len(response.LeaseID) == 0 && !response.Renewable &&
		response.LeaseDuration == 0 && isJSONNull(response.Data) && isJSONNull(response.WrapInfo) &&
		isJSONNull(response.Auth) && response.MountType == "token" && warningsValid
}

func (client *IssuerClient) validSecretData(data []byte) bool {
	var fields map[string]json.RawMessage
	if err := decodeStrictJSON(data, &fields); err != nil || len(fields) != len(client.profile.secretFields) {
		destroyRawMessageMap(fields)
		return false
	}
	defer destroyRawMessageMap(fields)
	for _, specification := range client.profile.secretFields {
		raw, ok := fields[specification.Name]
		if !ok {
			return false
		}
		value, err := decodeJSONStringBytes(raw, specification.MaxBytes)
		if err != nil || len(value) == 0 {
			clear(value)
			return false
		}
		clear(value)
	}
	return true
}

func decodeJSONStringBytes(encoded []byte, maximum int) ([]byte, error) {
	if maximum <= 0 || len(encoded) < 2 || encoded[0] != '"' || encoded[len(encoded)-1] != '"' {
		return nil, errors.New("invalid secret JSON field")
	}
	result := make([]byte, 0, len(encoded)-2)
	for index := 1; index < len(encoded)-1; index++ {
		character := encoded[index]
		if character != '\\' {
			if character < 0x20 {
				clear(result)
				return nil, errors.New("invalid secret JSON field")
			}
			result = append(result, character)
		} else {
			index++
			if index >= len(encoded)-1 {
				clear(result)
				return nil, errors.New("invalid secret JSON field")
			}
			switch encoded[index] {
			case '"', '\\', '/':
				result = append(result, encoded[index])
			case 'b':
				result = append(result, '\b')
			case 'f':
				result = append(result, '\f')
			case 'n':
				result = append(result, '\n')
			case 'r':
				result = append(result, '\r')
			case 't':
				result = append(result, '\t')
			case 'u':
				codepoint, next, ok := decodeJSONCodepoint(encoded, index+1)
				if !ok {
					clear(result)
					return nil, errors.New("invalid secret JSON field")
				}
				result = utf8.AppendRune(result, codepoint)
				index = next - 1
			default:
				clear(result)
				return nil, errors.New("invalid secret JSON field")
			}
		}
		if len(result) > maximum {
			clear(result)
			return nil, errors.New("secret JSON field limit exceeded")
		}
	}
	if !utf8.Valid(result) {
		clear(result)
		return nil, errors.New("invalid secret JSON field")
	}
	return result, nil
}

func decodeJSONCodepoint(encoded []byte, start int) (rune, int, bool) {
	first, ok := decodeHexQuad(encoded, start)
	if !ok {
		return 0, 0, false
	}
	next := start + 4
	if first >= 0xd800 && first <= 0xdbff {
		if next+6 > len(encoded)-1 || encoded[next] != '\\' || encoded[next+1] != 'u' {
			return 0, 0, false
		}
		second, ok := decodeHexQuad(encoded, next+2)
		if !ok || second < 0xdc00 || second > 0xdfff {
			return 0, 0, false
		}
		return utf16.DecodeRune(rune(first), rune(second)), next + 6, true
	}
	if first >= 0xdc00 && first <= 0xdfff {
		return 0, 0, false
	}
	return rune(first), next, true
}

func decodeHexQuad(encoded []byte, start int) (uint16, bool) {
	if start < 0 || start+4 > len(encoded)-1 {
		return 0, false
	}
	var value uint16
	for _, character := range encoded[start : start+4] {
		value <<= 4
		switch {
		case character >= '0' && character <= '9':
			value |= uint16(character - '0')
		case character >= 'a' && character <= 'f':
			value |= uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			value |= uint16(character-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

type requestSpec struct {
	operation         string
	method            string
	path              string
	token             []byte
	body              []byte
	expectedStatus    int
	alternateStatus   int
	allowEmptySuccess bool
	ambiguous         bool
}

func (client *clientCore) request(ctx context.Context, spec requestSpec) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, &ClientError{Operation: spec.operation, Class: ErrorTimeout, Ambiguous: false, cause: err}
	}
	if len(spec.body) > maxRequestBodyBytes || !validBearer(spec.token) {
		return nil, &ClientError{Operation: spec.operation, Class: ErrorProtocol, Ambiguous: spec.ambiguous}
	}
	endpoint := client.profile.address
	endpoint.Path = spec.path
	endpoint.RawPath, endpoint.RawQuery, endpoint.Fragment = "", "", ""

	var requestBody io.ReadCloser = http.NoBody
	if len(spec.body) > 0 {
		requestBody = io.NopCloser(bytes.NewReader(spec.body))
	}
	request, err := http.NewRequestWithContext(ctx, spec.method, endpoint.String(), requestBody)
	if err != nil {
		return nil, &ClientError{Operation: spec.operation, Class: ErrorProtocol, Ambiguous: false}
	}
	request.GetBody = nil
	request.Close = true
	request.ContentLength = int64(len(spec.body))
	request.Header.Set("Accept", "application/json")
	if len(spec.body) > 0 {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("X-Vault-Token", string(spec.token))
	if client.profile.namespace != "" {
		request.Header.Set("X-Vault-Namespace", client.profile.namespace)
	}

	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: connectTimeout, KeepAlive: -1}).DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: client.profile.rootCAs.Clone(), ServerName: client.profile.serverName},
		TLSHandshakeTimeout:    tlsHandshakeTimeout,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxConnsPerHost:        1,
		ResponseHeaderTimeout:  responseTimeout,
		MaxResponseHeaderBytes: maxResponseHeaders,
		ForceAttemptHTTP2:      false,
		TLSNextProto:           map[string]func(string, *tls.Conn) http.RoundTripper{},
		Protocols:              protocols,
	}
	defer transport.CloseIdleConnections()
	httpClient := &http.Client{
		Transport: transport,
		Timeout:   totalRequestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, requestErr := httpClient.Do(request)
	request.Header.Del("X-Vault-Token")
	if response != nil && response.Request != nil {
		response.Request.Header.Del("X-Vault-Token")
	}
	if requestErr != nil {
		return nil, requestFailure(ctx, spec.operation, spec.ambiguous)
	}
	defer response.Body.Close()
	if response.StatusCode != spec.expectedStatus && response.StatusCode != spec.alternateStatus {
		discard, _ := readBounded(response.Body, maxErrorBodyBytes)
		clear(discard)
		return nil, statusFailure(spec.operation, response.StatusCode, spec.ambiguous)
	}
	if spec.allowEmptySuccess && response.StatusCode == http.StatusNoContent {
		emptyBody, emptyErr := readBounded(response.Body, 0)
		clear(emptyBody)
		if emptyErr != nil {
			return nil, &ClientError{Operation: spec.operation, Class: ErrorProtocol, StatusCode: response.StatusCode, Ambiguous: spec.ambiguous}
		}
		return nil, nil
	}
	mediaType, _, mediaErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if mediaErr != nil || mediaType != "application/json" {
		return nil, &ClientError{Operation: spec.operation, Class: ErrorProtocol, StatusCode: response.StatusCode, Ambiguous: spec.ambiguous}
	}
	body, err := readBounded(response.Body, maxSuccessBodyBytes)
	if err != nil {
		clear(body)
		return nil, &ClientError{Operation: spec.operation, Class: ErrorProtocol, StatusCode: response.StatusCode, Ambiguous: spec.ambiguous}
	}
	return body, nil
}

type vaultEnvelope struct {
	RequestID     string          `json:"request_id"`
	LeaseID       sensitiveASCII  `json:"lease_id"`
	Renewable     bool            `json:"renewable"`
	LeaseDuration int64           `json:"lease_duration"`
	Data          json.RawMessage `json:"data"`
	WrapInfo      json.RawMessage `json:"wrap_info"`
	Warnings      []string        `json:"warnings"`
	Auth          json.RawMessage `json:"auth"`
	MountType     string          `json:"mount_type"`
}

func (response *vaultEnvelope) destroy() {
	if response == nil {
		return
	}
	response.LeaseID.destroy()
	clear(response.Data)
	clear(response.WrapInfo)
	clear(response.Auth)
	response.Data, response.WrapInfo, response.Auth = nil, nil, nil
}

type tokenLookupData struct {
	ID                        sensitiveASCII      `json:"id"`
	Accessor                  sensitiveASCII      `json:"accessor"`
	Policies                  []string            `json:"policies"`
	Path                      string              `json:"path"`
	Meta                      map[string]string   `json:"meta"`
	DisplayName               string              `json:"display_name"`
	NumUses                   int64               `json:"num_uses"`
	Orphan                    bool                `json:"orphan"`
	CreationTime              int64               `json:"creation_time"`
	CreationTTL               int64               `json:"creation_ttl"`
	ExpireTime                string              `json:"expire_time"`
	TTL                       int64               `json:"ttl"`
	ExplicitMaxTTL            int64               `json:"explicit_max_ttl"`
	EntityID                  string              `json:"entity_id"`
	Type                      string              `json:"type"`
	Role                      string              `json:"role,omitempty"`
	Period                    int64               `json:"period,omitempty"`
	BoundCIDRs                []string            `json:"bound_cidrs,omitempty"`
	NamespacePath             string              `json:"namespace_path,omitempty"`
	Renewable                 bool                `json:"renewable"`
	IssueTime                 string              `json:"issue_time"`
	LastRenewalTime           int64               `json:"last_renewal_time,omitempty"`
	LastRenewal               string              `json:"last_renewal,omitempty"`
	IdentityPolicies          []string            `json:"identity_policies,omitempty"`
	ExternalNamespacePolicies map[string][]string `json:"external_namespace_policies,omitempty"`
}

func (data *tokenLookupData) destroy() {
	if data == nil {
		return
	}
	data.ID.destroy()
	data.Accessor.destroy()
}

var tokenLookupRequiredFields = []string{
	"id", "accessor", "policies", "path", "meta", "display_name", "num_uses", "orphan",
	"creation_time", "creation_ttl", "expire_time", "ttl", "explicit_max_ttl", "entity_id",
	"type", "renewable", "issue_time",
}

func (client *IssuerClient) validManagerLookup(data tokenLookupData, token []byte) bool {
	issueTime, issueErr := time.Parse(time.RFC3339Nano, data.IssueTime)
	expireTime, expireErr := time.Parse(time.RFC3339Nano, data.ExpireTime)
	return subtle.ConstantTimeCompare(data.ID, token) == 1 &&
		validBearer(data.Accessor) && exactStringSet(data.Policies, []string{client.profile.managerPolicy}) &&
		data.Type == "service" && data.EntityID == "" && data.NumUses == 0 && data.Orphan && !data.Renewable && data.Period == 0 &&
		data.TTL >= int64(minimumManagerTTL/time.Second) && data.CreationTTL >= data.TTL && data.CreationTTL > 0 &&
		issueErr == nil && expireErr == nil && expireTime.After(issueTime) &&
		expireTime.Sub(issueTime) <= time.Duration(data.CreationTTL)*time.Second &&
		len(data.IdentityPolicies) == 0 && len(data.ExternalNamespacePolicies) == 0
}

func validChildInspectionRequest(profile *Profile, request credential.DurableChildInspectionRequest) bool {
	return profile != nil && credential.ValidRevocationID(request.RevocationID) &&
		request.ProfileRevision == profile.revision && request.ExpectedTTL >= time.Second &&
		request.ExpectedTTL <= credential.MaxCredentialTTL && request.ExpectedTTL%time.Second == 0 &&
		canonicalTime(request.CredentialExpiresAt)
}

func (client *IssuerClient) validChildLookup(
	data tokenLookupData,
	accessor []byte,
	request credential.DurableChildInspectionRequest,
) bool {
	issueTime, issueErr := time.Parse(time.RFC3339Nano, data.IssueTime)
	expireTime, expireErr := time.Parse(time.RFC3339Nano, data.ExpireTime)
	expectedTTLSeconds := int64(request.ExpectedTTL / time.Second)
	namespaceMatches := strings.Trim(data.NamespacePath, "/") == client.profile.namespace
	return len(data.ID) == 0 && subtle.ConstantTimeCompare(data.Accessor, accessor) == 1 &&
		exactStringSet(data.Policies, []string{client.profile.childPolicy}) &&
		data.Path == "auth/token/create/"+client.profile.tokenRole && maps.Equal(data.Meta, client.profile.metadata) &&
		data.DisplayName == "token-aiops-job" && data.NumUses == 2 && !data.Orphan && data.CreationTime > 0 &&
		data.CreationTTL > 0 && data.CreationTTL <= expectedTTLSeconds && data.TTL > 0 && data.TTL <= data.CreationTTL &&
		data.ExplicitMaxTTL == expectedTTLSeconds && data.CreationTTL <= data.ExplicitMaxTTL &&
		data.EntityID == "" && data.Type == "service" && data.Role == client.profile.tokenRole && data.Period == 0 &&
		len(data.BoundCIDRs) == 0 && namespaceMatches && !data.Renewable && len(data.IdentityPolicies) == 0 &&
		len(data.ExternalNamespacePolicies) == 0 && issueErr == nil && expireErr == nil && expireTime.After(issueTime) &&
		!expireTime.After(request.CredentialExpiresAt) && expireTime.Sub(issueTime) <= time.Duration(data.ExplicitMaxTTL)*time.Second
}

func validEnvelope(response vaultEnvelope, mountType string, dataExpected bool) bool {
	return validOpaqueIdentifier(response.RequestID, 256) && len(response.LeaseID) == 0 && !response.Renewable &&
		response.LeaseDuration == 0 && isJSONNull(response.WrapInfo) && len(response.Warnings) == 0 &&
		isJSONNull(response.Auth) && response.MountType == mountType &&
		((dataExpected && isJSONObject(response.Data)) || (!dataExpected && isJSONNull(response.Data)))
}

func decodeStrictJSON(data []byte, destination any) error {
	if len(data) == 0 || len(data) > maxSuccessBodyBytes || rejectDuplicateJSONKeys(data, maxJSONDepth) != nil {
		return errors.New("invalid JSON response")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return errors.New("invalid JSON response")
	}
	if err := requireJSONEOF(decoder); err != nil {
		return errors.New("invalid JSON response")
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte, maximumDepth int) error {
	if len(data) == 0 || maximumDepth < 0 {
		return errors.New("invalid JSON response")
	}
	scanner := strictJSONScanner{data: data, maximumDepth: maximumDepth}
	if err := scanner.scanValue(0); err != nil {
		return err
	}
	scanner.skipWhitespace()
	if scanner.offset != len(scanner.data) {
		return errors.New("multiple JSON values")
	}
	return nil
}

type strictJSONScanner struct {
	data         []byte
	offset       int
	maximumDepth int
}

func (scanner *strictJSONScanner) scanValue(depth int) error {
	if depth > scanner.maximumDepth {
		return errors.New("JSON nesting limit exceeded")
	}
	scanner.skipWhitespace()
	if scanner.offset >= len(scanner.data) {
		return errors.New("truncated JSON value")
	}
	switch scanner.data[scanner.offset] {
	case '{':
		return scanner.scanObject(depth)
	case '[':
		return scanner.scanArray(depth)
	case '"':
		_, err := scanner.scanString()
		return err
	case 't':
		return scanner.scanLiteral("true")
	case 'f':
		return scanner.scanLiteral("false")
	case 'n':
		return scanner.scanLiteral("null")
	default:
		return scanner.scanNumber()
	}

}

func (scanner *strictJSONScanner) scanObject(depth int) error {
	scanner.offset++
	scanner.skipWhitespace()
	if scanner.consume('}') {
		return nil
	}
	seen := make(map[[sha256.Size]byte]struct{})
	defer clear(seen)
	for {
		scanner.skipWhitespace()
		if scanner.offset >= len(scanner.data) || scanner.data[scanner.offset] != '"' {
			return errors.New("invalid JSON object key")
		}
		keyStart := scanner.offset
		keyEnd, err := scanner.scanString()
		if err != nil {
			return err
		}
		key, err := decodeJSONStringBytes(scanner.data[keyStart:keyEnd], maxSuccessBodyBytes)
		if err != nil {
			clear(key)
			return errors.New("invalid JSON object key")
		}
		keyHash := sha256.Sum256(key)
		clear(key)
		if _, duplicate := seen[keyHash]; duplicate {
			clear(keyHash[:])
			return errors.New("duplicate JSON object key")
		}
		seen[keyHash] = struct{}{}
		clear(keyHash[:])
		scanner.skipWhitespace()
		if !scanner.consume(':') {
			return errors.New("invalid JSON object")
		}
		if err := scanner.scanValue(depth + 1); err != nil {
			return err
		}
		scanner.skipWhitespace()
		if scanner.consume('}') {
			return nil
		}
		if !scanner.consume(',') {
			return errors.New("invalid JSON object")
		}
	}
}

func (scanner *strictJSONScanner) scanArray(depth int) error {
	scanner.offset++
	scanner.skipWhitespace()
	if scanner.consume(']') {
		return nil
	}
	for {
		if err := scanner.scanValue(depth + 1); err != nil {
			return err
		}
		scanner.skipWhitespace()
		if scanner.consume(']') {
			return nil
		}
		if !scanner.consume(',') {
			return errors.New("invalid JSON array")
		}
	}
}

func (scanner *strictJSONScanner) scanString() (int, error) {
	if scanner.offset >= len(scanner.data) || scanner.data[scanner.offset] != '"' {
		return 0, errors.New("invalid JSON string")
	}
	scanner.offset++
	for scanner.offset < len(scanner.data) {
		character := scanner.data[scanner.offset]
		switch {
		case character == '"':
			scanner.offset++
			return scanner.offset, nil
		case character < 0x20:
			return 0, errors.New("invalid JSON string")
		case character == '\\':
			if err := scanner.scanEscape(); err != nil {
				return 0, err
			}
		case character < utf8.RuneSelf:
			scanner.offset++
		default:
			_, size := utf8.DecodeRune(scanner.data[scanner.offset:])
			if size == 1 {
				return 0, errors.New("invalid UTF-8 in JSON string")
			}
			scanner.offset += size
		}
	}
	return 0, errors.New("truncated JSON string")
}

func (scanner *strictJSONScanner) scanEscape() error {
	scanner.offset++
	if scanner.offset >= len(scanner.data) {
		return errors.New("truncated JSON escape")
	}
	switch scanner.data[scanner.offset] {
	case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
		scanner.offset++
		return nil
	case 'u':
		first, next, ok := decodeHexQuadRaw(scanner.data, scanner.offset+1)
		if !ok {
			return errors.New("invalid JSON unicode escape")
		}
		scanner.offset = next
		if first >= 0xd800 && first <= 0xdbff {
			if scanner.offset+2 > len(scanner.data) || scanner.data[scanner.offset] != '\\' ||
				scanner.data[scanner.offset+1] != 'u' {
				return errors.New("invalid JSON unicode surrogate")
			}
			second, secondNext, secondOK := decodeHexQuadRaw(scanner.data, scanner.offset+2)
			if !secondOK || second < 0xdc00 || second > 0xdfff {
				return errors.New("invalid JSON unicode surrogate")
			}
			scanner.offset = secondNext
			return nil
		}
		if first >= 0xdc00 && first <= 0xdfff {
			return errors.New("invalid JSON unicode surrogate")
		}
		return nil
	default:
		return errors.New("invalid JSON escape")
	}
}

func decodeHexQuadRaw(data []byte, start int) (uint16, int, bool) {
	if start < 0 || start+4 > len(data) {
		return 0, 0, false
	}
	var value uint16
	for _, character := range data[start : start+4] {
		value <<= 4
		switch {
		case character >= '0' && character <= '9':
			value |= uint16(character - '0')
		case character >= 'a' && character <= 'f':
			value |= uint16(character-'a') + 10
		case character >= 'A' && character <= 'F':
			value |= uint16(character-'A') + 10
		default:
			return 0, 0, false
		}
	}
	return value, start + 4, true
}

func (scanner *strictJSONScanner) scanLiteral(literal string) error {
	if !bytes.HasPrefix(scanner.data[scanner.offset:], []byte(literal)) {
		return errors.New("invalid JSON literal")
	}
	scanner.offset += len(literal)
	return nil
}

func (scanner *strictJSONScanner) scanNumber() error {
	start := scanner.offset
	if scanner.consume('-') && scanner.offset >= len(scanner.data) {
		return errors.New("invalid JSON number")
	}
	if scanner.consume('0') {
		if scanner.offset < len(scanner.data) && scanner.data[scanner.offset] >= '0' && scanner.data[scanner.offset] <= '9' {
			return errors.New("invalid JSON number")
		}
	} else {
		if scanner.offset >= len(scanner.data) || scanner.data[scanner.offset] < '1' || scanner.data[scanner.offset] > '9' {
			return errors.New("invalid JSON number")
		}
		for scanner.offset < len(scanner.data) && scanner.data[scanner.offset] >= '0' && scanner.data[scanner.offset] <= '9' {
			scanner.offset++
		}
	}
	if scanner.consume('.') {
		fractionStart := scanner.offset
		for scanner.offset < len(scanner.data) && scanner.data[scanner.offset] >= '0' && scanner.data[scanner.offset] <= '9' {
			scanner.offset++
		}
		if scanner.offset == fractionStart {
			return errors.New("invalid JSON number")
		}
	}
	if scanner.offset < len(scanner.data) && (scanner.data[scanner.offset] == 'e' || scanner.data[scanner.offset] == 'E') {
		scanner.offset++
		if scanner.offset < len(scanner.data) && (scanner.data[scanner.offset] == '+' || scanner.data[scanner.offset] == '-') {
			scanner.offset++
		}
		exponentStart := scanner.offset
		for scanner.offset < len(scanner.data) && scanner.data[scanner.offset] >= '0' && scanner.data[scanner.offset] <= '9' {
			scanner.offset++
		}
		if scanner.offset == exponentStart {
			return errors.New("invalid JSON number")
		}
	}
	if scanner.offset == start {
		return errors.New("invalid JSON value")
	}
	return nil
}

func (scanner *strictJSONScanner) skipWhitespace() {
	for scanner.offset < len(scanner.data) {
		switch scanner.data[scanner.offset] {
		case ' ', '\t', '\n', '\r':
			scanner.offset++
		default:
			return
		}
	}
}

func (scanner *strictJSONScanner) consume(expected byte) bool {
	if scanner.offset >= len(scanner.data) || scanner.data[scanner.offset] != expected {
		return false
	}
	scanner.offset++
	return true
}

func exactJSONObjectField(data, target []byte) ([]byte, bool) {
	if len(target) == 0 {
		return nil, false
	}
	scanner := strictJSONScanner{data: data, maximumDepth: maxJSONDepth}
	scanner.skipWhitespace()
	if !scanner.consume('{') {
		return nil, false
	}
	scanner.skipWhitespace()
	if scanner.consume('}') {
		return nil, false
	}
	var result []byte
	for {
		scanner.skipWhitespace()
		if scanner.offset >= len(scanner.data) || scanner.data[scanner.offset] != '"' {
			clear(result)
			return nil, false
		}
		keyStart := scanner.offset
		keyEnd, err := scanner.scanString()
		if err != nil {
			clear(result)
			return nil, false
		}
		key, err := decodeJSONStringBytes(scanner.data[keyStart:keyEnd], maxSuccessBodyBytes)
		if err != nil {
			clear(key)
			clear(result)
			return nil, false
		}
		matches := bytes.Equal(key, target)
		clear(key)
		scanner.skipWhitespace()
		if !scanner.consume(':') {
			clear(result)
			return nil, false
		}
		scanner.skipWhitespace()
		valueStart := scanner.offset
		if err := scanner.scanValue(1); err != nil {
			clear(result)
			return nil, false
		}
		if matches {
			clear(result)
			result = bytes.Clone(scanner.data[valueStart:scanner.offset])
		}
		scanner.skipWhitespace()
		if scanner.consume('}') {
			scanner.skipWhitespace()
			if scanner.offset != len(scanner.data) {
				clear(result)
				return nil, false
			}
			return result, result != nil
		}
		if !scanner.consume(',') {
			clear(result)
			return nil, false
		}
	}
}

func requireJSONEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func requiredObjectFields(data []byte, required []string) bool {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		destroyRawMessageMap(fields)
		return false
	}
	defer destroyRawMessageMap(fields)
	for _, field := range required {
		if _, ok := fields[field]; !ok {
			return false
		}
	}
	return true
}

func destroyRawMessageMap(fields map[string]json.RawMessage) {
	for key, raw := range fields {
		clear(raw)
		delete(fields, key)
	}
}

func readBounded(reader io.Reader, maximum int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maximum+1))
	if err != nil || int64(len(body)) > maximum {
		return body, errors.New("response body limit exceeded")
	}
	return body, nil
}

func sourceFailure(ctx context.Context, operation string) error {
	if err := ctx.Err(); err != nil {
		return &ClientError{Operation: operation, Class: ErrorTimeout, cause: err}
	}
	return &ClientError{Operation: operation, Class: ErrorUnavailable}
}

func requestFailure(ctx context.Context, operation string, ambiguous bool) error {
	if err := ctx.Err(); err != nil {
		return &ClientError{Operation: operation, Class: ErrorTimeout, Ambiguous: ambiguous, cause: err}
	}
	return &ClientError{Operation: operation, Class: ErrorUnavailable, Ambiguous: ambiguous}
}

func statusFailure(operation string, status int, ambiguous bool) error {
	class := ErrorUnexpectedResponse
	switch status {
	case http.StatusUnauthorized:
		class = ErrorAuthentication
	case http.StatusForbidden:
		class = ErrorPermission
	case http.StatusTooManyRequests:
		class = ErrorRateLimited
	case http.StatusBadRequest, http.StatusNotFound:
		class = ErrorInvalidReference
	default:
		if status >= 500 {
			class = ErrorUnavailable
		}
	}
	return &ClientError{Operation: operation, Class: class, StatusCode: status, Ambiguous: ambiguous}
}

func nilTokenSource(source TokenSource) bool {
	if source == nil {
		return true
	}
	value := reflect.ValueOf(source)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

func validBearer(value []byte) bool {
	if len(value) == 0 || len(value) > 4096 {
		return false
	}
	for _, character := range value {
		if character <= 0x20 || character >= 0x7f || character == '"' || character == '\\' {
			return false
		}
	}
	return true
}

func canonicalTime(value time.Time) bool {
	return !value.IsZero() && value.Location() == time.UTC && value.Equal(credential.CanonicalCredentialExpiry(value))
}

func validOpaqueIdentifier(value string, maximum int) bool {
	return len(value) > 0 && len(value) <= maximum && strings.TrimSpace(value) == value &&
		!strings.ContainsFunc(value, unicode.IsControl)
}

func exactStringSet(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}
	actualCopy, expectedCopy := slices.Clone(actual), slices.Clone(expected)
	slices.Sort(actualCopy)
	slices.Sort(expectedCopy)
	return slices.Equal(actualCopy, expectedCopy)
}

func isJSONNull(value json.RawMessage) bool {
	return bytes.Equal(bytes.TrimSpace(value), []byte("null"))
}

func isJSONObject(value json.RawMessage) bool {
	trimmed := bytes.TrimSpace(value)
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}'
}
