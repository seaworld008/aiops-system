package kubernetes

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/aiops-system/control-plane/internal/connectors"
)

const (
	sourceName        = "kubernetes"
	maxSelectorLength = 1024
)

var (
	dns1123LabelPattern = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)
	labelPartPattern    = regexp.MustCompile(`^[A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?$`)
	fieldNamePattern    = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]*(/[A-Za-z0-9_.-]+)?$`)
	fieldValuePattern   = regexp.MustCompile(`^[A-Za-z0-9._:/@+\-]*$`)
	setRequirement      = regexp.MustCompile(`^([^[:space:]!(),=]+)[[:space:]]+(in|notin)[[:space:]]*\(([^()]*)\)$`)
)

// Client exposes only the Kubernetes read operations needed by investigations.
type Client struct {
	baseURL     *url.URL
	bearerToken string
	httpClient  *http.Client
	budget      connectors.Budget
	clock       func() time.Time
}

type objectMetadataEvidence struct {
	Name       string            `json:"name"`
	Namespace  string            `json:"namespace"`
	UID        string            `json:"uid,omitempty"`
	Generation int64             `json:"generation,omitempty"`
	Labels     map[string]string `json:"labels,omitempty"`
}

type containerEvidence struct {
	Name  string `json:"name"`
	Image string `json:"image,omitempty"`
}

type conditionEvidence struct {
	Type               string `json:"type"`
	Status             string `json:"status"`
	Reason             string `json:"reason,omitempty"`
	LastProbeTime      string `json:"lastProbeTime,omitempty"`
	LastUpdateTime     string `json:"lastUpdateTime,omitempty"`
	LastTransitionTime string `json:"lastTransitionTime,omitempty"`
}

type deploymentEvidence struct {
	APIVersion string                 `json:"apiVersion"`
	Kind       string                 `json:"kind"`
	Metadata   objectMetadataEvidence `json:"metadata"`
	Spec       struct {
		Replicas *int32 `json:"replicas,omitempty"`
		Selector struct {
			MatchLabels      map[string]string `json:"matchLabels,omitempty"`
			MatchExpressions []struct {
				Key      string   `json:"key"`
				Operator string   `json:"operator"`
				Values   []string `json:"values,omitempty"`
			} `json:"matchExpressions,omitempty"`
		} `json:"selector,omitempty"`
		Template struct {
			Metadata struct {
				Labels map[string]string `json:"labels,omitempty"`
			} `json:"metadata,omitempty"`
			Spec struct {
				Containers     []containerEvidence `json:"containers,omitempty"`
				InitContainers []containerEvidence `json:"initContainers,omitempty"`
			} `json:"spec,omitempty"`
		} `json:"template,omitempty"`
	} `json:"spec,omitempty"`
	Status struct {
		ObservedGeneration  int64               `json:"observedGeneration,omitempty"`
		Replicas            int32               `json:"replicas,omitempty"`
		UpdatedReplicas     int32               `json:"updatedReplicas,omitempty"`
		ReadyReplicas       int32               `json:"readyReplicas,omitempty"`
		AvailableReplicas   int32               `json:"availableReplicas,omitempty"`
		UnavailableReplicas int32               `json:"unavailableReplicas,omitempty"`
		Conditions          []conditionEvidence `json:"conditions,omitempty"`
	} `json:"status,omitempty"`
}

type containerStateEvidence struct {
	Waiting *struct {
		Reason string `json:"reason,omitempty"`
	} `json:"waiting,omitempty"`
	Running *struct {
		StartedAt string `json:"startedAt,omitempty"`
	} `json:"running,omitempty"`
	Terminated *struct {
		ExitCode   int32  `json:"exitCode"`
		Signal     int32  `json:"signal,omitempty"`
		Reason     string `json:"reason,omitempty"`
		StartedAt  string `json:"startedAt,omitempty"`
		FinishedAt string `json:"finishedAt,omitempty"`
	} `json:"terminated,omitempty"`
}

type containerStatusEvidence struct {
	Name         string                 `json:"name"`
	Image        string                 `json:"image,omitempty"`
	Ready        bool                   `json:"ready"`
	Started      *bool                  `json:"started,omitempty"`
	RestartCount int32                  `json:"restartCount"`
	State        containerStateEvidence `json:"state,omitempty"`
	LastState    containerStateEvidence `json:"lastState,omitempty"`
}

type podEvidence struct {
	APIVersion string                 `json:"apiVersion"`
	Kind       string                 `json:"kind"`
	Metadata   objectMetadataEvidence `json:"metadata"`
	Spec       struct {
		NodeName       string              `json:"nodeName,omitempty"`
		RestartPolicy  string              `json:"restartPolicy,omitempty"`
		Containers     []containerEvidence `json:"containers,omitempty"`
		InitContainers []containerEvidence `json:"initContainers,omitempty"`
	} `json:"spec,omitempty"`
	Status struct {
		Phase                 string                    `json:"phase,omitempty"`
		Reason                string                    `json:"reason,omitempty"`
		StartTime             string                    `json:"startTime,omitempty"`
		QOSClass              string                    `json:"qosClass,omitempty"`
		Conditions            []conditionEvidence       `json:"conditions,omitempty"`
		ContainerStatuses     []containerStatusEvidence `json:"containerStatuses,omitempty"`
		InitContainerStatuses []containerStatusEvidence `json:"initContainerStatuses,omitempty"`
	} `json:"status,omitempty"`
}

type objectReferenceEvidence struct {
	APIVersion string `json:"apiVersion,omitempty"`
	Kind       string `json:"kind,omitempty"`
	Namespace  string `json:"namespace,omitempty"`
	Name       string `json:"name,omitempty"`
	UID        string `json:"uid,omitempty"`
	FieldPath  string `json:"fieldPath,omitempty"`
}

type eventEvidence struct {
	APIVersion         string                  `json:"apiVersion"`
	Kind               string                  `json:"kind"`
	Metadata           objectMetadataEvidence  `json:"metadata"`
	InvolvedObject     objectReferenceEvidence `json:"involvedObject,omitempty"`
	Reason             string                  `json:"reason,omitempty"`
	Type               string                  `json:"type,omitempty"`
	Action             string                  `json:"action,omitempty"`
	Count              int32                   `json:"count,omitempty"`
	FirstTimestamp     string                  `json:"firstTimestamp,omitempty"`
	LastTimestamp      string                  `json:"lastTimestamp,omitempty"`
	EventTime          string                  `json:"eventTime,omitempty"`
	ReportingComponent string                  `json:"reportingComponent,omitempty"`
	ReportingInstance  string                  `json:"reportingInstance,omitempty"`
}

type listMetadata struct {
	Continue string `json:"continue"`
}

type listEnvelope struct {
	APIVersion string             `json:"apiVersion"`
	Kind       string             `json:"kind"`
	Metadata   *listMetadata      `json:"metadata"`
	Items      *[]json.RawMessage `json:"items"`
}

// New constructs a bounded, read-only Kubernetes REST API client.
func New(rawURL, bearerToken string, httpClient *http.Client, budget connectors.Budget) (*Client, error) {
	baseURL, err := url.Parse(rawURL)
	if err != nil || rawURL != strings.TrimSpace(rawURL) || baseURL.Scheme == "" || baseURL.Host == "" ||
		(baseURL.Scheme != "https" && baseURL.Scheme != "http") || baseURL.User != nil ||
		baseURL.RawQuery != "" || baseURL.ForceQuery || baseURL.Fragment != "" {
		return nil, fmt.Errorf("invalid Kubernetes API URL")
	}
	if baseURL.Scheme == "http" && !isLoopbackHost(baseURL.Hostname()) {
		return nil, fmt.Errorf("Kubernetes API URL must use HTTPS")
	}
	if err := validateBearerToken(bearerToken); err != nil {
		return nil, err
	}

	budget = budget.WithDefaults()
	if err := budget.Validate(); err != nil {
		return nil, err
	}

	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	readOnlyHTTPClient := *httpClient
	readOnlyHTTPClient.Jar = nil
	readOnlyHTTPClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return &Client{
		baseURL:     baseURL,
		bearerToken: bearerToken,
		httpClient:  &readOnlyHTTPClient,
		budget:      budget,
		clock:       time.Now,
	}, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// GetDeployment retrieves one apps/v1 Deployment.
func (client *Client) GetDeployment(ctx context.Context, namespace, name string) (connectors.Result, error) {
	if err := validateNamespace(namespace); err != nil {
		return connectors.Result{}, err
	}
	if err := validateResourceName(name); err != nil {
		return connectors.Result{}, err
	}

	endpoint := client.endpoint("/apis/apps/v1/namespaces/" + namespace + "/deployments/" + name)
	body, err := client.get(ctx, endpoint)
	if err != nil {
		return connectors.Result{}, err
	}
	item, err := projectDeployment(body, namespace, name)
	if err != nil {
		return connectors.Result{}, err
	}
	return client.result(endpoint.RequestURI(), []json.RawMessage{item}, false)
}

// ListPods lists core/v1 Pods matching labelSelector, bounded by MaxItems.
func (client *Client) ListPods(ctx context.Context, namespace, labelSelector string) (connectors.Result, error) {
	if err := validateNamespace(namespace); err != nil {
		return connectors.Result{}, err
	}
	if err := validateLabelSelector(labelSelector); err != nil {
		return connectors.Result{}, err
	}

	return client.list(
		ctx,
		"/api/v1/namespaces/"+namespace+"/pods",
		"labelSelector",
		labelSelector,
		"PodList",
		func(raw json.RawMessage) (json.RawMessage, error) { return projectPod(raw, namespace) },
	)
}

// ListEvents lists core/v1 Events matching fieldSelector, bounded by MaxItems.
func (client *Client) ListEvents(ctx context.Context, namespace, fieldSelector string) (connectors.Result, error) {
	if err := validateNamespace(namespace); err != nil {
		return connectors.Result{}, err
	}
	if err := validateFieldSelector(fieldSelector); err != nil {
		return connectors.Result{}, err
	}

	return client.list(
		ctx,
		"/api/v1/namespaces/"+namespace+"/events",
		"fieldSelector",
		fieldSelector,
		"EventList",
		func(raw json.RawMessage) (json.RawMessage, error) { return projectEvent(raw, namespace) },
	)
}

func (client *Client) list(
	ctx context.Context,
	apiPath, selectorKey, selector, expectedKind string,
	project func(json.RawMessage) (json.RawMessage, error),
) (connectors.Result, error) {
	endpoint := client.endpoint(apiPath)
	query := endpoint.Query()
	query.Set(selectorKey, selector)
	query.Set("limit", strconv.Itoa(client.budget.MaxItems))
	endpoint.RawQuery = query.Encode()

	body, err := client.get(ctx, endpoint)
	if err != nil {
		return connectors.Result{}, err
	}
	var list listEnvelope
	if err := json.Unmarshal(body, &list); err != nil {
		return connectors.Result{}, fmt.Errorf("decode Kubernetes list: %w", err)
	}
	if list.APIVersion != "v1" || list.Kind != expectedKind || list.Metadata == nil || list.Items == nil {
		return connectors.Result{}, fmt.Errorf("decode Kubernetes list: expected v1 %s envelope", expectedKind)
	}

	rawItems := *list.Items
	truncated := list.Metadata.Continue != "" || len(rawItems) > client.budget.MaxItems
	if len(rawItems) > client.budget.MaxItems {
		rawItems = rawItems[:client.budget.MaxItems]
	}
	items := make([]json.RawMessage, 0, len(rawItems))
	for index, raw := range rawItems {
		item, err := project(raw)
		if err != nil {
			return connectors.Result{}, fmt.Errorf("project Kubernetes %s item %d: %w", expectedKind, index, err)
		}
		items = append(items, item)
	}
	return client.result(endpoint.RequestURI(), items, truncated)
}

func projectDeployment(body []byte, namespace, name string) (json.RawMessage, error) {
	var deployment deploymentEvidence
	if err := json.Unmarshal(body, &deployment); err != nil {
		return nil, fmt.Errorf("decode Kubernetes Deployment: %w", err)
	}
	if deployment.APIVersion != "apps/v1" || deployment.Kind != "Deployment" ||
		deployment.Metadata.Namespace != namespace || deployment.Metadata.Name != name {
		return nil, fmt.Errorf("decode Kubernetes Deployment: response identity does not match %s/%s", namespace, name)
	}
	return marshalEvidence("Deployment", deployment)
}

func projectPod(raw json.RawMessage, namespace string) (json.RawMessage, error) {
	var pod podEvidence
	if err := json.Unmarshal(raw, &pod); err != nil {
		return nil, fmt.Errorf("decode Pod: %w", err)
	}
	if err := validateItemIdentity(pod.APIVersion, pod.Kind, "Pod", pod.Metadata, namespace); err != nil {
		return nil, err
	}
	return marshalEvidence("Pod", pod)
}

func projectEvent(raw json.RawMessage, namespace string) (json.RawMessage, error) {
	var event eventEvidence
	if err := json.Unmarshal(raw, &event); err != nil {
		return nil, fmt.Errorf("decode Event: %w", err)
	}
	if err := validateItemIdentity(event.APIVersion, event.Kind, "Event", event.Metadata, namespace); err != nil {
		return nil, err
	}
	return marshalEvidence("Event", event)
}

func validateItemIdentity(apiVersion, kind, expectedKind string, metadata objectMetadataEvidence, namespace string) error {
	if apiVersion != "v1" || kind != expectedKind || metadata.Name == "" || metadata.Namespace != namespace {
		return fmt.Errorf("response identity does not match v1 %s in namespace %q", expectedKind, namespace)
	}
	return nil
}

func marshalEvidence(kind string, value any) (json.RawMessage, error) {
	projected, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("encode Kubernetes %s projection: %w", kind, err)
	}
	return json.RawMessage(projected), nil
}

func (client *Client) endpoint(apiPath string) url.URL {
	endpoint := *client.baseURL
	endpoint.Path = strings.TrimRight(endpoint.Path, "/") + apiPath
	endpoint.RawPath = ""
	endpoint.RawQuery = ""
	endpoint.ForceQuery = false
	endpoint.Fragment = ""
	return endpoint
}

func (client *Client) get(ctx context.Context, endpoint url.URL) ([]byte, error) {
	requestContext, cancel := context.WithTimeout(ctx, client.budget.Timeout)
	defer cancel()

	request, err := http.NewRequestWithContext(requestContext, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build Kubernetes request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+client.bearerToken)

	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("query Kubernetes API: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("Kubernetes API returned HTTP %d", response.StatusCode)
	}

	body, err := readBounded(response.Body, client.budget.MaxBytes)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func (client *Client) result(query string, items []json.RawMessage, truncated bool) (connectors.Result, error) {
	projected, err := json.Marshal(items)
	if err != nil {
		return connectors.Result{}, fmt.Errorf("encode Kubernetes projected Items: %w", err)
	}
	sum := sha256.Sum256(projected)
	return connectors.Result{
		Source:      sourceName,
		Query:       query,
		CollectedAt: client.clock().UTC(),
		ItemCount:   len(items),
		ContentHash: hex.EncodeToString(sum[:]),
		Truncated:   truncated,
		Items:       items,
	}, nil
}

func readBounded(reader io.Reader, maxBytes int64) ([]byte, error) {
	limit := maxBytes
	if maxBytes < math.MaxInt64 {
		limit++
	}
	body, err := io.ReadAll(io.LimitReader(reader, limit))
	if err != nil {
		return nil, fmt.Errorf("read Kubernetes response: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("Kubernetes response exceeds %d bytes", maxBytes)
	}
	return body, nil
}

func validateBearerToken(token string) error {
	if token == "" || strings.TrimSpace(token) != token {
		return fmt.Errorf("Kubernetes bearer token is required")
	}
	for _, character := range token {
		if character > unicode.MaxASCII || unicode.IsControl(character) || unicode.IsSpace(character) {
			return fmt.Errorf("invalid Kubernetes bearer token")
		}
	}
	return nil
}

func validateNamespace(namespace string) error {
	if len(namespace) == 0 || len(namespace) > 63 || !dns1123LabelPattern.MatchString(namespace) {
		return fmt.Errorf("invalid Kubernetes namespace %q", namespace)
	}
	return nil
}

func validateResourceName(name string) error {
	if !isDNS1123Subdomain(name) {
		return fmt.Errorf("invalid Kubernetes resource name %q", name)
	}
	return nil
}

func validateLabelSelector(selector string) error {
	requirements, err := selectorRequirements(selector)
	if err != nil {
		return fmt.Errorf("invalid Kubernetes label selector: %w", err)
	}
	for _, requirement := range requirements {
		if matches := setRequirement.FindStringSubmatch(requirement); matches != nil {
			if err := validateLabelKey(matches[1]); err != nil {
				return fmt.Errorf("invalid Kubernetes label selector: %w", err)
			}
			values := strings.Split(matches[3], ",")
			if len(values) == 0 || (len(values) == 1 && strings.TrimSpace(values[0]) == "") {
				return fmt.Errorf("invalid Kubernetes label selector: set values are required")
			}
			for _, value := range values {
				if err := validateLabelValue(strings.TrimSpace(value)); err != nil {
					return fmt.Errorf("invalid Kubernetes label selector: %w", err)
				}
			}
			continue
		}

		operator, index := selectorOperator(requirement)
		if operator != "" {
			key := strings.TrimSpace(requirement[:index])
			value := strings.TrimSpace(requirement[index+len(operator):])
			if err := validateLabelKey(key); err != nil {
				return fmt.Errorf("invalid Kubernetes label selector: %w", err)
			}
			if strings.ContainsAny(value, "=!,()") {
				return fmt.Errorf("invalid Kubernetes label selector: malformed value")
			}
			if err := validateLabelValue(value); err != nil {
				return fmt.Errorf("invalid Kubernetes label selector: %w", err)
			}
			continue
		}

		key := requirement
		if strings.HasPrefix(key, "!") {
			key = strings.TrimSpace(strings.TrimPrefix(key, "!"))
		}
		if err := validateLabelKey(key); err != nil {
			return fmt.Errorf("invalid Kubernetes label selector: %w", err)
		}
	}
	return nil
}

func validateFieldSelector(selector string) error {
	requirements, err := selectorRequirements(selector)
	if err != nil {
		return fmt.Errorf("invalid Kubernetes field selector: %w", err)
	}
	for _, requirement := range requirements {
		operator, index := selectorOperator(requirement)
		if operator == "" {
			return fmt.Errorf("invalid Kubernetes field selector: comparison operator is required")
		}
		key := strings.TrimSpace(requirement[:index])
		value := strings.TrimSpace(requirement[index+len(operator):])
		if !fieldNamePattern.MatchString(key) || strings.ContainsAny(value, "=!(),") || !fieldValuePattern.MatchString(value) {
			return fmt.Errorf("invalid Kubernetes field selector requirement %q", requirement)
		}
	}
	return nil
}

func selectorRequirements(selector string) ([]string, error) {
	if selector == "" || strings.TrimSpace(selector) != selector {
		return nil, fmt.Errorf("selector is required without surrounding whitespace")
	}
	if len(selector) > maxSelectorLength {
		return nil, fmt.Errorf("selector exceeds %d bytes", maxSelectorLength)
	}
	for _, character := range selector {
		if character > unicode.MaxASCII || unicode.IsControl(character) || strings.ContainsRune("&?#;%", character) {
			return nil, fmt.Errorf("selector contains an invalid character")
		}
	}

	var requirements []string
	start := 0
	depth := 0
	for index, character := range selector {
		switch character {
		case '(':
			depth++
			if depth > 1 {
				return nil, fmt.Errorf("selector contains nested parentheses")
			}
		case ')':
			depth--
			if depth < 0 {
				return nil, fmt.Errorf("selector contains unbalanced parentheses")
			}
		case ',':
			if depth == 0 {
				requirement := strings.TrimSpace(selector[start:index])
				if requirement == "" {
					return nil, fmt.Errorf("selector contains an empty requirement")
				}
				requirements = append(requirements, requirement)
				start = index + 1
			}
		}
	}
	if depth != 0 {
		return nil, fmt.Errorf("selector contains unbalanced parentheses")
	}
	requirement := strings.TrimSpace(selector[start:])
	if requirement == "" {
		return nil, fmt.Errorf("selector contains an empty requirement")
	}
	return append(requirements, requirement), nil
}

func selectorOperator(requirement string) (string, int) {
	for _, operator := range []string{"!=", "==", "="} {
		if index := strings.Index(requirement, operator); index >= 0 {
			return operator, index
		}
	}
	return "", -1
}

func validateLabelKey(key string) error {
	if key == "" || len(key) > 317 {
		return fmt.Errorf("invalid label key %q", key)
	}
	parts := strings.Split(key, "/")
	if len(parts) > 2 {
		return fmt.Errorf("invalid label key %q", key)
	}
	name := parts[len(parts)-1]
	if len(name) == 0 || len(name) > 63 || !labelPartPattern.MatchString(name) {
		return fmt.Errorf("invalid label key %q", key)
	}
	if len(parts) == 2 {
		prefix := parts[0]
		if !isDNS1123Subdomain(prefix) {
			return fmt.Errorf("invalid label key %q", key)
		}
	}
	return nil
}

func isDNS1123Subdomain(value string) bool {
	if len(value) == 0 || len(value) > 253 {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || !dns1123LabelPattern.MatchString(label) {
			return false
		}
	}
	return true
}

func validateLabelValue(value string) error {
	if len(value) > 63 || (value != "" && !labelPartPattern.MatchString(value)) {
		return fmt.Errorf("invalid label value %q", value)
	}
	return nil
}
