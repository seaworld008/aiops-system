package awx

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/aiops-system/control-plane/internal/connectors"
)

const maxInventoryPageSize = 100

type Client struct {
	baseURL    *url.URL
	token      string
	httpClient *http.Client
	budget     connectors.Budget
	clock      func() time.Time
}

type inventoryHost struct {
	ID          int    `json:"id"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Enabled     bool   `json:"enabled"`
	InstanceID  string `json:"instance_id,omitempty"`
}

type jobTemplate struct {
	ID                   int    `json:"id"`
	Name                 string `json:"name"`
	Description          string `json:"description,omitempty"`
	JobType              string `json:"job_type"`
	Playbook             string `json:"playbook,omitempty"`
	Inventory            int    `json:"inventory,omitempty"`
	Project              int    `json:"project,omitempty"`
	AskVariablesOnLaunch bool   `json:"ask_variables_on_launch"`
	SurveyEnabled        bool   `json:"survey_enabled"`
}

type jobStatus struct {
	ID          int     `json:"id"`
	Name        string  `json:"name,omitempty"`
	Status      string  `json:"status"`
	Failed      bool    `json:"failed"`
	Started     string  `json:"started,omitempty"`
	Finished    string  `json:"finished,omitempty"`
	Elapsed     float64 `json:"elapsed,omitempty"`
	JobTemplate int     `json:"job_template,omitempty"`
	Inventory   int     `json:"inventory,omitempty"`
}

func New(rawURL, token string, httpClient *http.Client, budget connectors.Budget) (*Client, error) {
	baseURL, err := url.Parse(rawURL)
	if err != nil || rawURL != strings.TrimSpace(rawURL) ||
		(baseURL.Scheme != "http" && baseURL.Scheme != "https") ||
		baseURL.Host == "" ||
		baseURL.User != nil ||
		baseURL.ForceQuery ||
		baseURL.RawQuery != "" ||
		baseURL.Fragment != "" {
		return nil, fmt.Errorf("invalid AWX URL")
	}
	if baseURL.Scheme == "http" && !isLoopbackHost(baseURL.Hostname()) {
		return nil, fmt.Errorf("AWX URL must use HTTPS")
	}
	if !validBearerToken(token) {
		return nil, fmt.Errorf("AWX bearer token is required")
	}
	budget = budget.WithDefaults()
	if err := budget.Validate(); err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	connectorHTTPClient := *httpClient
	connectorHTTPClient.Jar = nil
	connectorHTTPClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{
		baseURL:    baseURL,
		token:      token,
		httpClient: &connectorHTTPClient,
		budget:     budget,
		clock:      time.Now,
	}, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (client *Client) ListInventoryHosts(ctx context.Context, inventoryID int) (connectors.Result, error) {
	if inventoryID <= 0 {
		return connectors.Result{}, fmt.Errorf("positive AWX inventory ID is required")
	}
	pageSize := min(client.budget.MaxItems, maxInventoryPageSize)
	endpoint := client.endpoint("api", "v2", "inventories", strconv.Itoa(inventoryID), "hosts")
	query := endpoint.Query()
	query.Set("page", "1")
	query.Set("page_size", strconv.Itoa(pageSize))
	endpoint.RawQuery = query.Encode()

	body, err := client.get(ctx, endpoint)
	if err != nil {
		return connectors.Result{}, err
	}
	var envelope struct {
		Count   *int            `json:"count"`
		Next    json.RawMessage `json:"next"`
		Results json.RawMessage `json:"results"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return connectors.Result{}, fmt.Errorf("decode AWX inventory hosts response: %w", err)
	}
	if envelope.Count == nil || *envelope.Count < 0 {
		return connectors.Result{}, fmt.Errorf("invalid AWX inventory hosts response: non-negative count is required")
	}
	if err := validateNextPage(envelope.Next); err != nil {
		return connectors.Result{}, err
	}
	resultsJSON := bytes.TrimSpace(envelope.Results)
	if len(resultsJSON) == 0 || bytes.Equal(resultsJSON, []byte("null")) {
		return connectors.Result{}, fmt.Errorf("invalid AWX inventory hosts response: results array is required")
	}
	var results []inventoryHost
	if err := json.Unmarshal(resultsJSON, &results); err != nil {
		return connectors.Result{}, fmt.Errorf("decode AWX inventory host results: %w", err)
	}
	if *envelope.Count < len(results) {
		return connectors.Result{}, fmt.Errorf("invalid AWX inventory hosts response: count is smaller than results")
	}
	for index := range results {
		if results[index].ID <= 0 || strings.TrimSpace(results[index].Name) == "" {
			return connectors.Result{}, fmt.Errorf("invalid AWX inventory host at index %d: positive id and name are required", index)
		}
	}

	truncated := *envelope.Count > pageSize || hasNextPage(envelope.Next) || len(results) > pageSize
	if len(results) > pageSize {
		results = results[:pageSize]
	}
	items, err := marshalItems(results)
	if err != nil {
		return connectors.Result{}, fmt.Errorf("encode AWX inventory host projection: %w", err)
	}
	return client.result(
		items,
		fmt.Sprintf("inventory_hosts inventory_id=%d page_size=%d", inventoryID, pageSize),
		truncated,
	)
}

func (client *Client) GetJobTemplate(ctx context.Context, templateID int) (connectors.Result, error) {
	if templateID <= 0 {
		return connectors.Result{}, fmt.Errorf("positive AWX job template ID is required")
	}
	endpoint := client.endpoint("api", "v2", "job_templates", strconv.Itoa(templateID))
	return client.getProjectedObject(ctx, endpoint, "job_template id="+strconv.Itoa(templateID), templateID, &jobTemplate{})
}

func (client *Client) GetJobStatus(ctx context.Context, jobID int) (connectors.Result, error) {
	if jobID <= 0 {
		return connectors.Result{}, fmt.Errorf("positive AWX job ID is required")
	}
	endpoint := client.endpoint("api", "v2", "jobs", strconv.Itoa(jobID))
	return client.getProjectedObject(ctx, endpoint, "job_status id="+strconv.Itoa(jobID), jobID, &jobStatus{})
}

type objectProjection interface {
	validate(expectedID int) error
}

func (client *Client) getProjectedObject(ctx context.Context, endpoint url.URL, query string, expectedID int, projection objectProjection) (connectors.Result, error) {
	body, err := client.get(ctx, endpoint)
	if err != nil {
		return connectors.Result{}, err
	}
	if err := json.Unmarshal(body, projection); err != nil {
		return connectors.Result{}, fmt.Errorf("decode AWX object response: %w", err)
	}
	if err := projection.validate(expectedID); err != nil {
		return connectors.Result{}, err
	}
	projected, err := json.Marshal(projection)
	if err != nil {
		return connectors.Result{}, fmt.Errorf("encode AWX object projection: %w", err)
	}
	return client.result([]json.RawMessage{json.RawMessage(projected)}, query, false)
}

func (template *jobTemplate) validate(expectedID int) error {
	if template.ID != expectedID {
		return fmt.Errorf("invalid AWX job template response: id %d does not match requested id %d", template.ID, expectedID)
	}
	if strings.TrimSpace(template.Name) == "" || strings.TrimSpace(template.JobType) == "" {
		return fmt.Errorf("invalid AWX job template response: name and job_type are required")
	}
	return nil
}

func (job *jobStatus) validate(expectedID int) error {
	if job.ID != expectedID {
		return fmt.Errorf("invalid AWX job response: id %d does not match requested id %d", job.ID, expectedID)
	}
	if strings.TrimSpace(job.Status) == "" {
		return fmt.Errorf("invalid AWX job response: status is required")
	}
	return nil
}

func marshalItems[T any](values []T) ([]json.RawMessage, error) {
	items := make([]json.RawMessage, 0, len(values))
	for _, value := range values {
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		items = append(items, json.RawMessage(encoded))
	}
	return items, nil
}

func (client *Client) get(ctx context.Context, endpoint url.URL) ([]byte, error) {
	requestCtx, cancel := context.WithTimeout(ctx, client.budget.Timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build AWX request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+client.token)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("query AWX: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("AWX returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, client.budget.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read AWX response: %w", err)
	}
	if int64(len(body)) > client.budget.MaxBytes {
		return nil, fmt.Errorf("AWX response exceeds %d bytes", client.budget.MaxBytes)
	}
	return body, nil
}

func (client *Client) endpoint(parts ...string) url.URL {
	endpoint := *client.baseURL
	allParts := append([]string{endpoint.Path}, parts...)
	endpoint.Path = path.Join(allParts...) + "/"
	return endpoint
}

func (client *Client) result(items []json.RawMessage, query string, truncated bool) (connectors.Result, error) {
	body, err := json.Marshal(items)
	if err != nil {
		return connectors.Result{}, fmt.Errorf("encode AWX evidence items: %w", err)
	}
	sum := sha256.Sum256(body)
	return connectors.Result{
		Source:      "awx",
		Query:       query,
		CollectedAt: client.clock().UTC(),
		ItemCount:   len(items),
		ContentHash: hex.EncodeToString(sum[:]),
		Truncated:   truncated,
		Items:       items,
	}, nil
}

func validBearerToken(token string) bool {
	if token == "" {
		return false
	}
	for _, character := range token {
		if unicode.IsSpace(character) || unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func validateNextPage(raw json.RawMessage) error {
	next := bytes.TrimSpace(raw)
	if len(next) == 0 {
		return fmt.Errorf("invalid AWX inventory hosts response: next is required")
	}
	if bytes.Equal(next, []byte("null")) {
		return nil
	}
	var nextURL string
	if err := json.Unmarshal(next, &nextURL); err != nil {
		return fmt.Errorf("invalid AWX inventory hosts response: next must be a string or null")
	}
	return nil
}

func hasNextPage(raw json.RawMessage) bool {
	next := bytes.TrimSpace(raw)
	return len(next) > 0 && !bytes.Equal(next, []byte("null")) && !bytes.Equal(next, []byte(`""`))
}
