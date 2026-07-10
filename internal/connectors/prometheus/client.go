package prometheus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"time"

	"github.com/aiops-system/control-plane/internal/connectors"
)

type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
	budget     connectors.Budget
	clock      func() time.Time
}

func New(rawURL string, httpClient *http.Client, budget connectors.Budget) (*Client, error) {
	baseURL, err := url.Parse(rawURL)
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" {
		return nil, fmt.Errorf("invalid Prometheus URL")
	}
	if err := budget.Validate(); err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Client{baseURL: baseURL, httpClient: httpClient, budget: budget, clock: time.Now}, nil
}

func (client *Client) Query(ctx context.Context, expression string, at time.Time) (connectors.Result, error) {
	if expression == "" {
		return connectors.Result{}, fmt.Errorf("PromQL expression is required")
	}
	if at.IsZero() {
		at = client.clock().UTC()
	}

	endpoint := *client.baseURL
	endpoint.Path = path.Join(endpoint.Path, "/api/v1/query")
	query := endpoint.Query()
	query.Set("query", expression)
	query.Set("time", at.UTC().Format(time.RFC3339Nano))
	endpoint.RawQuery = query.Encode()

	requestCtx, cancel := context.WithTimeout(ctx, client.budget.Timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return connectors.Result{}, fmt.Errorf("build Prometheus request: %w", err)
	}
	response, err := client.httpClient.Do(request)
	if err != nil {
		return connectors.Result{}, fmt.Errorf("query Prometheus: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return connectors.Result{}, fmt.Errorf("Prometheus returned HTTP %d", response.StatusCode)
	}
	body, err := readBounded(response.Body, client.budget.MaxBytes)
	if err != nil {
		return connectors.Result{}, err
	}
	var envelope struct {
		Status string `json:"status"`
		Data   struct {
			Result []json.RawMessage `json:"result"`
		} `json:"data"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return connectors.Result{}, fmt.Errorf("decode Prometheus response: %w", err)
	}
	if envelope.Status != "success" {
		return connectors.Result{}, fmt.Errorf("Prometheus query failed: %s", envelope.Error)
	}
	truncated := len(envelope.Data.Result) > client.budget.MaxItems
	if truncated {
		envelope.Data.Result = envelope.Data.Result[:client.budget.MaxItems]
	}
	sum := sha256.Sum256(body)
	return connectors.Result{
		Source:      "prometheus",
		Query:       expression,
		CollectedAt: client.clock().UTC(),
		ItemCount:   len(envelope.Data.Result),
		ContentHash: hex.EncodeToString(sum[:]),
		Truncated:   truncated,
		Items:       envelope.Data.Result,
	}, nil
}

func readBounded(reader io.Reader, maxBytes int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(reader, maxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read Prometheus response: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("Prometheus response exceeds %d bytes", maxBytes)
	}
	return body, nil
}
