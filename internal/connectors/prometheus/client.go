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
	"strconv"
	"time"

	"github.com/aiops-system/control-plane/internal/connectors"
)

type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
	budget     connectors.Budget
	clock      func() time.Time
}

type RangeRequest struct {
	Expression string
	Start      time.Time
	End        time.Time
	Step       time.Duration
}

func New(rawURL string, httpClient *http.Client, budget connectors.Budget) (*Client, error) {
	baseURL, err := url.Parse(rawURL)
	if err != nil || baseURL.Scheme == "" || baseURL.Host == "" {
		return nil, fmt.Errorf("invalid Prometheus URL")
	}
	budget = budget.WithDefaults()
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

	return client.execute(ctx, endpoint, expression)
}

func (client *Client) QueryRange(ctx context.Context, queryRequest RangeRequest) (connectors.Result, error) {
	if queryRequest.Expression == "" {
		return connectors.Result{}, fmt.Errorf("PromQL expression is required")
	}
	if queryRequest.Start.IsZero() || queryRequest.End.IsZero() || !queryRequest.Start.Before(queryRequest.End) {
		return connectors.Result{}, fmt.Errorf("bounded start and end times are required")
	}
	if queryRequest.Step <= 0 {
		return connectors.Result{}, fmt.Errorf("positive query step is required")
	}
	window := queryRequest.End.Sub(queryRequest.Start)
	if window > client.budget.MaxTimeRange {
		return connectors.Result{}, fmt.Errorf("query range %s exceeds budget %s", window, client.budget.MaxTimeRange)
	}
	estimatedSamples := int64(window/queryRequest.Step) + 1
	if estimatedSamples > int64(client.budget.MaxSamples) {
		return connectors.Result{}, fmt.Errorf("estimated samples %d exceed budget %d", estimatedSamples, client.budget.MaxSamples)
	}

	endpoint := *client.baseURL
	endpoint.Path = path.Join(endpoint.Path, "/api/v1/query_range")
	query := endpoint.Query()
	query.Set("query", queryRequest.Expression)
	query.Set("start", queryRequest.Start.UTC().Format(time.RFC3339Nano))
	query.Set("end", queryRequest.End.UTC().Format(time.RFC3339Nano))
	query.Set("step", strconv.FormatFloat(queryRequest.Step.Seconds(), 'f', -1, 64))
	endpoint.RawQuery = query.Encode()

	return client.execute(ctx, endpoint, queryRequest.Expression)
}

func (client *Client) execute(ctx context.Context, endpoint url.URL, expression string) (connectors.Result, error) {
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
			ResultType string          `json:"resultType"`
			Result     json.RawMessage `json:"result"`
		} `json:"data"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return connectors.Result{}, fmt.Errorf("decode Prometheus response: %w", err)
	}
	if envelope.Status != "success" {
		return connectors.Result{}, fmt.Errorf("Prometheus query failed: %s", envelope.Error)
	}
	items, err := decodeResultItems(envelope.Data.ResultType, envelope.Data.Result)
	if err != nil {
		return connectors.Result{}, err
	}
	samples, err := countSamples(envelope.Data.ResultType, items)
	if err != nil {
		return connectors.Result{}, err
	}
	if samples > client.budget.MaxSamples {
		return connectors.Result{}, fmt.Errorf("Prometheus returned %d samples, exceeding budget %d", samples, client.budget.MaxSamples)
	}
	truncated := len(items) > client.budget.MaxItems
	if truncated {
		items = items[:client.budget.MaxItems]
	}
	sum := sha256.Sum256(body)
	return connectors.Result{
		Source:      "prometheus",
		Query:       expression,
		CollectedAt: client.clock().UTC(),
		ItemCount:   len(items),
		ContentHash: hex.EncodeToString(sum[:]),
		Truncated:   truncated,
		Items:       items,
	}, nil
}

func decodeResultItems(resultType string, raw json.RawMessage) ([]json.RawMessage, error) {
	switch resultType {
	case "vector", "matrix":
		var items []json.RawMessage
		if err := json.Unmarshal(raw, &items); err != nil {
			return nil, fmt.Errorf("decode Prometheus %s result: %w", resultType, err)
		}
		return items, nil
	case "scalar", "string":
		if len(raw) == 0 || string(raw) == "null" {
			return nil, nil
		}
		return []json.RawMessage{raw}, nil
	default:
		return nil, fmt.Errorf("unsupported Prometheus result type %q", resultType)
	}
}

func countSamples(resultType string, items []json.RawMessage) (int, error) {
	if resultType == "scalar" || resultType == "string" {
		return len(items), nil
	}
	total := 0
	for _, item := range items {
		var series struct {
			Value      json.RawMessage   `json:"value"`
			Histogram  json.RawMessage   `json:"histogram"`
			Values     []json.RawMessage `json:"values"`
			Histograms []json.RawMessage `json:"histograms"`
		}
		if err := json.Unmarshal(item, &series); err != nil {
			return 0, fmt.Errorf("decode Prometheus series: %w", err)
		}
		if len(series.Value) > 0 && string(series.Value) != "null" {
			total++
		}
		if len(series.Histogram) > 0 && string(series.Histogram) != "null" {
			total++
		}
		total += len(series.Values) + len(series.Histograms)
	}
	return total, nil
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
