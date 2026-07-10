package victorialogs

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/seaworld008/aiops-system/internal/connectors"
)

var fieldNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_.-]*$`)

type SearchRequest struct {
	Query  string
	Start  time.Time
	End    time.Time
	Fields []string
	Limit  int
}

type Client struct {
	baseURL    *url.URL
	httpClient *http.Client
	budget     connectors.Budget
	clock      func() time.Time
}

func New(rawURL string, httpClient *http.Client, budget connectors.Budget) (*Client, error) {
	baseURL, err := url.Parse(rawURL)
	if err != nil || rawURL != strings.TrimSpace(rawURL) || (baseURL.Scheme != "http" && baseURL.Scheme != "https") || baseURL.Host == "" || baseURL.User != nil || baseURL.ForceQuery || baseURL.RawQuery != "" || baseURL.Fragment != "" {
		return nil, fmt.Errorf("invalid VictoriaLogs URL")
	}
	budget = budget.WithDefaults()
	if err := budget.Validate(); err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	boundedClient := *httpClient
	boundedClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return errors.New("VictoriaLogs redirects are disabled")
	}
	return &Client{baseURL: baseURL, httpClient: &boundedClient, budget: budget, clock: time.Now}, nil
}

func (client *Client) Search(ctx context.Context, search SearchRequest) (connectors.Result, error) {
	if err := client.validateSearch(search); err != nil {
		return connectors.Result{}, err
	}
	queryWithProjection := search.Query + " | fields " + strings.Join(search.Fields, ",")
	form := url.Values{
		"query":   []string{queryWithProjection},
		"start":   []string{search.Start.UTC().Format(time.RFC3339Nano)},
		"end":     []string{search.End.UTC().Format(time.RFC3339Nano)},
		"limit":   []string{strconv.Itoa(search.Limit + 1)},
		"timeout": []string{client.budget.Timeout.String()},
	}

	endpoint := *client.baseURL
	endpoint.Path = path.Join(endpoint.Path, "/select/logsql/query")
	requestCtx, cancel := context.WithTimeout(ctx, client.budget.Timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodPost, endpoint.String(), strings.NewReader(form.Encode()))
	if err != nil {
		return connectors.Result{}, fmt.Errorf("build VictoriaLogs request: %w", err)
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return connectors.Result{}, fmt.Errorf("query VictoriaLogs: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return connectors.Result{}, fmt.Errorf("VictoriaLogs returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, client.budget.MaxBytes+1))
	if err != nil {
		return connectors.Result{}, fmt.Errorf("read VictoriaLogs response: %w", err)
	}
	if int64(len(body)) > client.budget.MaxBytes {
		return connectors.Result{}, fmt.Errorf("VictoriaLogs response exceeds %d bytes", client.budget.MaxBytes)
	}

	items, truncated, err := decodeJSONLines(body, search.Limit)
	if err != nil {
		return connectors.Result{}, err
	}
	items, err = projectFields(items, search.Fields)
	if err != nil {
		return connectors.Result{}, err
	}
	contentHash, err := connectors.HashItems(items)
	if err != nil {
		return connectors.Result{}, err
	}
	return connectors.Result{
		Source:      "victorialogs",
		Query:       queryWithProjection,
		CollectedAt: client.clock().UTC(),
		ItemCount:   len(items),
		ContentHash: contentHash,
		Truncated:   truncated,
		Items:       items,
	}, nil
}

func (client *Client) validateSearch(search SearchRequest) error {
	if strings.TrimSpace(search.Query) == "" || len(search.Query) > 4096 || strings.ContainsAny(search.Query, "\r\n\x00") {
		return fmt.Errorf("LogsQL query is required and limited to 4096 single-line bytes")
	}
	if search.Start.IsZero() || search.End.IsZero() || !search.Start.Before(search.End) {
		return fmt.Errorf("bounded start and end times are required")
	}
	if window := search.End.Sub(search.Start); window > client.budget.MaxTimeRange {
		return fmt.Errorf("query range %s exceeds budget %s", window, client.budget.MaxTimeRange)
	}
	if len(search.Fields) == 0 {
		return fmt.Errorf("at least one projected field is required")
	}
	seenFields := make(map[string]struct{}, len(search.Fields))
	for _, field := range search.Fields {
		if !fieldNamePattern.MatchString(field) {
			return fmt.Errorf("invalid projected field %q", field)
		}
		if _, duplicate := seenFields[field]; duplicate {
			return fmt.Errorf("duplicate projected field %q", field)
		}
		seenFields[field] = struct{}{}
	}
	if search.Limit <= 0 || search.Limit > client.budget.MaxItems {
		return fmt.Errorf("limit must be between 1 and %d", client.budget.MaxItems)
	}
	return nil
}

func projectFields(items []json.RawMessage, fields []string) ([]json.RawMessage, error) {
	projected := make([]json.RawMessage, 0, len(items))
	for _, item := range items {
		var source map[string]json.RawMessage
		if err := json.Unmarshal(item, &source); err != nil || source == nil {
			return nil, fmt.Errorf("VictoriaLogs result must be a JSON object")
		}
		projection := make(map[string]json.RawMessage, len(fields))
		for _, field := range fields {
			if value, exists := source[field]; exists {
				projection[field] = value
			}
		}
		if len(projection) == 0 {
			return nil, fmt.Errorf("VictoriaLogs result contains none of the projected fields")
		}
		encoded, err := json.Marshal(projection)
		if err != nil {
			return nil, fmt.Errorf("project VictoriaLogs result: %w", err)
		}
		projected = append(projected, json.RawMessage(encoded))
	}
	return projected, nil
}

func decodeJSONLines(body []byte, limit int) ([]json.RawMessage, bool, error) {
	scanner := bufio.NewScanner(bytes.NewReader(body))
	scanner.Buffer(make([]byte, 64<<10), 1<<20)
	items := make([]json.RawMessage, 0, limit)
	truncated := false
	for scanner.Scan() {
		line := bytes.TrimSpace(scanner.Bytes())
		if len(line) == 0 {
			continue
		}
		if !json.Valid(line) {
			return nil, false, fmt.Errorf("VictoriaLogs returned invalid JSON line")
		}
		if len(items) == limit {
			truncated = true
			break
		}
		items = append(items, json.RawMessage(bytes.Clone(line)))
	}
	if err := scanner.Err(); err != nil {
		return nil, false, fmt.Errorf("scan VictoriaLogs response: %w", err)
	}
	return items, truncated, nil
}
