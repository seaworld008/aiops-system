package argocd

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
	"strings"
	"time"
	"unicode"

	"github.com/aiops-system/control-plane/internal/connectors"
)

type Client struct {
	baseURL    *url.URL
	token      string
	httpClient *http.Client
	budget     connectors.Budget
	clock      func() time.Time
}

type application struct {
	Metadata struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace,omitempty"`
	} `json:"metadata"`
	Status struct {
		Health struct {
			Status string `json:"status"`
		} `json:"health"`
		Sync struct {
			Status   string `json:"status"`
			Revision string `json:"revision"`
		} `json:"sync"`
		History []struct {
			ID         int64  `json:"id"`
			Revision   string `json:"revision"`
			DeployedAt string `json:"deployedAt,omitempty"`
		} `json:"history"`
		OperationState struct {
			Phase      string `json:"phase,omitempty"`
			StartedAt  string `json:"startedAt,omitempty"`
			FinishedAt string `json:"finishedAt,omitempty"`
		} `json:"operationState,omitempty"`
	} `json:"status"`
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
		return nil, fmt.Errorf("invalid Argo CD URL")
	}
	if baseURL.Scheme == "http" && !isLoopbackHost(baseURL.Hostname()) {
		return nil, fmt.Errorf("Argo CD URL must use HTTPS")
	}
	if !validBearerToken(token) {
		return nil, fmt.Errorf("Argo CD bearer token is required")
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

func (client *Client) ListApplications(ctx context.Context) (connectors.Result, error) {
	endpoint := *client.baseURL
	endpoint.Path = path.Join(endpoint.Path, "api", "v1", "applications")

	requestCtx, cancel := context.WithTimeout(ctx, client.budget.Timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return connectors.Result{}, fmt.Errorf("build Argo CD request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Authorization", "Bearer "+client.token)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return connectors.Result{}, fmt.Errorf("query Argo CD: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return connectors.Result{}, fmt.Errorf("Argo CD returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, client.budget.MaxBytes+1))
	if err != nil {
		return connectors.Result{}, fmt.Errorf("read Argo CD response: %w", err)
	}
	if int64(len(body)) > client.budget.MaxBytes {
		return connectors.Result{}, fmt.Errorf("Argo CD response exceeds %d bytes", client.budget.MaxBytes)
	}

	var envelope struct {
		Items json.RawMessage `json:"items"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return connectors.Result{}, fmt.Errorf("decode Argo CD applications response: %w", err)
	}
	itemsJSON := bytes.TrimSpace(envelope.Items)
	if len(itemsJSON) == 0 || bytes.Equal(itemsJSON, []byte("null")) {
		return connectors.Result{}, fmt.Errorf("invalid Argo CD applications response: items array is required")
	}
	var applications []application
	if err := json.Unmarshal(itemsJSON, &applications); err != nil {
		return connectors.Result{}, fmt.Errorf("decode Argo CD application items: %w", err)
	}
	for index := range applications {
		if !validApplicationName(applications[index].Metadata.Name) {
			return connectors.Result{}, fmt.Errorf("invalid Argo CD application at index %d: valid metadata.name is required", index)
		}
	}

	truncated := len(applications) > client.budget.MaxItems
	if truncated {
		applications = applications[:client.budget.MaxItems]
	}
	historyLimit := min(client.budget.MaxItems, 20)
	items := make([]json.RawMessage, 0, len(applications))
	for index := range applications {
		if len(applications[index].Status.History) > historyLimit {
			applications[index].Status.History = applications[index].Status.History[:historyLimit]
			truncated = true
		}
		projected, err := json.Marshal(applications[index])
		if err != nil {
			return connectors.Result{}, fmt.Errorf("encode Argo CD application projection: %w", err)
		}
		items = append(items, json.RawMessage(projected))
	}
	projectedBody, err := json.Marshal(items)
	if err != nil {
		return connectors.Result{}, fmt.Errorf("encode Argo CD projection: %w", err)
	}
	sum := sha256.Sum256(projectedBody)
	return connectors.Result{
		Source:      "argocd",
		Query:       "applications fields=health,sync,revision,history",
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

func validApplicationName(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || !isDNS1123AlphaNumeric(label[0]) || !isDNS1123AlphaNumeric(label[len(label)-1]) {
			return false
		}
		for index := 1; index < len(label)-1; index++ {
			character := label[index]
			if !isDNS1123AlphaNumeric(character) && character != '-' {
				return false
			}
		}
	}
	return true
}

func isDNS1123AlphaNumeric(character byte) bool {
	return character >= 'a' && character <= 'z' || character >= '0' && character <= '9'
}
