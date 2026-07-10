package gitlab

import (
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

	"github.com/aiops-system/control-plane/internal/connectors"
)

const maxPageSize = 100
const maxCredentialBytes = 4096
const maxEvidenceFutureSkew = 24 * time.Hour

type Client struct {
	baseURL    *url.URL
	token      string
	httpClient *http.Client
	budget     connectors.Budget
	clock      func() time.Time
}

type clientOptions struct {
	allowInsecureLoopback bool
}

type Option func(*clientOptions)

// AllowInsecureForTesting permits HTTP only for loopback test servers.
func AllowInsecureForTesting() Option {
	return func(options *clientOptions) {
		options.allowInsecureLoopback = true
	}
}

type pipelineResponse struct {
	ID        int64  `json:"id"`
	ProjectID int64  `json:"project_id"`
	Status    string `json:"status"`
	SHA       string `json:"sha"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type pipelineProjection struct {
	ID        int64  `json:"id"`
	Status    string `json:"status"`
	SHA       string `json:"sha"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type jobResponse struct {
	ID       int64  `json:"id"`
	Status   string `json:"status"`
	Pipeline struct {
		ID        int64  `json:"id"`
		ProjectID int64  `json:"project_id"`
		SHA       string `json:"sha"`
	} `json:"pipeline"`
	Commit struct {
		ID string `json:"id"`
	} `json:"commit"`
	CreatedAt  string `json:"created_at"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
}

type jobProjection struct {
	ID         int64  `json:"id"`
	Status     string `json:"status"`
	SHA        string `json:"sha"`
	CreatedAt  string `json:"created_at"`
	StartedAt  string `json:"started_at"`
	FinishedAt string `json:"finished_at"`
}

func New(rawURL, token string, httpClient *http.Client, budget connectors.Budget, suppliedOptions ...Option) (*Client, error) {
	options, err := resolveOptions(suppliedOptions)
	if err != nil {
		return nil, err
	}
	baseURL, err := url.Parse(rawURL)
	if err != nil || !validBaseURL(baseURL, options.allowInsecureLoopback) {
		return nil, fmt.Errorf("invalid GitLab URL")
	}
	if !validCredential(token, maxCredentialBytes) {
		return nil, fmt.Errorf("GitLab token is required")
	}
	budget = budget.WithDefaults()
	if err := budget.Validate(); err != nil {
		return nil, err
	}
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	strictHTTPClient := *httpClient
	strictHTTPClient.CheckRedirect = rejectRedirect
	strictHTTPClient.Jar = nil
	return &Client{
		baseURL:    baseURL,
		token:      token,
		httpClient: &strictHTTPClient,
		budget:     budget,
		clock:      time.Now,
	}, nil
}

func (client *Client) ListPipelines(ctx context.Context, projectID int64) (connectors.Result, error) {
	if projectID <= 0 {
		return connectors.Result{}, fmt.Errorf("positive GitLab project ID is required")
	}
	limit := min(client.budget.MaxItems, maxPageSize)
	endpoint := client.endpoint("api", "v4", "projects", strconv.FormatInt(projectID, 10), "pipelines")
	query := endpoint.Query()
	query.Set("order_by", "id")
	query.Set("page", "1")
	query.Set("per_page", strconv.Itoa(limit))
	query.Set("sort", "desc")
	endpoint.RawQuery = query.Encode()

	body, header, err := client.get(ctx, endpoint)
	if err != nil {
		return connectors.Result{}, err
	}
	var response []pipelineResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return connectors.Result{}, fmt.Errorf("decode GitLab pipelines response: %w", err)
	}
	if response == nil {
		return connectors.Result{}, fmt.Errorf("invalid GitLab pipelines response envelope")
	}
	truncated := len(response) > limit || strings.TrimSpace(header.Get("X-Next-Page")) != ""
	if len(response) > limit {
		response = response[:limit]
	}
	if err := validatePipelines(response, projectID, client.clock().UTC()); err != nil {
		return connectors.Result{}, err
	}
	items := make([]json.RawMessage, 0, len(response))
	for _, pipeline := range response {
		item, err := json.Marshal(pipelineProjection{
			ID:        pipeline.ID,
			Status:    pipeline.Status,
			SHA:       pipeline.SHA,
			CreatedAt: pipeline.CreatedAt,
			UpdatedAt: pipeline.UpdatedAt,
		})
		if err != nil {
			return connectors.Result{}, fmt.Errorf("project GitLab pipeline: %w", err)
		}
		items = append(items, item)
	}
	return client.result(items, fmt.Sprintf("pipelines project_id=%d limit=%d", projectID, limit), truncated)
}

func (client *Client) ListPipelineJobs(ctx context.Context, projectID, pipelineID int64) (connectors.Result, error) {
	if projectID <= 0 {
		return connectors.Result{}, fmt.Errorf("positive GitLab project ID is required")
	}
	if pipelineID <= 0 {
		return connectors.Result{}, fmt.Errorf("positive GitLab pipeline ID is required")
	}
	limit := min(client.budget.MaxItems, maxPageSize)
	endpoint := client.endpoint(
		"api", "v4", "projects", strconv.FormatInt(projectID, 10),
		"pipelines", strconv.FormatInt(pipelineID, 10), "jobs",
	)
	query := endpoint.Query()
	query.Set("page", "1")
	query.Set("per_page", strconv.Itoa(limit))
	endpoint.RawQuery = query.Encode()

	body, header, err := client.get(ctx, endpoint)
	if err != nil {
		return connectors.Result{}, err
	}
	var response []jobResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return connectors.Result{}, fmt.Errorf("decode GitLab pipeline jobs response: %w", err)
	}
	if response == nil {
		return connectors.Result{}, fmt.Errorf("invalid GitLab pipeline jobs response envelope")
	}
	truncated := len(response) > limit || strings.TrimSpace(header.Get("X-Next-Page")) != ""
	if len(response) > limit {
		response = response[:limit]
	}
	if err := validateJobs(response, projectID, pipelineID, client.clock().UTC()); err != nil {
		return connectors.Result{}, err
	}
	items := make([]json.RawMessage, 0, len(response))
	for _, job := range response {
		item, err := json.Marshal(jobProjection{
			ID:         job.ID,
			Status:     job.Status,
			SHA:        job.Commit.ID,
			CreatedAt:  job.CreatedAt,
			StartedAt:  job.StartedAt,
			FinishedAt: job.FinishedAt,
		})
		if err != nil {
			return connectors.Result{}, fmt.Errorf("project GitLab pipeline job: %w", err)
		}
		items = append(items, item)
	}
	return client.result(
		items,
		fmt.Sprintf("pipeline_jobs project_id=%d pipeline_id=%d limit=%d", projectID, pipelineID, limit),
		truncated,
	)
}

func (client *Client) get(ctx context.Context, endpoint url.URL) ([]byte, http.Header, error) {
	requestCtx, cancel := context.WithTimeout(ctx, client.budget.Timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, nil, fmt.Errorf("build GitLab request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("PRIVATE-TOKEN", client.token)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, nil, fmt.Errorf("query GitLab: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, nil, fmt.Errorf("GitLab returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, client.budget.MaxBytes+1))
	if err != nil {
		return nil, nil, fmt.Errorf("read GitLab response: %w", err)
	}
	if int64(len(body)) > client.budget.MaxBytes {
		return nil, nil, fmt.Errorf("GitLab response exceeds %d bytes", client.budget.MaxBytes)
	}
	return body, response.Header.Clone(), nil
}

func (client *Client) endpoint(parts ...string) url.URL {
	endpoint := *client.baseURL
	allParts := append([]string{endpoint.Path}, parts...)
	endpoint.Path = path.Join(allParts...)
	return endpoint
}

func rejectRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

func validBaseURL(baseURL *url.URL, allowInsecureLoopback bool) bool {
	if baseURL == nil || (baseURL.Scheme != "http" && baseURL.Scheme != "https") {
		return false
	}
	if baseURL.Scheme == "http" && (!allowInsecureLoopback || !isLoopbackHost(baseURL.Hostname())) {
		return false
	}
	return baseURL.Host != "" && baseURL.User == nil && baseURL.Opaque == "" &&
		baseURL.RawQuery == "" && !baseURL.ForceQuery && baseURL.Fragment == ""
}

func resolveOptions(supplied []Option) (clientOptions, error) {
	options := clientOptions{}
	for _, option := range supplied {
		if option == nil {
			return clientOptions{}, fmt.Errorf("invalid GitLab client option")
		}
		option(&options)
	}
	return options, nil
}

func isLoopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validCredential(value string, maxBytes int) bool {
	if len(value) == 0 || len(value) > maxBytes {
		return false
	}
	for index := 0; index < len(value); index++ {
		if value[index] < 0x21 || value[index] > 0x7e {
			return false
		}
	}
	return true
}

func validatePipelines(pipelines []pipelineResponse, projectID int64, now time.Time) error {
	seen := make(map[int64]struct{}, len(pipelines))
	maximumTimestamp := now.Add(maxEvidenceFutureSkew)
	for index, pipeline := range pipelines {
		createdAt, createdErr := time.Parse(time.RFC3339, pipeline.CreatedAt)
		updatedAt, updatedErr := time.Parse(time.RFC3339, pipeline.UpdatedAt)
		if pipeline.ID <= 0 || pipeline.ProjectID != projectID || !validGitLabStatus(pipeline.Status) ||
			!validCommitID(pipeline.SHA) || createdErr != nil || updatedErr != nil || updatedAt.Before(createdAt) ||
			createdAt.After(maximumTimestamp) || updatedAt.After(maximumTimestamp) {
			return fmt.Errorf("invalid GitLab pipeline response at index %d", index)
		}
		if _, duplicate := seen[pipeline.ID]; duplicate {
			return fmt.Errorf("duplicate GitLab pipeline identity at index %d", index)
		}
		seen[pipeline.ID] = struct{}{}
	}
	return nil
}

func validateJobs(jobs []jobResponse, projectID, pipelineID int64, now time.Time) error {
	seen := make(map[int64]struct{}, len(jobs))
	maximumTimestamp := now.Add(maxEvidenceFutureSkew)
	for index, job := range jobs {
		createdAt, createdErr := time.Parse(time.RFC3339, job.CreatedAt)
		startedAt, startedErr := optionalRFC3339(job.StartedAt)
		finishedAt, finishedErr := optionalRFC3339(job.FinishedAt)
		if job.ID <= 0 || job.Pipeline.ProjectID != projectID || job.Pipeline.ID != pipelineID ||
			!validGitLabStatus(job.Status) || !validCommitID(job.Commit.ID) || job.Pipeline.SHA != job.Commit.ID ||
			createdErr != nil || startedErr != nil || finishedErr != nil ||
			createdAt.After(maximumTimestamp) ||
			(job.StartedAt != "" && startedAt.Before(createdAt)) ||
			(job.StartedAt != "" && startedAt.After(maximumTimestamp)) ||
			(job.FinishedAt != "" && finishedAt.Before(createdAt)) ||
			(job.FinishedAt != "" && finishedAt.After(maximumTimestamp)) ||
			(job.StartedAt != "" && job.FinishedAt != "" && finishedAt.Before(startedAt)) ||
			(terminalGitLabStatus(job.Status) && job.FinishedAt == "") ||
			(!terminalGitLabStatus(job.Status) && job.FinishedAt != "") ||
			((job.Status == "running" || job.Status == "canceling") && job.StartedAt == "") {
			return fmt.Errorf("invalid GitLab pipeline job response at index %d", index)
		}
		if _, duplicate := seen[job.ID]; duplicate {
			return fmt.Errorf("duplicate GitLab pipeline job identity at index %d", index)
		}
		seen[job.ID] = struct{}{}
	}
	return nil
}

func validGitLabStatus(status string) bool {
	switch status {
	case "created", "waiting_for_resource", "preparing", "pending", "running", "success", "failed",
		"canceled", "canceling", "skipped", "manual", "scheduled", "waiting_for_callback":
		return true
	default:
		return false
	}
}

func validCommitID(value string) bool {
	if len(value) != 40 && len(value) != 64 {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f') || (character >= 'A' && character <= 'F')) {
			return false
		}
	}
	return true
}

func optionalRFC3339(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, value)
}

func terminalGitLabStatus(status string) bool {
	switch status {
	case "success", "failed", "canceled", "skipped":
		return true
	default:
		return false
	}
}

func (client *Client) result(items []json.RawMessage, query string, truncated bool) (connectors.Result, error) {
	projectedContent, err := json.Marshal(items)
	if err != nil {
		return connectors.Result{}, fmt.Errorf("hash GitLab projected content: %w", err)
	}
	sum := sha256.Sum256(projectedContent)
	return connectors.Result{
		Source:      "gitlab",
		Query:       query,
		CollectedAt: client.clock().UTC(),
		ItemCount:   len(items),
		ContentHash: hex.EncodeToString(sum[:]),
		Truncated:   truncated,
		Items:       items,
	}, nil
}
