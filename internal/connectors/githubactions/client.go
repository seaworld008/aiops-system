package githubactions

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
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/aiops-system/control-plane/internal/connectors"
)

const maxGitHubPageSize = 100
const maxCredentialBytes = 4096
const maxEvidenceFutureSkew = 24 * time.Hour

var workflowPathSegmentPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)
var ownerPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
var repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9._-]+$`)

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

type workflowRun struct {
	ID         int64  `json:"id"`
	WorkflowID int64  `json:"workflow_id"`
	Path       string `json:"path"`
	Repository struct {
		FullName string `json:"full_name"`
	} `json:"repository"`
	Status       string  `json:"status"`
	Conclusion   *string `json:"conclusion"`
	HeadSHA      string  `json:"head_sha"`
	CreatedAt    string  `json:"created_at"`
	UpdatedAt    string  `json:"updated_at"`
	RunStartedAt string  `json:"run_started_at"`
}

type workflowJob struct {
	ID          int64   `json:"id"`
	RunID       int64   `json:"run_id"`
	Status      string  `json:"status"`
	Conclusion  *string `json:"conclusion"`
	HeadSHA     string  `json:"head_sha"`
	StartedAt   string  `json:"started_at"`
	CompletedAt string  `json:"completed_at"`
}

type workflowRunProjection struct {
	RunID        int64   `json:"run_id"`
	WorkflowID   int64   `json:"workflow_id"`
	Status       string  `json:"status"`
	Conclusion   *string `json:"conclusion"`
	HeadSHA      string  `json:"head_sha"`
	CreatedAt    string  `json:"created_at"`
	UpdatedAt    string  `json:"updated_at"`
	RunStartedAt string  `json:"run_started_at"`
}

type workflowJobProjection struct {
	JobID       int64   `json:"job_id"`
	RunID       int64   `json:"run_id"`
	Status      string  `json:"status"`
	Conclusion  *string `json:"conclusion"`
	HeadSHA     string  `json:"head_sha"`
	StartedAt   string  `json:"started_at"`
	CompletedAt string  `json:"completed_at"`
}

func New(rawURL, token string, httpClient *http.Client, budget connectors.Budget, suppliedOptions ...Option) (*Client, error) {
	options, err := resolveOptions(suppliedOptions)
	if err != nil {
		return nil, err
	}
	baseURL, err := url.Parse(rawURL)
	if err != nil || !validBaseURL(baseURL, options.allowInsecureLoopback) {
		return nil, fmt.Errorf("invalid GitHub API URL")
	}
	if !validCredential(token, maxCredentialBytes) {
		return nil, fmt.Errorf("GitHub bearer token is required")
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

func (client *Client) ListWorkflowRuns(ctx context.Context, owner, repo string) (connectors.Result, error) {
	if err := validateRepositoryIdentity(owner, repo); err != nil {
		return connectors.Result{}, err
	}
	pageSize := min(client.budget.MaxItems, maxGitHubPageSize)
	endpoint := *client.baseURL
	endpoint.Path = path.Join(endpoint.Path, "repos", owner, repo, "actions", "runs")
	query := endpoint.Query()
	query.Set("page", "1")
	query.Set("per_page", strconv.Itoa(pageSize))
	endpoint.RawQuery = query.Encode()

	body, err := client.get(ctx, endpoint)
	if err != nil {
		return connectors.Result{}, err
	}
	var page struct {
		TotalCount   *int           `json:"total_count"`
		WorkflowRuns *[]workflowRun `json:"workflow_runs"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return connectors.Result{}, fmt.Errorf("decode GitHub Actions workflow runs response: %w", err)
	}
	if page.TotalCount == nil || page.WorkflowRuns == nil {
		return connectors.Result{}, fmt.Errorf("invalid GitHub Actions workflow runs response envelope")
	}
	runs := *page.WorkflowRuns
	if *page.TotalCount < 0 || *page.TotalCount < len(runs) || (*page.TotalCount > 0 && len(runs) == 0) {
		return connectors.Result{}, fmt.Errorf("invalid GitHub Actions workflow runs count")
	}

	truncated := *page.TotalCount > pageSize || len(runs) > pageSize
	if len(runs) > pageSize {
		runs = runs[:pageSize]
	}
	if err := validateWorkflowRuns(runs, owner, repo, "", client.clock().UTC()); err != nil {
		return connectors.Result{}, err
	}
	items, err := projectWorkflowRuns(runs)
	if err != nil {
		return connectors.Result{}, fmt.Errorf("encode GitHub Actions workflow run projection: %w", err)
	}
	return client.result(
		items,
		fmt.Sprintf("workflow_runs owner=%s repo=%s page=1 per_page=%d", owner, repo, pageSize),
		truncated,
	)
}

func (client *Client) ListWorkflowRunsByWorkflow(ctx context.Context, owner, repo, workflow string) (connectors.Result, error) {
	if err := validateRepositoryIdentity(owner, repo); err != nil {
		return connectors.Result{}, err
	}
	if err := validateWorkflowPath(workflow); err != nil {
		return connectors.Result{}, err
	}
	pageSize := min(client.budget.MaxItems, maxGitHubPageSize)
	endpoint := *client.baseURL
	baseEscapedPath := endpoint.EscapedPath()
	endpoint.Path = path.Join("/", endpoint.Path, "repos", owner, repo, "actions", "workflows", workflow, "runs")
	endpoint.RawPath = path.Join(
		"/",
		baseEscapedPath,
		"repos",
		url.PathEscape(owner),
		url.PathEscape(repo),
		"actions",
		"workflows",
		url.PathEscape(workflow),
		"runs",
	)
	query := endpoint.Query()
	query.Set("page", "1")
	query.Set("per_page", strconv.Itoa(pageSize))
	endpoint.RawQuery = query.Encode()

	body, err := client.get(ctx, endpoint)
	if err != nil {
		return connectors.Result{}, err
	}
	var page struct {
		TotalCount   *int           `json:"total_count"`
		WorkflowRuns *[]workflowRun `json:"workflow_runs"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return connectors.Result{}, fmt.Errorf("decode GitHub Actions workflow runs response: %w", err)
	}
	if page.TotalCount == nil || page.WorkflowRuns == nil {
		return connectors.Result{}, fmt.Errorf("invalid GitHub Actions workflow runs response envelope")
	}
	runs := *page.WorkflowRuns
	if *page.TotalCount < 0 || *page.TotalCount < len(runs) || (*page.TotalCount > 0 && len(runs) == 0) {
		return connectors.Result{}, fmt.Errorf("invalid GitHub Actions workflow runs count")
	}

	truncated := *page.TotalCount > pageSize || len(runs) > pageSize
	if len(runs) > pageSize {
		runs = runs[:pageSize]
	}
	if err := validateWorkflowRuns(runs, owner, repo, workflow, client.clock().UTC()); err != nil {
		return connectors.Result{}, err
	}
	items, err := projectWorkflowRuns(runs)
	if err != nil {
		return connectors.Result{}, fmt.Errorf("encode GitHub Actions workflow run projection: %w", err)
	}
	return client.result(
		items,
		fmt.Sprintf("workflow_runs owner=%s repo=%s workflow=%s page=1 per_page=%d", owner, repo, workflow, pageSize),
		truncated,
	)
}

func (client *Client) ListRunJobs(ctx context.Context, owner, repo string, runID int64) (connectors.Result, error) {
	if err := validateRepositoryIdentity(owner, repo); err != nil {
		return connectors.Result{}, err
	}
	if runID <= 0 {
		return connectors.Result{}, fmt.Errorf("positive GitHub Actions run ID is required")
	}
	pageSize := min(client.budget.MaxItems, maxGitHubPageSize)
	endpoint := *client.baseURL
	endpoint.Path = path.Join(endpoint.Path, "repos", owner, repo, "actions", "runs", strconv.FormatInt(runID, 10), "jobs")
	query := endpoint.Query()
	query.Set("page", "1")
	query.Set("per_page", strconv.Itoa(pageSize))
	endpoint.RawQuery = query.Encode()

	body, err := client.get(ctx, endpoint)
	if err != nil {
		return connectors.Result{}, err
	}
	var page struct {
		TotalCount *int           `json:"total_count"`
		Jobs       *[]workflowJob `json:"jobs"`
	}
	if err := json.Unmarshal(body, &page); err != nil {
		return connectors.Result{}, fmt.Errorf("decode GitHub Actions run jobs response: %w", err)
	}
	if page.TotalCount == nil || page.Jobs == nil {
		return connectors.Result{}, fmt.Errorf("invalid GitHub Actions run jobs response envelope")
	}
	jobs := *page.Jobs
	if *page.TotalCount < 0 || *page.TotalCount < len(jobs) || (*page.TotalCount > 0 && len(jobs) == 0) {
		return connectors.Result{}, fmt.Errorf("invalid GitHub Actions run jobs count")
	}

	truncated := *page.TotalCount > pageSize || len(jobs) > pageSize
	if len(jobs) > pageSize {
		jobs = jobs[:pageSize]
	}
	if err := validateWorkflowJobs(jobs, runID, client.clock().UTC()); err != nil {
		return connectors.Result{}, err
	}
	items, err := projectWorkflowJobs(jobs)
	if err != nil {
		return connectors.Result{}, fmt.Errorf("encode GitHub Actions run job projection: %w", err)
	}
	return client.result(
		items,
		fmt.Sprintf("run_jobs owner=%s repo=%s run_id=%d page=1 per_page=%d", owner, repo, runID, pageSize),
		truncated,
	)
}

func (client *Client) get(ctx context.Context, endpoint url.URL) ([]byte, error) {
	requestCtx, cancel := context.WithTimeout(ctx, client.budget.Timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build GitHub Actions request: %w", err)
	}
	request.Header.Set("Accept", "application/vnd.github+json")
	request.Header.Set("Authorization", "Bearer "+client.token)
	request.Header.Set("X-GitHub-Api-Version", "2026-03-10")
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("query GitHub Actions: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("GitHub Actions returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, client.budget.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read GitHub Actions response: %w", err)
	}
	if int64(len(body)) > client.budget.MaxBytes {
		return nil, fmt.Errorf("GitHub Actions response exceeds %d bytes", client.budget.MaxBytes)
	}
	return body, nil
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

func projectWorkflowRuns(runs []workflowRun) ([]json.RawMessage, error) {
	projections := make([]workflowRunProjection, 0, len(runs))
	for _, run := range runs {
		projections = append(projections, workflowRunProjection{
			RunID: run.ID, WorkflowID: run.WorkflowID, Status: run.Status, Conclusion: run.Conclusion, HeadSHA: run.HeadSHA,
			CreatedAt: run.CreatedAt, UpdatedAt: run.UpdatedAt, RunStartedAt: run.RunStartedAt,
		})
	}
	return marshalItems(projections)
}

func projectWorkflowJobs(jobs []workflowJob) ([]json.RawMessage, error) {
	projections := make([]workflowJobProjection, 0, len(jobs))
	for _, job := range jobs {
		projections = append(projections, workflowJobProjection{
			JobID: job.ID, RunID: job.RunID, Status: job.Status, Conclusion: job.Conclusion, HeadSHA: job.HeadSHA,
			StartedAt: job.StartedAt, CompletedAt: job.CompletedAt,
		})
	}
	return marshalItems(projections)
}

func validateWorkflowRuns(runs []workflowRun, owner, repo, expectedWorkflow string, now time.Time) error {
	wantRepository := owner + "/" + repo
	seen := make(map[int64]struct{}, len(runs))
	maximumTimestamp := now.Add(maxEvidenceFutureSkew)
	for index, run := range runs {
		createdAt, createdErr := time.Parse(time.RFC3339, run.CreatedAt)
		updatedAt, updatedErr := time.Parse(time.RFC3339, run.UpdatedAt)
		if run.ID <= 0 || run.WorkflowID <= 0 || !strings.EqualFold(run.Repository.FullName, wantRepository) ||
			!validGitHubState(run.Status, run.Conclusion) || !validGitCommitID(run.HeadSHA) ||
			createdErr != nil || updatedErr != nil || updatedAt.Before(createdAt) ||
			createdAt.After(maximumTimestamp) || updatedAt.After(maximumTimestamp) ||
			(expectedWorkflow != "" && !workflowPathMatches(run.Path, expectedWorkflow)) {
			return fmt.Errorf("invalid GitHub Actions workflow run response at index %d", index)
		}
		if run.RunStartedAt != "" {
			runStartedAt, err := time.Parse(time.RFC3339, run.RunStartedAt)
			if err != nil || runStartedAt.Before(createdAt) || runStartedAt.After(updatedAt) || runStartedAt.After(maximumTimestamp) {
				return fmt.Errorf("invalid GitHub Actions workflow run response at index %d", index)
			}
		} else if run.Status == "completed" {
			return fmt.Errorf("invalid GitHub Actions workflow run response at index %d", index)
		}
		if _, duplicate := seen[run.ID]; duplicate {
			return fmt.Errorf("duplicate GitHub Actions workflow run identity at index %d", index)
		}
		seen[run.ID] = struct{}{}
	}
	return nil
}

func validateWorkflowJobs(jobs []workflowJob, runID int64, now time.Time) error {
	seen := make(map[int64]struct{}, len(jobs))
	maximumTimestamp := now.Add(maxEvidenceFutureSkew)
	for index, job := range jobs {
		if job.ID <= 0 || job.RunID != runID || !validGitHubState(job.Status, job.Conclusion) || !validGitCommitID(job.HeadSHA) {
			return fmt.Errorf("invalid GitHub Actions run job response at index %d", index)
		}
		startedAt, startedErr := optionalRFC3339(job.StartedAt)
		completedAt, completedErr := optionalRFC3339(job.CompletedAt)
		if startedErr != nil || completedErr != nil ||
			(job.StartedAt != "" && startedAt.After(maximumTimestamp)) ||
			(job.CompletedAt != "" && completedAt.After(maximumTimestamp)) ||
			(job.Status == "completed" && (job.StartedAt == "" || job.CompletedAt == "" || completedAt.Before(startedAt))) ||
			(job.Status == "in_progress" && (job.StartedAt == "" || job.CompletedAt != "")) ||
			(job.Status != "completed" && job.Status != "in_progress" && (job.StartedAt != "" || job.CompletedAt != "")) {
			return fmt.Errorf("invalid GitHub Actions run job response at index %d", index)
		}
		if _, duplicate := seen[job.ID]; duplicate {
			return fmt.Errorf("duplicate GitHub Actions run job identity at index %d", index)
		}
		seen[job.ID] = struct{}{}
	}
	return nil
}

func validGitHubState(status string, conclusion *string) bool {
	switch status {
	case "queued", "in_progress", "requested", "waiting", "pending":
		return conclusion == nil
	case "completed":
		if conclusion == nil {
			return false
		}
		switch *conclusion {
		case "success", "failure", "neutral", "cancelled", "skipped", "timed_out", "action_required", "startup_failure", "stale":
			return true
		}
	}
	return false
}

func validGitCommitID(value string) bool {
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

func workflowPathMatches(responsePath, expectedWorkflow string) bool {
	if responsePath == expectedWorkflow {
		return true
	}
	return strings.HasPrefix(responsePath, expectedWorkflow+"@") && len(responsePath) > len(expectedWorkflow)+1
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
			return clientOptions{}, fmt.Errorf("invalid GitHub Actions client option")
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

func validateWorkflowPath(workflow string) error {
	if workflow == "" || len(workflow) > 255 || strings.HasPrefix(workflow, "/") || strings.HasSuffix(workflow, "/") {
		return fmt.Errorf("invalid GitHub Actions workflow path")
	}
	if strings.ContainsAny(workflow, `\%?#`) {
		return fmt.Errorf("invalid GitHub Actions workflow path")
	}
	segments := strings.Split(workflow, "/")
	for _, segment := range segments {
		if segment == "" || segment == "." || segment == ".." || !workflowPathSegmentPattern.MatchString(segment) {
			return fmt.Errorf("invalid GitHub Actions workflow path")
		}
	}
	filename := strings.ToLower(segments[len(segments)-1])
	if !strings.HasSuffix(filename, ".yml") && !strings.HasSuffix(filename, ".yaml") {
		return fmt.Errorf("invalid GitHub Actions workflow path")
	}
	return nil
}

func validateRepositoryIdentity(owner, repo string) error {
	if len(owner) == 0 || len(owner) > 39 || !ownerPattern.MatchString(owner) || strings.Contains(owner, "--") {
		return fmt.Errorf("invalid GitHub repository owner")
	}
	if len(repo) == 0 || len(repo) > 100 || repo == "." || repo == ".." || !repositoryPattern.MatchString(repo) {
		return fmt.Errorf("invalid GitHub repository name")
	}
	return nil
}

func (client *Client) result(items []json.RawMessage, query string, truncated bool) (connectors.Result, error) {
	projectedBody, err := json.Marshal(items)
	if err != nil {
		return connectors.Result{}, fmt.Errorf("encode GitHub Actions final projection: %w", err)
	}
	sum := sha256.Sum256(projectedBody)
	return connectors.Result{
		Source:      "github_actions",
		Query:       query,
		CollectedAt: client.clock().UTC(),
		ItemCount:   len(items),
		ContentHash: hex.EncodeToString(sum[:]),
		Truncated:   truncated,
		Items:       items,
	}, nil
}
