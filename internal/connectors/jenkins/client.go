package jenkins

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
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/seaworld008/aiops-system/internal/connectors"
)

const maxBuildItems = 100
const maxUsernameBytes = 256
const maxCredentialBytes = 4096
const maxJobFullNameBytes = 512
const maxJobSegments = 16

var jobNamePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._ -]{0,127}$`)

type Client struct {
	baseURL    *url.URL
	username   string
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

type buildResponse struct {
	Number    int64  `json:"number"`
	Result    string `json:"result"`
	Building  bool   `json:"building"`
	Timestamp int64  `json:"timestamp"`
	Duration  int64  `json:"duration"`
	URL       string `json:"url"`
	Actions   []struct {
		LastBuiltRevision struct {
			SHA1 string `json:"SHA1"`
		} `json:"lastBuiltRevision"`
	} `json:"actions"`
}

type buildProjection struct {
	Number    int64  `json:"number"`
	Status    string `json:"status"`
	Revision  string `json:"revision"`
	Timestamp int64  `json:"timestamp"`
	Duration  int64  `json:"duration"`
}

func New(rawURL, username, token string, httpClient *http.Client, budget connectors.Budget, suppliedOptions ...Option) (*Client, error) {
	options, err := resolveOptions(suppliedOptions)
	if err != nil {
		return nil, err
	}
	baseURL, err := url.Parse(rawURL)
	if err != nil || !validBaseURL(baseURL, options.allowInsecureLoopback) {
		return nil, fmt.Errorf("invalid Jenkins URL")
	}
	if !validUsername(username) || !validCredential(token, maxCredentialBytes) {
		return nil, fmt.Errorf("Jenkins username and API token are required")
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
		username:   username,
		token:      token,
		httpClient: &strictHTTPClient,
		budget:     budget,
		clock:      time.Now,
	}, nil
}

func (client *Client) ListJobBuilds(ctx context.Context, jobName string) (connectors.Result, error) {
	if err := validateJobName(jobName); err != nil {
		return connectors.Result{}, err
	}
	limit := min(client.budget.MaxItems, maxBuildItems)
	endpoint := client.jobEndpoint(jobName, "api", "json")
	query := endpoint.Query()
	query.Set(
		"tree",
		fmt.Sprintf("fullName,builds[number,result,building,timestamp,duration,url,actions[lastBuiltRevision[SHA1]]]{0,%d}", limit+1),
	)
	endpoint.RawQuery = query.Encode()

	body, err := client.get(ctx, endpoint)
	if err != nil {
		return connectors.Result{}, err
	}
	var response struct {
		FullName string           `json:"fullName"`
		Builds   *[]buildResponse `json:"builds"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return connectors.Result{}, fmt.Errorf("decode Jenkins job builds response: %w", err)
	}
	if response.Builds == nil {
		return connectors.Result{}, fmt.Errorf("invalid Jenkins job builds response envelope")
	}
	builds := *response.Builds
	truncated := len(builds) > limit
	if truncated {
		builds = builds[:limit]
	}
	if response.FullName != jobName {
		return connectors.Result{}, fmt.Errorf("Jenkins job identity does not match request")
	}
	if err := client.validateBuilds(builds, jobName); err != nil {
		return connectors.Result{}, err
	}
	items, err := projectBuilds(builds)
	if err != nil {
		return connectors.Result{}, err
	}
	return client.result(items, fmt.Sprintf("job_builds job=%s limit=%d", jobName, limit), truncated)
}

func (client *Client) GetBuildStatus(ctx context.Context, jobName string, buildNumber int64) (connectors.Result, error) {
	if err := validateJobName(jobName); err != nil {
		return connectors.Result{}, err
	}
	if buildNumber <= 0 {
		return connectors.Result{}, fmt.Errorf("positive Jenkins build number is required")
	}
	endpoint := client.jobEndpoint(jobName, strconv.FormatInt(buildNumber, 10), "api", "json")
	query := endpoint.Query()
	query.Set("tree", "number,result,building,timestamp,duration,url,actions[lastBuiltRevision[SHA1]]")
	endpoint.RawQuery = query.Encode()

	body, err := client.get(ctx, endpoint)
	if err != nil {
		return connectors.Result{}, err
	}
	var response buildResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return connectors.Result{}, fmt.Errorf("decode Jenkins build status response: %w", err)
	}
	if response.Number != buildNumber {
		return connectors.Result{}, fmt.Errorf("Jenkins build identity does not match request")
	}
	if err := client.validateBuilds([]buildResponse{response}, jobName); err != nil {
		return connectors.Result{}, err
	}
	items, err := projectBuilds([]buildResponse{response})
	if err != nil {
		return connectors.Result{}, err
	}
	return client.result(
		items,
		fmt.Sprintf("build_status job=%s build=%d", jobName, buildNumber),
		false,
	)
}

func (client *Client) get(ctx context.Context, endpoint url.URL) ([]byte, error) {
	requestCtx, cancel := context.WithTimeout(ctx, client.budget.Timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, http.MethodGet, endpoint.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("build Jenkins request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.SetBasicAuth(client.username, client.token)
	response, err := client.httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("query Jenkins: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("Jenkins returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, client.budget.MaxBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read Jenkins response: %w", err)
	}
	if int64(len(body)) > client.budget.MaxBytes {
		return nil, fmt.Errorf("Jenkins response exceeds %d bytes", client.budget.MaxBytes)
	}
	return body, nil
}

func (client *Client) jobEndpoint(jobName string, suffix ...string) url.URL {
	endpoint := *client.baseURL
	pathParts := []string{"/", endpoint.Path}
	rawPathParts := []string{"/", endpoint.EscapedPath()}
	for _, segment := range strings.Split(jobName, "/") {
		pathParts = append(pathParts, "job", segment)
		rawPathParts = append(rawPathParts, "job", url.PathEscape(segment))
	}
	for _, segment := range suffix {
		pathParts = append(pathParts, segment)
		rawPathParts = append(rawPathParts, url.PathEscape(segment))
	}
	endpoint.Path = path.Join(pathParts...)
	endpoint.RawPath = path.Join(rawPathParts...)
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
			return clientOptions{}, fmt.Errorf("invalid Jenkins client option")
		}
		option(&options)
	}
	return options, nil
}

func isLoopbackHost(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func validUsername(value string) bool {
	if !validCredential(value, maxUsernameBytes) || strings.Contains(value, ":") {
		return false
	}
	return true
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

func (client *Client) result(items []json.RawMessage, query string, truncated bool) (connectors.Result, error) {
	projectedContent, err := json.Marshal(items)
	if err != nil {
		return connectors.Result{}, fmt.Errorf("hash Jenkins projected content: %w", err)
	}
	sum := sha256.Sum256(projectedContent)
	return connectors.Result{
		Source:      "jenkins",
		Query:       query,
		CollectedAt: client.clock().UTC(),
		ItemCount:   len(items),
		ContentHash: hex.EncodeToString(sum[:]),
		Truncated:   truncated,
		Items:       items,
	}, nil
}

func validateJobName(jobName string) error {
	if len(jobName) == 0 || len(jobName) > maxJobFullNameBytes {
		return fmt.Errorf("invalid Jenkins job name")
	}
	segments := strings.Split(jobName, "/")
	if len(segments) > maxJobSegments {
		return fmt.Errorf("invalid Jenkins job name")
	}
	for _, segment := range segments {
		if segment != strings.TrimSpace(segment) || !jobNamePattern.MatchString(segment) {
			return fmt.Errorf("invalid Jenkins job name")
		}
	}
	return nil
}

func projectBuilds(builds []buildResponse) ([]json.RawMessage, error) {
	items := make([]json.RawMessage, 0, len(builds))
	for _, build := range builds {
		revision, err := buildRevision(build)
		if err != nil {
			return nil, err
		}
		item, err := json.Marshal(buildProjection{
			Number:    build.Number,
			Status:    buildStatus(build),
			Revision:  revision,
			Timestamp: build.Timestamp,
			Duration:  build.Duration,
		})
		if err != nil {
			return nil, fmt.Errorf("project Jenkins build: %w", err)
		}
		items = append(items, item)
	}
	return items, nil
}

func (client *Client) validateBuilds(builds []buildResponse, jobName string) error {
	seen := make(map[int64]struct{}, len(builds))
	minimumTimestamp := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	maximumTimestamp := client.clock().UTC().Add(24 * time.Hour)
	for index, build := range builds {
		if build.Number <= 0 || build.Timestamp <= 0 || build.Duration < 0 || !validBuildState(build) {
			return fmt.Errorf("invalid Jenkins build response at index %d", index)
		}
		if build.Duration > math.MaxInt64-build.Timestamp {
			return fmt.Errorf("invalid Jenkins build response at index %d", index)
		}
		startedAt := time.UnixMilli(build.Timestamp)
		finishedAt := time.UnixMilli(build.Timestamp + build.Duration)
		if startedAt.Before(minimumTimestamp) || startedAt.After(maximumTimestamp) || finishedAt.After(maximumTimestamp) ||
			!validBuildURL(build.URL, client.baseURL, jobName, build.Number) {
			return fmt.Errorf("invalid Jenkins build response at index %d", index)
		}
		revision, revisionErr := buildRevision(build)
		if revisionErr != nil {
			return fmt.Errorf("invalid Jenkins build response at index %d", index)
		}
		if revision != "" && !validGitCommitID(revision) {
			return fmt.Errorf("invalid Jenkins build response at index %d", index)
		}
		if _, duplicate := seen[build.Number]; duplicate {
			return fmt.Errorf("duplicate Jenkins build identity at index %d", index)
		}
		seen[build.Number] = struct{}{}
	}
	return nil
}

func validBuildState(build buildResponse) bool {
	if build.Building {
		return build.Result == ""
	}
	switch build.Result {
	case "SUCCESS", "FAILURE", "UNSTABLE", "ABORTED", "NOT_BUILT":
		return true
	default:
		return false
	}
}

func validGitCommitID(value string) bool {
	if len(value) != 40 {
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

func buildStatus(build buildResponse) string {
	if build.Building {
		return "RUNNING"
	}
	if build.Result == "" {
		return "UNKNOWN"
	}
	return build.Result
}

func buildRevision(build buildResponse) (string, error) {
	revision := ""
	for _, action := range build.Actions {
		candidate := action.LastBuiltRevision.SHA1
		if candidate == "" {
			continue
		}
		if revision != "" {
			return "", fmt.Errorf("ambiguous Jenkins SCM revisions")
		}
		revision = candidate
	}
	return revision, nil
}

func validBuildURL(rawURL string, baseURL *url.URL, jobName string, buildNumber int64) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
		return false
	}
	if parsed.IsAbs() {
		if !strings.EqualFold(parsed.Scheme, baseURL.Scheme) || !strings.EqualFold(parsed.Host, baseURL.Host) {
			return false
		}
	} else if parsed.Host != "" {
		return false
	}
	want := path.Join("/", baseURL.Path, jenkinsJobPath(jobName), strconv.FormatInt(buildNumber, 10))
	got := parsed.Path
	if !parsed.IsAbs() && !strings.HasPrefix(got, "/") {
		got = path.Join("/", baseURL.Path, got)
	}
	trimmed := strings.TrimSuffix(got, "/")
	return trimmed == path.Clean(trimmed) && path.Clean(trimmed) == want
}

func jenkinsJobPath(jobName string) string {
	parts := make([]string, 0, len(strings.Split(jobName, "/"))*2)
	for _, segment := range strings.Split(jobName, "/") {
		parts = append(parts, "job", segment)
	}
	return path.Join(parts...)
}
