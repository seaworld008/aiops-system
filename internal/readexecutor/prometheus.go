package readexecutor

import (
	"encoding/json"
	"math"
	"sort"
	"strconv"
	"time"

	"github.com/seaworld008/aiops-system/internal/readconnector"
	"github.com/seaworld008/aiops-system/internal/readtask"
)

type prometheusResponseEnvelope struct {
	Status   string          `json:"status"`
	Data     json.RawMessage `json:"data"`
	Warnings json.RawMessage `json:"warnings,omitempty"`
	Infos    json.RawMessage `json:"infos,omitempty"`
}

type prometheusResponseData struct {
	ResultType string            `json:"resultType"`
	Result     []json.RawMessage `json:"result"`
}

type prometheusMatrixSeries struct {
	Metric     map[string]string `json:"metric"`
	Values     []json.RawMessage `json:"values"`
	Histograms json.RawMessage   `json:"histograms,omitempty"`
}

type prometheusMetricLabel struct {
	name  string
	value string
}

func parsePrometheusResponse(
	body []byte,
	execution readconnector.ExecutionSpec,
	collectedAt time.Time,
) (readtask.EvidenceCompletion, responseFailure) {
	query, ok := execution.PrometheusRangeQuery()
	if !ok || execution.Lookback() <= 0 || query.Step() <= 0 || query.MaxItems() <= 0 || query.MaxSamples() <= 0 {
		return readtask.EvidenceCompletion{}, responseRejected
	}
	if len(body) == 0 {
		return readtask.EvidenceCompletion{}, responseInvalid
	}
	if len(body) > MaximumUpstreamResponseBytes {
		return readtask.EvidenceCompletion{}, responseRejected
	}

	var envelope prometheusResponseEnvelope
	if !strictDecodeJSONObject(body, &envelope) || envelope.Status != "success" || len(envelope.Data) == 0 {
		return readtask.EvidenceCompletion{}, responseInvalid
	}
	if failure := prometheusAnnotationsFailure(envelope.Warnings, envelope.Infos); failure != responseAccepted {
		return readtask.EvidenceCompletion{}, failure
	}

	var data prometheusResponseData
	if !strictDecodeJSONObject(envelope.Data, &data) || data.ResultType != "matrix" || data.Result == nil {
		return readtask.EvidenceCompletion{}, responseInvalid
	}
	if len(data.Result) > query.MaxItems() {
		return readtask.EvidenceCompletion{}, responseRejected
	}

	items := make([]json.RawMessage, 0, len(data.Result))
	var previousMetric []prometheusMetricLabel
	for _, encodedSeries := range data.Result {
		var series prometheusMatrixSeries
		if !strictDecodeJSONObject(encodedSeries, &series) || series.Metric == nil || series.Values == nil {
			return readtask.EvidenceCompletion{}, responseInvalid
		}
		if series.Histograms != nil {
			return readtask.EvidenceCompletion{}, responseRejected
		}
		metricIdentity := prometheusMetricIdentity(series.Metric)
		if previousMetric != nil && comparePrometheusMetrics(previousMetric, metricIdentity) >= 0 {
			return readtask.EvidenceCompletion{}, responseRejected
		}
		previousMetric = metricIdentity
		if failure := prometheusSampleGridFailure(series.Values, collectedAt, execution.Lookback(), query.Step()); failure != responseAccepted {
			return readtask.EvidenceCompletion{}, failure
		}
		canonical, valid := canonicalJSONObject(encodedSeries)
		if !valid {
			return readtask.EvidenceCompletion{}, responseInvalid
		}
		items = append(items, json.RawMessage(canonical))
	}

	evidence := readtask.EvidenceCompletion{CollectedAt: collectedAt, Items: items}
	if execution.ValidateEvidence(evidence) != nil || !evidenceFitsProjectionBudget(evidence) {
		return readtask.EvidenceCompletion{}, responseRejected
	}
	return evidence, responseAccepted
}

func prometheusMetricIdentity(metric map[string]string) []prometheusMetricLabel {
	identity := make([]prometheusMetricLabel, 0, len(metric))
	for name, value := range metric {
		identity = append(identity, prometheusMetricLabel{name: name, value: value})
	}
	sort.Slice(identity, func(left, right int) bool {
		if identity[left].name != identity[right].name {
			return identity[left].name < identity[right].name
		}
		return identity[left].value < identity[right].value
	})
	return identity
}

func comparePrometheusMetrics(left, right []prometheusMetricLabel) int {
	limit := min(len(left), len(right))
	for index := range limit {
		switch {
		case left[index].name < right[index].name:
			return -1
		case left[index].name > right[index].name:
			return 1
		case left[index].value < right[index].value:
			return -1
		case left[index].value > right[index].value:
			return 1
		}
	}
	switch {
	case len(left) < len(right):
		return -1
	case len(left) > len(right):
		return 1
	default:
		return 0
	}
}

func prometheusSampleGridFailure(
	values []json.RawMessage,
	collectedAt time.Time,
	lookback time.Duration,
	step time.Duration,
) responseFailure {
	if collectedAt.IsZero() || lookback <= 0 || step <= 0 {
		return responseRejected
	}
	start := collectedAt.Add(-lookback)
	startSeconds := float64(start.Unix()) + float64(start.Nanosecond())/float64(time.Second)
	endSeconds := float64(collectedAt.Unix()) + float64(collectedAt.Nanosecond())/float64(time.Second)
	stepSeconds := step.Seconds()
	toleranceSeconds := time.Millisecond.Seconds()
	previous := math.Inf(-1)
	for _, raw := range values {
		var pair []json.RawMessage
		if json.Unmarshal(raw, &pair) != nil || len(pair) != 2 || len(pair[0]) == 0 || pair[0][0] == '"' {
			return responseInvalid
		}
		timestamp, err := strconv.ParseFloat(string(pair[0]), 64)
		if err != nil || math.IsNaN(timestamp) || math.IsInf(timestamp, 0) {
			return responseInvalid
		}
		if timestamp <= previous {
			return responseRejected
		}
		previous = timestamp
		if timestamp < startSeconds-toleranceSeconds || timestamp > endSeconds+toleranceSeconds {
			return responseRejected
		}
		ratio := (timestamp - startSeconds) / stepSeconds
		if nearest := math.Round(ratio); nearest < 0 || math.Abs(ratio-nearest) > toleranceSeconds/stepSeconds {
			return responseRejected
		}
	}
	return responseAccepted
}

func prometheusAnnotationsFailure(encoded ...json.RawMessage) responseFailure {
	for _, raw := range encoded {
		if raw == nil {
			continue
		}
		var values []string
		if json.Unmarshal(raw, &values) != nil || values == nil {
			return responseInvalid
		}
		if len(values) != 0 {
			return responseRejected
		}
	}
	return responseAccepted
}
