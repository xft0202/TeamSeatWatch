package runtime

import (
	"fmt"
	"net/http"
	"sort"
	"sync/atomic"

	"github.com/teamseatwatch/teamseatwatch/internal/egress"
)

type Metrics struct {
	requests                atomic.Uint64
	ready                   atomic.Bool
	queuedTasks             atomic.Int64
	runningLeases           atomic.Int64
	egressLeases            atomic.Int64
	taskSucceeded           atomic.Uint64
	taskFailed              atomic.Uint64
	retentionScheduleFailed atomic.Uint64
	egressStatus            egress.Status
}

func NewMetrics(status ...egress.Status) *Metrics {
	var egressStatus egress.Status
	if len(status) > 0 {
		egressStatus = status[0]
	}
	return &Metrics{egressStatus: egressStatus}
}

func (m *Metrics) IncHTTPRequests()        { m.requests.Add(1) }
func (m *Metrics) SetReadiness(ready bool) { m.ready.Store(ready) }
func (m *Metrics) SetTaskCounts(queued, running, egressActive int64) {
	m.queuedTasks.Store(queued)
	m.runningLeases.Store(running)
	m.egressLeases.Store(egressActive)
}
func (m *Metrics) IncTaskResult(succeeded bool) {
	if succeeded {
		m.taskSucceeded.Add(1)
	} else {
		m.taskFailed.Add(1)
	}
}

func (m *Metrics) IncRetentionScheduleFailure() { m.retentionScheduleFailed.Add(1) }

func (m *Metrics) CountRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.IncHTTPRequests()
		next.ServeHTTP(w, r)
	})
}

func (m *Metrics) Handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		value := 0
		if m.ready.Load() {
			value = 1
		}
		_, _ = fmt.Fprintf(w, "# HELP tsw_http_requests_total HTTP requests served.\n# TYPE tsw_http_requests_total counter\ntsw_http_requests_total %d\n# HELP tsw_readiness Control readiness status.\n# TYPE tsw_readiness gauge\ntsw_readiness %d\n", m.requests.Load(), value)
		// Egress metrics use fixed schemes and normalized failure classes only. Candidate
		// identities, proxy hosts, observed exits, and fingerprints are intentionally absent.
		_, _ = fmt.Fprintf(w, "# HELP tsw_egress_policy Configured egress policy.\n# TYPE tsw_egress_policy gauge\ntsw_egress_policy{policy=%q} 1\n", m.egressStatus.Policy)
		_, _ = fmt.Fprint(w, "# HELP tsw_egress_admitted_candidates Admitted proxy candidates by scheme.\n# TYPE tsw_egress_admitted_candidates gauge\n")
		for _, scheme := range []string{"http", "https", "socks5", "socks5h"} {
			_, _ = fmt.Fprintf(w, "tsw_egress_admitted_candidates{scheme=%q} %d\n", scheme, m.egressStatus.AdmittedByScheme[scheme])
		}
		_, _ = fmt.Fprintf(w, "# HELP tsw_egress_unique_exits Admitted unique public exits.\n# TYPE tsw_egress_unique_exits gauge\ntsw_egress_unique_exits %d\n", m.egressStatus.UniqueExitCount)
		_, _ = fmt.Fprint(w, "# HELP tsw_egress_validation_failures Egress validation failures by stable class.\n# TYPE tsw_egress_validation_failures gauge\n")
		failureClasses := make([]string, 0, len(m.egressStatus.FailureClasses))
		for class := range m.egressStatus.FailureClasses {
			failureClasses = append(failureClasses, class)
		}
		sort.Strings(failureClasses)
		for _, class := range failureClasses {
			_, _ = fmt.Fprintf(w, "tsw_egress_validation_failures{class=%q} %d\n", class, m.egressStatus.FailureClasses[class])
		}
		_, _ = fmt.Fprintf(w, "# HELP tsw_egress_last_validation_timestamp_seconds Last completed egress validation time.\n# TYPE tsw_egress_last_validation_timestamp_seconds gauge\ntsw_egress_last_validation_timestamp_seconds %d\n", m.egressStatus.ValidatedAt.Unix())
		// Workflow metrics are deliberately label-free and low cardinality.
		_, _ = fmt.Fprintf(w, "# HELP tsw_tasks_queued Queued durable tasks.\n# TYPE tsw_tasks_queued gauge\ntsw_tasks_queued %d\n# HELP tsw_task_leases_active Active database task leases.\n# TYPE tsw_task_leases_active gauge\ntsw_task_leases_active %d\n# HELP tsw_egress_leases_active Active in-process egress leases.\n# TYPE tsw_egress_leases_active gauge\ntsw_egress_leases_active %d\n# HELP tsw_task_results_total Settled task results.\n# TYPE tsw_task_results_total counter\ntsw_task_results_total{result=\"succeeded\"} %d\ntsw_task_results_total{result=\"failed\"} %d\n# HELP tsw_retention_schedule_failures_total Failed durable retention scheduling attempts.\n# TYPE tsw_retention_schedule_failures_total counter\ntsw_retention_schedule_failures_total %d\n", m.queuedTasks.Load(), m.runningLeases.Load(), m.egressLeases.Load(), m.taskSucceeded.Load(), m.taskFailed.Load(), m.retentionScheduleFailed.Load())
	})
}
