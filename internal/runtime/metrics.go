package runtime

import (
	"fmt"
	"net/http"
	"sync/atomic"
)

type Metrics struct {
	requests atomic.Uint64
	ready    atomic.Bool
}

func NewMetrics() *Metrics { return &Metrics{} }

func (m *Metrics) IncHTTPRequests()        { m.requests.Add(1) }
func (m *Metrics) SetReadiness(ready bool) { m.ready.Store(ready) }

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
	})
}
