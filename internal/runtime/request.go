package runtime

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"
)

type requestIDKey struct{}
type correlationIDKey struct{}

func NewRequestMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			requestID := r.Header.Get(requestIDHeader)
			if !validRequestID(requestID) {
				var err error
				requestID, err = newOpaqueID()
				if err != nil {
					http.Error(w, "internal server error", http.StatusInternalServerError)
					return
				}
			}
			correlationID, err := newOpaqueID()
			if err != nil {
				http.Error(w, "internal server error", http.StatusInternalServerError)
				return
			}
			ctx := context.WithValue(r.Context(), requestIDKey{}, requestID)
			ctx = context.WithValue(ctx, correlationIDKey{}, correlationID)
			r = r.WithContext(ctx)
			w.Header().Set(requestIDHeader, requestID)

			recorder := &statusRecorder{ResponseWriter: w}
			started := time.Now()
			next.ServeHTTP(recorder, r)
			pattern := r.Pattern
			if pattern == "" {
				pattern = "unmatched"
			}
			logger.Info("http_request",
				"request_id", requestID,
				"correlation_id", correlationID,
				"method", r.Method,
				"path", pattern,
				"status", recorder.status(),
				"duration_ms", time.Since(started).Milliseconds(),
			)
		})
	}
}

func RequestIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(requestIDKey{}).(string)
	return value
}

func CorrelationIDFromContext(ctx context.Context) string {
	value, _ := ctx.Value(correlationIDKey{}).(string)
	return value
}

func validRequestID(value string) bool {
	if value == "" || len(value) > maxRequestIDLength {
		return false
	}
	for _, char := range value {
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') && (char < '0' || char > '9') && char != '-' && char != '_' && char != '.' {
			return false
		}
	}
	return true
}

func newOpaqueID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "tsw_" + hex.EncodeToString(raw[:]), nil
}

type statusRecorder struct {
	http.ResponseWriter
	written bool
	code    int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.written = true
	r.code = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(body []byte) (int, error) {
	if !r.written {
		r.WriteHeader(http.StatusOK)
	}
	return r.ResponseWriter.Write(body)
}

func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *statusRecorder) status() int {
	if !r.written {
		return http.StatusOK
	}
	return r.code
}
