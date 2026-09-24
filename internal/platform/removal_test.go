package platform

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestSnapshotMembersRequiresDeclaredFullCoverage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"complete":true,"member_count":2,"members":[{"kind":"member","platform_member_id":"owner-live","identifier":"owner@example.com","status":"active","role":"owner"}]}`))
	}))
	defer server.Close()

	reader, err := NewHTTPReader(&http.Client{Transport: http.DefaultTransport, Timeout: time.Second}, server.URL, Credentials{LoginIdentifier: "owner@example.com", Password: "password"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.SnapshotMembers(context.Background(), "workspace-platform"); err == nil {
		t.Fatal("snapshot with less than 100% declared coverage must be rejected")
	}
}

func TestRemoveMemberUsesLiveMemberIDAndClassifiesResponse(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodDelete || r.URL.Path != "/backend-api/accounts/workspace-platform/users/member-live" {
			t.Fatalf("request=%s %s", r.Method, r.URL.Path)
		}
		username, password, ok := r.BasicAuth()
		if !ok || username != "owner@example.com" || password != "password" {
			t.Fatalf("basic auth=%q/%q ok=%v", username, password, ok)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true}`))
	}))
	defer server.Close()

	reader, err := NewHTTPReader(&http.Client{Transport: http.DefaultTransport, Timeout: time.Second}, server.URL, Credentials{LoginIdentifier: "owner@example.com", Password: "password"})
	if err != nil {
		t.Fatal(err)
	}
	result, err := reader.RemoveMember(context.Background(), "workspace-platform", "member-live")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Accepted || !result.RequestMayHaveEffect || result.HTTPStatus != http.StatusOK || calls.Load() != 1 {
		t.Fatalf("result=%+v calls=%d", result, calls.Load())
	}
}
