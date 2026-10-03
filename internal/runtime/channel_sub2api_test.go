package runtime

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type channelWireMock struct {
	accounts   []map[string]any
	posts      int
	timeout    bool
	getFailure bool
	paths      []string
}

func (m *channelWireMock) RoundTrip(r *http.Request) (*http.Response, error) {
	m.paths = append(m.paths, r.Method+" "+r.URL.Path)
	if r.Header.Get("x-api-key") != "channel-key" || r.URL.Host != "hub.fixture.test" {
		return nil, errChannelPending
	}
	var data any
	if r.Method == "POST" {
		m.posts++
		raw, _ := io.ReadAll(r.Body)
		var account map[string]any
		if json.Unmarshal(raw, &account) != nil {
			return nil, errChannelPending
		}
		account["id"] = 17
		m.accounts = append(m.accounts, account)
		if m.timeout {
			return nil, errChannelPending
		}
		data = map[string]any{"id": 17}
	} else {
		if m.getFailure {
			return nil, errChannelPending
		}
		data = map[string]any{"items": m.accounts, "total": len(m.accounts), "page": 1, "page_size": 100}
	}
	raw, _ := json.Marshal(map[string]any{"code": 0, "data": data})
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(string(raw)))}, nil
}
func TestChannelSub2APIPreparationFailureDoesNotStartAttempt(t *testing.T) {
	d, o := channelWireObject()
	wire := &channelWireMock{accounts: []map[string]any{}, getFailure: true}
	adapter := sub2APIChannel{client: &http.Client{Transport: wire}}
	attempted := false
	beforeWrite := func(context.Context) error {
		attempted = true
		return nil
	}
	if _, e := adapter.Receive(context.Background(), d, o, beforeWrite); e == nil || attempted || wire.posts != 0 {
		t.Fatal("read-only failure started attempt", e, attempted, wire.posts)
	}
	wire.getFailure = false
	if _, e := adapter.Receive(context.Background(), d, o, beforeWrite); e != nil || !attempted || wire.posts != 1 {
		t.Fatal("original preparation could not continue", e, attempted, wire.posts)
	}
}
func channelWireObject() (ChannelDestination, ChannelObject) {
	d := ChannelDestination{ID: uuid.New(), Revision: 1, Endpoint: "https://hub.fixture.test/api/v1", Group: "42", Secret: "channel-key"}
	o := ChannelObject{PackageID: uuid.New(), AccountID: uuid.New(), SlotID: uuid.New(), PackageDigest: strings.Repeat("a", 64), WorkspaceID: "target-workspace", Identifier: "account@fixture.test", OAuth: json.RawMessage(`{"platform":"openai","type":"oauth","credentials":{"email":"account@fixture.test","chatgpt_account_id":"target-workspace","access_token":"fixture-at","refresh_token":"fixture-rt","id_token":"fixture-idt","model_mapping":{}}}`)}
	return d, o
}
func TestChannelSub2APIProductionReceiveAndOwnedRecovery(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "uncertain"}[timeout], func(t *testing.T) {
			d, o := channelWireObject()
			wire := &channelWireMock{accounts: []map[string]any{}, timeout: timeout}
			adapter := sub2APIChannel{client: &http.Client{Transport: wire}}
			fenceCalls := 0
			received, e := adapter.Receive(context.Background(), d, o, func(context.Context) error { fenceCalls++; return nil })
			if !timeout && (e != nil || received.RemoteObjectID != "17") || timeout && e == nil {
				t.Fatal(received, e)
			}
			if wire.posts != 1 || fenceCalls != 1 {
				t.Fatal(wire.posts, fenceCalls)
			}
			recovered, e := adapter.Inspect(context.Background(), d, o)
			if e != nil || recovered.RemoteObjectID != "17" || recovered.ObservedAt.Before(time.Now().Add(-time.Minute)) {
				t.Fatal(recovered, e)
			}
			if _, e = adapter.Receive(context.Background(), d, o, func(context.Context) error { return nil }); e != nil || wire.posts != 1 {
				t.Fatal("owned object duplicated", e, wire.posts)
			}
			if _, e = adapter.AuthorizeZIP(context.Background(), d, []ChannelObject{o}); e != errChannelFinalUnavailable {
				t.Fatal("HTTP2xx invented final customer")
			}
			payload := wire.accounts[0]
			if payload["name"] != channelRemoteName(o) {
				t.Fatal("wrong owned marker")
			}
			if _, ok := payload["password"]; ok {
				t.Fatal("full materials pushed")
			}
			groups := payload["group_ids"].([]any)
			if len(groups) != 1 || groups[0] != float64(42) {
				t.Fatal("target fallback")
			}
		})
	}
}
func TestChannelSub2APIForeignIdentityAndFenceNeverCreate(t *testing.T) {
	for _, mode := range []string{"foreign", "fence", "missing_refresh", "invalid_group"} {
		t.Run(mode, func(t *testing.T) {
			d, o := channelWireObject()
			wire := &channelWireMock{accounts: []map[string]any{}}
			fence := func(context.Context) error { return nil }
			switch mode {
			case "foreign":
				wire.accounts = append(wire.accounts, map[string]any{"id": 17, "name": "external", "platform": "openai", "type": "oauth", "credentials": map[string]any{"email": o.Identifier, "chatgpt_account_id": o.WorkspaceID}, "group_ids": []int64{42}, "extra": map[string]any{}})
			case "fence":
				fence = func(context.Context) error { return errChannelPending }
			case "missing_refresh":
				o.OAuth = json.RawMessage(`{"credentials":{"access_token":"at","id_token":"idt"}}`)
			case "invalid_group":
				d.Group = "0"
			}
			adapter := sub2APIChannel{client: &http.Client{Transport: wire}}
			if _, e := adapter.Receive(context.Background(), d, o, fence); e == nil || wire.posts != 0 {
				t.Fatal("unauthorized POST", wire.posts, e)
			}
		})
	}
}
