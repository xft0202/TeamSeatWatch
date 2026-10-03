package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

// sub2APIChannel migrates the reference managed OAuth reception protocol:
// explicit target/group, x-api-key, envelope code0, original owned marker,
// preflight identity check, single-attempt POST and read-only unknown recovery.
// The reference endpoint provides no customer order or final ZIP receipt.
type sub2APIChannel struct{ client *http.Client }

func NewSub2APIChannel(config Sub2APIProbeConfig) ChannelDeliveryAdapter {
	probe := NewSub2APIProbe(config).(sub2APIProbe)
	return sub2APIChannel{client: probe.client}
}
func channelMarker(d ChannelDestination, o ChannelObject) string {
	return rotationHash([]any{"tsw.channel.oauth.v1", d.ID, d.Revision, d.Endpoint, d.Group, o.PackageID, o.PackageDigest, o.AccountID, o.SlotID, o.WorkspaceID})
}
func channelRemoteName(o ChannelObject) string {
	return "tsw-channel-" + o.PackageID.String() + "-" + o.AccountID.String()
}
func (a sub2APIChannel) request(ctx context.Context, d ChannelDestination, method, path string, payload []byte, beforeWrite func(context.Context) error) (json.RawMessage, error) {
	if _, ok := validSub2APIBase(d.Endpoint); !ok {
		return nil, errChannelPending
	}
	group, e := strconv.ParseInt(d.Group, 10, 64)
	if e != nil || group <= 0 || d.Secret == "" {
		return nil, errChannelPending
	}
	req, e := http.NewRequestWithContext(ctx, method, d.Endpoint+path, bytes.NewReader(payload))
	if e != nil {
		return nil, e
	}
	req.Header.Set("x-api-key", d.Secret)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if method != http.MethodGet {
		if beforeWrite == nil {
			return nil, errChannelPending
		}
		if e = ctx.Err(); e != nil {
			return nil, e
		}
		// Request construction and every read-only preflight are complete. The
		// caller records its durable attempt immediately before external I/O.
		if e = beforeWrite(ctx); e != nil {
			return nil, e
		}
	}
	resp, e := a.client.Do(req)
	if e != nil {
		return nil, errChannelPending
	}
	defer resp.Body.Close()
	media, _, e := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 || e != nil || media != "application/json" {
		return nil, errChannelPending
	}
	raw, e := io.ReadAll(io.LimitReader(resp.Body, 4<<20+1))
	if e != nil || len(raw) > 4<<20 {
		return nil, errChannelPending
	}
	defer clear(raw)
	var envelope struct {
		Code *int            `json:"code"`
		Data json.RawMessage `json:"data"`
	}
	if e = json.Unmarshal(raw, &envelope); e != nil || envelope.Code == nil || *envelope.Code != 0 || len(envelope.Data) == 0 {
		return nil, errChannelPending
	}
	return envelope.Data, nil
}

type channelRemoteAccount struct {
	ID          json.Number `json:"id"`
	Name        string      `json:"name"`
	Platform    string      `json:"platform"`
	Type        string      `json:"type"`
	Credentials struct {
		Email     string `json:"email"`
		Workspace string `json:"chatgpt_account_id"`
	} `json:"credentials"`
	Groups []int64                    `json:"group_ids"`
	Extra  map[string]json.RawMessage `json:"extra"`
}

func (a sub2APIChannel) readAccounts(ctx context.Context, d ChannelDestination, identifier string) ([]channelRemoteAccount, error) {
	// The query is identity-specific, but every returned match must be read and
	// checked; an incomplete page is never evidence of remote absence/ownership.
	raw, e := a.request(ctx, d, http.MethodGet, "/admin/accounts?page=1&page_size=100&search="+url.QueryEscape(identifier), nil, nil)
	if e != nil {
		return nil, e
	}
	defer clear(raw)
	var page struct {
		Items []channelRemoteAccount `json:"items"`
		Total *int                   `json:"total"`
		Page  *int                   `json:"page"`
		Size  *int                   `json:"page_size"`
	}
	if e = json.Unmarshal(raw, &page); e != nil || page.Total == nil || page.Page == nil || page.Size == nil || *page.Page != 1 || *page.Size != 100 || *page.Total != len(page.Items) {
		return nil, errChannelPending
	}
	return page.Items, nil
}
func (a sub2APIChannel) Inspect(ctx context.Context, d ChannelDestination, o ChannelObject) (ChannelReception, error) {
	accounts, e := a.readAccounts(ctx, d, o.Identifier)
	if e != nil {
		return ChannelReception{}, e
	}
	var found ChannelReception
	group, _ := strconv.ParseInt(d.Group, 10, 64)
	for _, r := range accounts {
		if r.Name != channelRemoteName(o) && !(r.Credentials.Email == o.Identifier && r.Credentials.Workspace == o.WorkspaceID) {
			continue
		}
		var marker string
		_ = json.Unmarshal(r.Extra["tsw_channel_delivery"], &marker)
		id, e := strconv.ParseInt(string(r.ID), 10, 64)
		if e != nil || id <= 0 || r.Name != channelRemoteName(o) || r.Platform != "openai" || r.Type != "oauth" || r.Credentials.Email != o.Identifier || r.Credentials.Workspace != o.WorkspaceID || marker != channelMarker(d, o) || len(r.Groups) != 1 || r.Groups[0] != group || found.RemoteObjectID != "" {
			return ChannelReception{}, errChannelPending
		}
		found = ChannelReception{RemoteObjectID: strconv.FormatInt(id, 10), ReceiptID: "sub2api-account/" + strconv.FormatInt(id, 10), ObservedAt: time.Now().UTC()}
	}
	if found.RemoteObjectID == "" {
		return found, errChannelPending
	}
	return found, nil
}
func (a sub2APIChannel) Receive(ctx context.Context, d ChannelDestination, o ChannelObject, beforeWrite func(context.Context) error) (ChannelReception, error) {
	// Existing identities never authorize adoption/update. Only an exact owned
	// original marker may be reconciled; otherwise create must fail closed.
	if old, e := a.Inspect(ctx, d, o); e == nil {
		return old, nil
	}
	// A separate complete read establishes authoritative absence before create.
	accounts, e := a.readAccounts(ctx, d, o.Identifier)
	if e != nil {
		return ChannelReception{}, e
	}
	for _, r := range accounts {
		if r.Name == channelRemoteName(o) || r.Credentials.Email == o.Identifier && r.Credentials.Workspace == o.WorkspaceID {
			return ChannelReception{}, errChannelPending
		}
	}
	var payload map[string]any
	if json.Unmarshal(o.OAuth, &payload) != nil {
		return ChannelReception{}, errChannelPending
	}
	creds, ok := payload["credentials"].(map[string]any)
	if !ok {
		return ChannelReception{}, errChannelPending
	}
	for _, k := range []string{"access_token", "refresh_token", "id_token"} {
		v, ok := creds[k].(string)
		if !ok || v == "" {
			return ChannelReception{}, errChannelPending
		}
	}
	group, e := strconv.ParseInt(d.Group, 10, 64)
	if e != nil || group <= 0 {
		return ChannelReception{}, errChannelPending
	}
	payload["name"] = channelRemoteName(o)
	payload["group_ids"] = []int64{group}
	extra, ok := payload["extra"].(map[string]any)
	if !ok {
		extra = map[string]any{}
	}
	extra["tsw_channel_delivery"] = channelMarker(d, o)
	payload["extra"] = extra
	body, e := json.Marshal(payload)
	if e != nil {
		return ChannelReception{}, e
	}
	defer clear(body)
	response, e := a.request(ctx, d, http.MethodPost, "/admin/accounts", body, beforeWrite)
	if e != nil {
		return ChannelReception{}, e
	}
	defer clear(response)
	var result struct {
		ID json.Number `json:"id"`
	}
	if json.Unmarshal(response, &result) != nil {
		return ChannelReception{}, errChannelPending
	}
	id, e := strconv.ParseInt(string(result.ID), 10, 64)
	if e != nil || id <= 0 {
		return ChannelReception{}, errChannelPending
	}
	// Response ID alone is insufficient to adopt ownership. Confirm the original
	// marker, target and account through a read before committing reception.
	received, e := a.Inspect(ctx, d, o)
	if e != nil || received.RemoteObjectID != strconv.FormatInt(id, 10) {
		return ChannelReception{}, errChannelPending
	}
	return received, nil
}
func (sub2APIChannel) AuthorizeZIP(context.Context, ChannelDestination, []ChannelObject) (BatchZIPRecipient, error) {
	return BatchZIPRecipient{}, errChannelFinalUnavailable
}
func (sub2APIChannel) DeliverZIP(context.Context, ChannelDestination, []ChannelObject, BatchZIPRecipient, string, []byte, func(context.Context) error) ([]ChannelFinalReceipt, error) {
	return nil, errChannelFinalUnavailable
}
func (sub2APIChannel) InspectZIP(context.Context, ChannelDestination, []ChannelObject, BatchZIPRecipient) ([]ChannelFinalReceipt, error) {
	return nil, errChannelFinalUnavailable
}

var _ ChannelDeliveryAdapter = sub2APIChannel{}
