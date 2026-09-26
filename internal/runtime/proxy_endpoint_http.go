package runtime

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/teamseatwatch/teamseatwatch/internal/generated/ownerapi"
)

// Proxy endpoint CRUD（规格书 §7 扩展：Owner 直接管理代理端点）。
// 端点是完整 URL（socks5://user:pass@host:port 或 http://host:port），
// 探测返回国家/州信息。地址和认证是 Owner 主动输入的业务数据，不是部署秘密。

type proxyEndpointDTO = ownerapi.ProxyEndpoint

func (h *OwnerAuthHandler) ListProxyEndpoints(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	rows, err := h.pool.Query(r.Context(), `
		SELECT id, url, label, country, region, status, verified_at, created_at, updated_at
		FROM tsw_proxy_endpoints
		ORDER BY created_at DESC
	`)
	if err != nil {
		writeProblem(w, r, 500, "proxy_endpoint_list_failed", "Internal Error", "Unable to list proxy endpoints", 0)
		return
	}
	defer rows.Close()

	items := make([]proxyEndpointDTO, 0)
	for rows.Next() {
		var item proxyEndpointDTO
		var verifiedAt *time.Time
		if err := rows.Scan(&item.Id, &item.Url, &item.Label, &item.Country, &item.Region, &item.Status, &verifiedAt, &item.CreatedAt, &item.UpdatedAt); err != nil {
			writeProblem(w, r, 500, "proxy_endpoint_scan_failed", "Internal Error", "Unable to scan proxy endpoint", 0)
			return
		}
		if verifiedAt != nil {
			item.VerifiedAt = verifiedAt
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, ownerapi.ProxyEndpointList{Items: items})
}

func (h *OwnerAuthHandler) CreateProxyEndpoint(w http.ResponseWriter, r *http.Request, _ ownerapi.CreateProxyEndpointParams) {
	if _, ok := h.authenticated(w, r, true); !ok {
		return
	}
	var request ownerapi.CreateProxyEndpointJSONRequestBody
	if !decodeJSON(w, r, &request) {
		writeProblem(w, r, 400, "invalid_proxy_endpoint", "Invalid Request", "Proxy endpoint body is invalid", 0)
		return
	}

	parsed, err := url.Parse(request.Url)
	if err != nil || parsed.Host == "" {
		writeProblem(w, r, 400, "invalid_proxy_url", "Invalid Request", "Proxy URL must be a valid URL with a host", 0)
		return
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" && scheme != "socks5" && scheme != "socks5h" {
		writeProblem(w, r, 400, "invalid_proxy_scheme", "Invalid Request", "Proxy URL scheme must be http, https, socks5, or socks5h", 0)
		return
	}

	label := ""
	if request.Label != nil {
		label = *request.Label
	}

	var id uuid.UUID
	err = h.pool.QueryRow(r.Context(), `
		INSERT INTO tsw_proxy_endpoints (url, label)
		VALUES ($1, $2)
		RETURNING id
	`, request.Url, label).Scan(&id)
	if err != nil {
		writeProblem(w, r, 500, "proxy_endpoint_create_failed", "Internal Error", "Unable to create proxy endpoint", 0)
		return
	}

	labelPtr := &label
	writeJSON(w, http.StatusCreated, proxyEndpointDTO{
		Id:        id,
		Url:       request.Url,
		Label:     labelPtr,
		Status:    "pending",
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	})
}

func (h *OwnerAuthHandler) DeleteProxyEndpoint(w http.ResponseWriter, r *http.Request, endpointId ownerapi.EndpointId, _ ownerapi.DeleteProxyEndpointParams) {
	if _, ok := h.authenticated(w, r, true); !ok {
		return
	}
	result, err := h.pool.Exec(r.Context(), `DELETE FROM tsw_proxy_endpoints WHERE id = $1`, endpointId)
	if err != nil {
		writeProblem(w, r, 500, "proxy_endpoint_delete_failed", "Internal Error", "Unable to delete proxy endpoint", 0)
		return
	}
	if result.RowsAffected() == 0 {
		writeProblem(w, r, 404, "proxy_endpoint_not_found", "Not Found", "Proxy endpoint not found", 0)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *OwnerAuthHandler) VerifyProxyEndpoint(w http.ResponseWriter, r *http.Request, endpointId ownerapi.EndpointId, _ ownerapi.VerifyProxyEndpointParams) {
	if _, ok := h.authenticated(w, r, true); !ok {
		return
	}

	var endpointURL string
	err := h.pool.QueryRow(r.Context(), `SELECT url FROM tsw_proxy_endpoints WHERE id = $1`, endpointId).Scan(&endpointURL)
	if err != nil {
		writeProblem(w, r, 404, "proxy_endpoint_not_found", "Not Found", "Proxy endpoint not found", 0)
		return
	}

	country, region, verifyErr := h.probeEndpointRegion(r.Context(), endpointURL)
	now := time.Now().UTC()
	status := "verified"
	if verifyErr != nil {
		status = "failed"
	}

	_, err = h.pool.Exec(r.Context(), `
		UPDATE tsw_proxy_endpoints
		SET country = $1, region = $2, status = $3, verified_at = $4, updated_at = $5
		WHERE id = $6
	`, country, region, status, now, now, endpointId)
	if err != nil {
		writeProblem(w, r, 500, "proxy_endpoint_verify_failed", "Internal Error", "Unable to update proxy endpoint", 0)
		return
	}

	var item proxyEndpointDTO
	_ = h.pool.QueryRow(r.Context(), `
		SELECT id, url, label, country, region, status, verified_at, created_at, updated_at
		FROM tsw_proxy_endpoints WHERE id = $1
	`, endpointId).Scan(&item.Id, &item.Url, &item.Label, &item.Country, &item.Region, &item.Status, &item.VerifiedAt, &item.CreatedAt, &item.UpdatedAt)

	if verifyErr != nil {
		writeProblem(w, r, 502, "proxy_probe_failed", "Proxy Unreachable", "Unable to probe the proxy endpoint: "+verifyErr.Error(), 0)
		return
	}
	writeJSON(w, http.StatusOK, item)
}

// probeEndpointRegion creates a transport for the given proxy URL,
// calls the IP echo endpoint, and returns the detected country and region.
func (h *OwnerAuthHandler) probeEndpointRegion(ctx context.Context, rawURL string) (string, string, error) {
	_ = ctx // probe uses a short timeout; context cancellation handled by caller
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", "", err
	}

	transport := &http.Transport{}
	switch strings.ToLower(parsed.Scheme) {
	case "http", "https":
		transport.Proxy = http.ProxyURL(parsed)
	case "socks5", "socks5h":
		// SOCKS5 needs the proxy package; for now return an error
		return "", "", &url.Error{Op: "probe", URL: rawURL, Err: http.ErrNotSupported}
	default:
		return "", "", &url.Error{Op: "probe", URL: rawURL, Err: http.ErrNotSupported}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   10 * time.Second,
	}

	// Call the IP echo service to get the exit IP
	resp, err := client.Get("https://httpbin.org/ip")
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", &url.Error{Op: "probe", URL: rawURL, Err: errors.New("non-200 from IP echo")}
	}

	// Parse the JSON response to extract the IP
	var ipResp struct {
		Origin string `json:"origin"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&ipResp); err != nil {
		return "", "", err
	}

	// Use ipinfo.io for country/region lookup
	geoURL := "https://ipinfo.io/" + ipResp.Origin + "/json"
	geoResp, err := client.Get(geoURL)
	if err != nil {
		return ipResp.Origin, "", err
	}
	defer geoResp.Body.Close()

	var geo struct {
		Country string `json:"country"`
		Region  string `json:"region"`
	}
	_ = json.NewDecoder(geoResp.Body).Decode(&geo)

	return geo.Country, geo.Region, nil
}
