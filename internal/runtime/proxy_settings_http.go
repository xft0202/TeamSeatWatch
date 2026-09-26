package runtime

import (
	"net/http"

	"github.com/teamseatwatch/teamseatwatch/internal/egress"
	"github.com/teamseatwatch/teamseatwatch/internal/generated/ownerapi"
	"github.com/teamseatwatch/teamseatwatch/internal/settings"
)

// Proxy settings are owner data, not deployment config: the owner edits them in
// the UI and a save takes effect immediately. Saving swaps the whole egress pool
// atomically, so in-flight attempts keep the exit they started on (ADR-0004).

func (h *OwnerAuthHandler) GetProxySettings(w http.ResponseWriter, r *http.Request) {
	if _, ok := h.authenticated(w, r, false); !ok {
		return
	}
	snapshot, err := h.settings.Load(r.Context())
	if err != nil {
		writeProblem(w, r, 500, "settings_unavailable", "Internal Error", "Unable to load proxy settings", 0)
		return
	}
	writeJSON(w, http.StatusOK, proxySettingsResponse(snapshot))
}

func (h *OwnerAuthHandler) SaveProxySettings(w http.ResponseWriter, r *http.Request, _ ownerapi.SaveProxySettingsParams) {
	if _, ok := h.authenticated(w, r, true); !ok {
		return
	}
	var request ownerapi.SaveProxySettingsJSONRequestBody
	if !decodeJSON(w, r, &request) {
		writeProblem(w, r, 400, "invalid_settings", "Invalid Request", "Proxy settings body is invalid", 0)
		return
	}

	keepPassword := request.KeepPassword != nil && *request.KeepPassword
	proxy := settings.Proxy{
		Provider: string(request.Provider),
		Host:     stringValue(request.Host),
		Account:  stringValue(request.Account),
		Password: stringValue(request.Password),
		Country:  stringValue(request.Country),
		State:    stringValue(request.State),
	}
	if request.Port != nil {
		proxy.Port = *request.Port
	}
	if request.SessionLifetimeMin != nil {
		proxy.SessionLifetimeMin = *request.SessionLifetimeMin
	}
	if request.AuthMode != nil {
		proxy.AuthMode = string(*request.AuthMode)
	}
	if request.Socks5List != nil {
		proxy.Socks5List = *request.Socks5List
	}

	snapshot, err := h.settings.Save(r.Context(), proxy, keepPassword)
	if err != nil {
		writeProblem(w, r, 500, "settings_save_failed", "Internal Error", "Unable to save proxy settings", 0)
		return
	}

	// Apply immediately: build the pool from the saved row and publish it.
	if err := h.rebuildEgress(r, snapshot.Proxy); err != nil {
		writeProblem(w, r, 422, "settings_apply_failed", "Proxy Not Applied", "Settings were saved but the proxy pool could not be rebuilt: "+err.Error(), 0)
		return
	}

	writeJSON(w, http.StatusOK, proxySettingsResponse(snapshot))
}

func (h *OwnerAuthHandler) rebuildEgress(r *http.Request, proxy settings.Proxy) error {
	base := egress.Config{Mode: egress.ModeDirect}
	if existing := h.egress; existing != nil {
		// Keep the probe URLs and HMAC material from the deployment baseline; only
		// the provider/endpoint choice is owner-editable.
		base = existing.BaseConfig()
	}
	config, err := settings.BuildEgressConfig(proxy, base)
	if err != nil {
		return err
	}
	if config.Mode == egress.ModeRequired {
		config = settings.FillProbeDefaults(config, h.keyRing)
	}
	router, err := egress.New(config)
	if err != nil {
		return err
	}
	admission, admitErr := router.Admit(r.Context())
	if admitErr != nil {
		// A required deployment with no usable candidate stays blocked, which is the
		// correct fail-closed outcome; the pool is still published so status shows it.
		admission = egress.Admission{Failures: nil}
	}
	leases, err := egress.NewLeaseManager(router, admission)
	if err != nil {
		router.CloseIdleConnections()
		return err
	}
	h.egress.Swap(leases, router.Status(admission))
	return nil
}

func proxySettingsResponse(snapshot settings.Snapshot) ownerapi.ProxySettings {
	passwordSet := snapshot.Proxy.PasswordSet
	response := ownerapi.ProxySettings{
		Provider:    ownerapi.ProxySettingsProvider(snapshot.Proxy.Provider),
		PasswordSet: &passwordSet,
	}
	host, account, country, state := snapshot.Proxy.Host, snapshot.Proxy.Account, snapshot.Proxy.Country, snapshot.Proxy.State
	response.Host = &host
	response.Account = &account
	response.Country = &country
	response.State = &state
	port, session := snapshot.Proxy.Port, snapshot.Proxy.SessionLifetimeMin
	response.Port = &port
	response.SessionLifetimeMin = &session
	authMode := ownerapi.ProxySettingsAuthMode(snapshot.Proxy.AuthMode)
	response.AuthMode = &authMode
	list := snapshot.Proxy.Socks5List
	response.Socks5List = &list
	updated := snapshot.UpdatedAt
	response.UpdatedAt = &updated
	return response
}
