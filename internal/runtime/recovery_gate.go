package runtime

import (
	"net/http"

	"github.com/teamseatwatch/teamseatwatch/internal/generated/internalapi"
)

// recoveryGateAPI keeps restored databases closed to all public operations until
// the Owner has run the retention check and explicitly opened the gate.
type recoveryGateAPI struct {
	*PublicRedeemHandler
}

var _ internalapi.ServerInterface = (*recoveryGateAPI)(nil)

func (h *recoveryGateAPI) gate(w http.ResponseWriter, r *http.Request) bool {
	var state string
	if err := h.pool.QueryRow(r.Context(), `SELECT state FROM tsw_recovery_gate WHERE id=true`).Scan(&state); err != nil {
		writeProblem(w, r, http.StatusServiceUnavailable, "recovery_gate_unavailable", "Service Unavailable", "Recovery checks are temporarily unavailable", 0)
		return false
	}
	if state != "open" {
		writeProblem(w, r, http.StatusServiceUnavailable, "recovery_gate_closed", "Service Unavailable", "Recovery verification is in progress", 0)
		return false
	}
	return true
}

func (h *recoveryGateAPI) GetPrivateHealth(w http.ResponseWriter, r *http.Request) {
	h.PublicRedeemHandler.GetPrivateHealth(w, r)
}
func (h *recoveryGateAPI) ConfirmPublicRedeem(w http.ResponseWriter, r *http.Request) {
	if h.gate(w, r) {
		h.PublicRedeemHandler.ConfirmPublicRedeem(w, r)
	}
}
func (h *recoveryGateAPI) CheckPublicRedeemCredentialStatus(w http.ResponseWriter, r *http.Request) {
	if h.gate(w, r) {
		h.PublicRedeemHandler.CheckPublicRedeemCredentialStatus(w, r)
	}
}
func (h *recoveryGateAPI) DownloadPublicRedeemDelivery(w http.ResponseWriter, r *http.Request) {
	if h.gate(w, r) {
		h.PublicRedeemHandler.DownloadPublicRedeemDelivery(w, r)
	}
}
func (h *recoveryGateAPI) RequestPublicRedeemReclaim(w http.ResponseWriter, r *http.Request) {
	if h.gate(w, r) {
		h.PublicRedeemHandler.RequestPublicRedeemReclaim(w, r)
	}
}
func (h *recoveryGateAPI) GetPublicRedeemReclaimStatus(w http.ResponseWriter, r *http.Request) {
	if h.gate(w, r) {
		h.PublicRedeemHandler.GetPublicRedeemReclaimStatus(w, r)
	}
}
func (h *recoveryGateAPI) ListPublicRedeemRecords(w http.ResponseWriter, r *http.Request) {
	if h.gate(w, r) {
		h.PublicRedeemHandler.ListPublicRedeemRecords(w, r)
	}
}
func (h *recoveryGateAPI) GetPublicRedeemState(w http.ResponseWriter, r *http.Request) {
	if h.gate(w, r) {
		h.PublicRedeemHandler.GetPublicRedeemState(w, r)
	}
}
