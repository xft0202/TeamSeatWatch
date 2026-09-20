package runtime

import (
	"net/http"

	openapi_types "github.com/oapi-codegen/runtime/types"
	"github.com/teamseatwatch/teamseatwatch/internal/generated/ownerapi"
)

// These thin methods are the generated Owner API boundary. Domain and SQL work
// remain in the private handlers so DTO generation does not leak across modules.
func (h *OwnerAuthHandler) ListMotherAccounts(w http.ResponseWriter, r *http.Request, params ownerapi.ListMotherAccountsParams) {
	h.listMotherAccounts(w, r, params)
}

func (h *OwnerAuthHandler) CreateMotherAccount(w http.ResponseWriter, r *http.Request, _ ownerapi.CreateMotherAccountParams) {
	h.createMotherAccount(w, r)
}

func (h *OwnerAuthHandler) UpdateMotherAccount(w http.ResponseWriter, r *http.Request, accountID openapi_types.UUID, params ownerapi.UpdateMotherAccountParams) {
	r.SetPathValue("accountId", accountID.String())
	h.updateMotherAccount(w, r, params)
}

func (h *OwnerAuthHandler) ListWorkspaces(w http.ResponseWriter, r *http.Request, params ownerapi.ListWorkspacesParams) {
	h.listWorkspaces(w, r, params)
}

func (h *OwnerAuthHandler) CreateWorkspace(w http.ResponseWriter, r *http.Request, _ ownerapi.CreateWorkspaceParams) {
	h.createWorkspace(w, r)
}

func (h *OwnerAuthHandler) ListWorkspacesNeedingAttention(w http.ResponseWriter, r *http.Request, params ownerapi.ListWorkspacesNeedingAttentionParams) {
	h.listNeedsAttention(w, r, params)
}

func (h *OwnerAuthHandler) GetWorkspace(w http.ResponseWriter, r *http.Request, workspaceID openapi_types.UUID, params ownerapi.GetWorkspaceParams) {
	r.SetPathValue("workspaceId", workspaceID.String())
	h.getWorkspace(w, r, params)
}

func (h *OwnerAuthHandler) UpdateWorkspace(w http.ResponseWriter, r *http.Request, workspaceID openapi_types.UUID, params ownerapi.UpdateWorkspaceParams) {
	r.SetPathValue("workspaceId", workspaceID.String())
	h.updateWorkspace(w, r, params)
}

func (h *OwnerAuthHandler) CreateMotherWorkspaceBinding(w http.ResponseWriter, r *http.Request, _ ownerapi.CreateMotherWorkspaceBindingParams) {
	h.createBinding(w, r)
}

func (h *OwnerAuthHandler) RefreshWorkspaceFacts(w http.ResponseWriter, r *http.Request, workspaceID openapi_types.UUID, _ ownerapi.RefreshWorkspaceFactsParams) {
	r.SetPathValue("workspaceId", workspaceID.String())
	h.refreshWorkspace(w, r)
}

func (h *OwnerAuthHandler) GetWorkspaceReadStatus(w http.ResponseWriter, r *http.Request, readID openapi_types.UUID) {
	r.SetPathValue("readId", readID.String())
	h.getWorkspaceRead(w, r)
}

func (h *OwnerAuthHandler) CreateWorkspaceManualVerification(w http.ResponseWriter, r *http.Request, workspaceID openapi_types.UUID, _ ownerapi.CreateWorkspaceManualVerificationParams) {
	r.SetPathValue("workspaceId", workspaceID.String())
	h.manualVerifyWorkspace(w, r)
}
