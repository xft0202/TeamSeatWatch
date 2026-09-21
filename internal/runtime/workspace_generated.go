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

func (h *OwnerAuthHandler) ListTargetAccounts(w http.ResponseWriter, r *http.Request, params ownerapi.ListTargetAccountsParams) {
	h.listTargetAccounts(w, r, params)
}

func (h *OwnerAuthHandler) CreateTargetAccount(w http.ResponseWriter, r *http.Request, _ ownerapi.CreateTargetAccountParams) {
	h.createTargetAccount(w, r)
}

func (h *OwnerAuthHandler) GetTargetAccount(w http.ResponseWriter, r *http.Request, targetAccountID openapi_types.UUID) {
	r.SetPathValue("targetAccountId", targetAccountID.String())
	h.getTargetAccount(w, r)
}

func (h *OwnerAuthHandler) UpdateTargetAccount(w http.ResponseWriter, r *http.Request, targetAccountID openapi_types.UUID, params ownerapi.UpdateTargetAccountParams) {
	r.SetPathValue("targetAccountId", targetAccountID.String())
	h.updateTargetAccount(w, r, params)
}

func (h *OwnerAuthHandler) PreviewTargetAccountImport(w http.ResponseWriter, r *http.Request, _ ownerapi.PreviewTargetAccountImportParams) {
	h.previewTargetImport(w, r, false)
}

func (h *OwnerAuthHandler) ImportTargetAccounts(w http.ResponseWriter, r *http.Request, _ ownerapi.ImportTargetAccountsParams) {
	h.previewTargetImport(w, r, true)
}

func (h *OwnerAuthHandler) CreateTargetAccountProbes(w http.ResponseWriter, r *http.Request, _ ownerapi.CreateTargetAccountProbesParams) {
	h.createTargetProbes(w, r)
}

func (h *OwnerAuthHandler) GetTargetAccountProbe(w http.ResponseWriter, r *http.Request, probeID openapi_types.UUID) {
	r.SetPathValue("probeId", probeID.String())
	h.getTargetProbe(w, r)
}

func (h *OwnerAuthHandler) ListBatches(w http.ResponseWriter, r *http.Request, params ownerapi.ListBatchesParams) {
	h.listBatches(w, r, params)
}

func (h *OwnerAuthHandler) CreateBatch(w http.ResponseWriter, r *http.Request, _ ownerapi.CreateBatchParams) {
	h.createBatch(w, r)
}

func (h *OwnerAuthHandler) GetBatch(w http.ResponseWriter, r *http.Request, batchID openapi_types.UUID, params ownerapi.GetBatchParams) {
	r.SetPathValue("batchId", batchID.String())
	h.getBatch(w, r, params)
}

func (h *OwnerAuthHandler) UpdateBatch(w http.ResponseWriter, r *http.Request, batchID openapi_types.UUID, params ownerapi.UpdateBatchParams) {
	r.SetPathValue("batchId", batchID.String())
	h.updateBatch(w, r, params)
}

func (h *OwnerAuthHandler) GetBatchPreview(w http.ResponseWriter, r *http.Request, batchID openapi_types.UUID, params ownerapi.GetBatchPreviewParams) {
	r.SetPathValue("batchId", batchID.String())
	h.getBatchPreview(w, r, params)
}

func (h *OwnerAuthHandler) GetBatchJoinPreview(w http.ResponseWriter, r *http.Request, batchID openapi_types.UUID) {
	r.SetPathValue("batchId", batchID.String())
	h.getBatchJoinPreview(w, r)
}

func (h *OwnerAuthHandler) CreateJoinOperation(w http.ResponseWriter, r *http.Request, batchID openapi_types.UUID, _ ownerapi.CreateJoinOperationParams) {
	r.SetPathValue("batchId", batchID.String())
	h.createJoinOperation(w, r)
}

func (h *OwnerAuthHandler) GetJoinOperation(w http.ResponseWriter, r *http.Request, batchID openapi_types.UUID, params ownerapi.GetJoinOperationParams) {
	r.SetPathValue("batchId", batchID.String())
	h.getJoinOperation(w, r, params)
}

func (h *OwnerAuthHandler) CreateJoinReconciliation(w http.ResponseWriter, r *http.Request, batchID openapi_types.UUID, _ ownerapi.CreateJoinReconciliationParams) {
	r.SetPathValue("batchId", batchID.String())
	h.createJoinReconciliation(w, r)
}

func (h *OwnerAuthHandler) ListJoinOperationsNeedingAttention(w http.ResponseWriter, r *http.Request, params ownerapi.ListJoinOperationsNeedingAttentionParams) {
	h.listJoinOperationsNeedingAttention(w, r, params)
}
