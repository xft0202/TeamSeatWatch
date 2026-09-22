package oauth

import (
	"testing"

	"github.com/google/uuid"
)

func TestCanPublishRequiresCurrentFenceAndTaskLease(t *testing.T) {
	lease := uuid.New()
	fence := Fence{AssetID: "asset", Generation: 2, AttemptID: "attempt-2", TaskID: "task", TaskLease: lease}
	if !CanPublish(2, "attempt-2", fence, lease, true) {
		t.Fatal("current fenced attempt should publish")
	}
	if CanPublish(1, "attempt-2", fence, lease, true) || CanPublish(2, "attempt-1", fence, lease, true) || CanPublish(2, "attempt-2", fence, uuid.New(), true) || CanPublish(2, "attempt-2", fence, lease, false) {
		t.Fatal("stale generation, attempt, lease, or task lease must not publish")
	}
}

func TestProbeAuthoritativeOnlyAcceptsStrongHTTPEvidence(t *testing.T) {
	if !ProbeAuthoritative(ProbeOK, 200) || !ProbeAuthoritative(ProbeAuthError, 401) || !ProbeAuthoritative(ProbeDeactivatedWorkspace, 402) {
		t.Fatal("expected strong probe evidence to be authoritative")
	}
	if ProbeAuthoritative(ProbeOK, 0) || ProbeAuthoritative(ProbeAuthError, 403) || ProbeAuthoritative(ProbeTransientFailure, 500) {
		t.Fatal("weak probe evidence must remain non-authoritative")
	}
}
