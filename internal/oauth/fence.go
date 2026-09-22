package oauth

import "github.com/google/uuid"

// Fence is the durable identity of one OAuth execution. A result may publish
// only when all three parts still identify the current execution.
type Fence struct {
	AssetID    string
	Generation int64
	AttemptID  string
	TaskID     string
	TaskLease  uuid.UUID
}

func (f Fence) Valid() bool {
	return f.AssetID != "" && f.Generation > 0 && f.AttemptID != "" && f.TaskID != "" && f.TaskLease != uuid.Nil
}

func CanPublish(currentGeneration int64, currentAttemptID string, fence Fence, taskLease uuid.UUID, taskLeaseValid bool) bool {
	return fence.Valid() && taskLeaseValid && fence.TaskLease == taskLease && currentGeneration == fence.Generation && currentAttemptID == fence.AttemptID
}

// ProbeStatus is deliberately separate from the delivery status. A transient
// probe result never becomes a successful delivery or an authoritative 401.
type ProbeStatus string

const (
	ProbeOK                   ProbeStatus = "ok"
	ProbeAuthError            ProbeStatus = "auth_error"
	ProbeDeactivatedWorkspace ProbeStatus = "deactivated_workspace"
	ProbeRateLimited          ProbeStatus = "rate_limited"
	ProbeTransientFailure     ProbeStatus = "transient_failure"
	ProbeUnknown              ProbeStatus = "unknown"
)

func ProbeAuthoritative(status ProbeStatus, httpStatus int) bool {
	return (status == ProbeOK && httpStatus >= 200 && httpStatus < 300) ||
		(status == ProbeAuthError && httpStatus == 401) ||
		(status == ProbeDeactivatedWorkspace && httpStatus == 402)
}
