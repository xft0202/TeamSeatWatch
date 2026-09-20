package workspace

import (
	"sort"
	"time"

	"github.com/teamseatwatch/teamseatwatch/internal/platform"
)

type OperationalState string

const (
	StateUnknown     OperationalState = "unknown"
	StateOperational OperationalState = "operational"
	StateDeactivated OperationalState = "deactivated"
	StateNotFound    OperationalState = "not_found"
)

type SourceKind string

const (
	SourcePlatform SourceKind = "platform"
	SourceOwner    SourceKind = "owner"
)

type Observation struct {
	ID         string
	Endpoint   platform.Endpoint
	Source     SourceKind
	Outcome    platform.Outcome
	ObservedAt time.Time
	ExpiresAt  time.Time
}

type Projection struct {
	State                   OperationalState
	ConclusionObservationID string
	EvidenceExpiresAt       time.Time
}

// Recompute uses only unexpired evidence. Endpoint identity is retained so an
// unrelated success cannot erase terminal support from a different capability.
func Recompute(now time.Time, observations []Observation) Projection {
	current := make([]Observation, 0, len(observations))
	for _, observation := range observations {
		if observation.ExpiresAt.After(now) {
			current = append(current, observation)
		}
	}
	sort.SliceStable(current, func(i, j int) bool { return current[i].ObservedAt.After(current[j].ObservedAt) })

	manual := latestManualConclusion(current)
	platformConclusion, platformState := latestPlatformConclusion(current)
	if manual != nil && (platformConclusion == nil || manual.ObservedAt.After(platformConclusion.ObservedAt)) {
		if manual.Outcome == platform.Outcome("manual_recovered") {
			return conclusion(StateOperational, *manual)
		}
		return conclusion(StateDeactivated, *manual)
	}
	if platformConclusion != nil {
		return conclusion(platformState, *platformConclusion)
	}
	return Projection{State: StateUnknown}
}

func latestManualConclusion(observations []Observation) *Observation {
	for index := range observations {
		if observations[index].Source == SourceOwner &&
			(observations[index].Outcome == platform.Outcome("manual_recovered") || observations[index].Outcome == platform.Outcome("manual_deactivated")) {
			return &observations[index]
		}
	}
	return nil
}

func latestPlatformConclusion(observations []Observation) (*Observation, OperationalState) {
	if terminal := latestUnrecoveredTerminal(observations); terminal != nil {
		state := StateDeactivated
		if terminal.Outcome == platform.OutcomeNotFound {
			state = StateNotFound
		}
		return terminal, state
	}
	for index := range observations {
		if observations[index].Endpoint == platform.EndpointExchange && observations[index].Outcome == platform.OutcomeOperational {
			return &observations[index], StateOperational
		}
	}
	return nil, StateUnknown
}

func latestUnrecoveredTerminal(observations []Observation) *Observation {
	for index := range observations {
		observation := observations[index]
		if observation.Outcome != platform.OutcomeDeactivated && observation.Outcome != platform.OutcomeNotFound {
			continue
		}
		if !newerEndpointRecovery(observations[:index], observation) {
			return &observations[index]
		}
	}
	return nil
}

func newerEndpointRecovery(observations []Observation, terminal Observation) bool {
	for _, observation := range observations {
		if observation.ObservedAt.After(terminal.ObservedAt) &&
			observation.Endpoint == terminal.Endpoint && observation.Outcome == platform.OutcomeOperational {
			return true
		}
	}
	return false
}

func conclusion(state OperationalState, observation Observation) Projection {
	return Projection{State: state, ConclusionObservationID: observation.ID, EvidenceExpiresAt: observation.ExpiresAt}
}
