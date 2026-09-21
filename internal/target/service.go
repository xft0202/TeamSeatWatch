package target

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/teamseatwatch/teamseatwatch/internal/audit"
	"github.com/teamseatwatch/teamseatwatch/internal/platform"
)

type Service struct{}

func NewService() *Service { return &Service{} }

// PublishProbeTx stores the current, bounded observation and its audit fact in
// the same transaction as the durable task settlement.
func (s *Service) PublishProbeTx(ctx context.Context, tx pgx.Tx, targetID string, result platform.TargetProbeResult, correlationID, idempotencyKey string) error {
	observedAt := result.ObservedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	var httpStatus interface{}
	if result.HTTPStatus > 0 {
		httpStatus = result.HTTPStatus
	}
	diagnostic := platform.NormalizeDiagnostic(result.ErrorCode)
	var errorCode interface{}
	if diagnostic != "" {
		errorCode = diagnostic
	}
	status := string(result.Status)
	if status == "" {
		status = string(platform.TargetUnknown)
	}
	endpoint := result.Endpoint
	if endpoint == "" {
		endpoint = "account_usage"
	}
	origin := result.Origin
	if origin == "" {
		origin = "worker"
	}
	updated, err := tx.Exec(ctx, `
		UPDATE tsw_target_credentials
		SET latest_probe_status=$2,
			latest_probe_http_status=$3,
			latest_probe_error_code=$4,
			latest_probe_endpoint_key=$5,
			latest_probe_origin=$6,
			latest_probed_at=$7,
			last_verified_at=CASE WHEN $2='available' THEN $7 ELSE last_verified_at END,
			version=version+1
		WHERE target_account_id=$1`, targetID, status, httpStatus, errorCode, endpoint, origin, observedAt)
	if err != nil {
		return err
	}
	if updated.RowsAffected() != 1 {
		return errors.New("target credential projection was not found")
	}
	_, err = audit.Write(ctx, tx, audit.Event{
		Type: audit.TargetAccountProbed, Actor: audit.ActorSystem, RetentionScopeID: targetID,
		EntityType: "target_account", EntityID: targetID,
		Outcome: audit.OutcomeSucceeded, CorrelationID: correlationID,
		Details: audit.TargetProbeDetails{
			Status: status, Endpoint: endpoint, Origin: origin,
			HTTPStatus: result.HTTPStatus, ErrorCode: diagnostic,
			ObservedAt: observedAt.UTC().Format(time.RFC3339Nano),
		},
		IdempotencyKey: idempotencyKey,
	})
	return err
}
