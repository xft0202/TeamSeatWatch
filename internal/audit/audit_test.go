package audit

import "testing"

func TestOwnerMutationRejectionKeepsRegisteredOperations(t *testing.T) {
	operations := []string{
		"mother_account.create", "mother_account.update", "workspace.create", "workspace.update",
		"binding.create", "workspace_read.create", "manual_verification.create",
		"target_account.create", "target_account.import", "target_account.update",
		"target_probe.create", "batch.create", "batch.update", "join.create",
		"join.reconcile", "card.activate", "delivery.reclaim_authorize",
	}
	for _, operation := range operations {
		t.Run(operation, func(t *testing.T) {
			event := Event{
				Type: OwnerMutationRejected, Actor: ActorOwner, OwnerID: "owner-id",
				EntityType: "owner", EntityID: "owner-id", Outcome: OutcomeDenied,
				CorrelationID: "audit-test", Details: OwnerMutationRejectionDetails{
					Operation: operation, Reason: "invalid_request",
				}, IdempotencyKey: "rejection:" + operation,
			}
			if _, _, err := validate(event); err != nil {
				t.Fatalf("valid Owner rejection operation rejected: %v", err)
			}
		})
	}
}

func TestDeliveryReclaimTerminalRejectionReasonIsRegistered(t *testing.T) {
	event := Event{
		Type: OwnerMutationRejected, Actor: ActorOwner, OwnerID: "owner-id",
		EntityType: "owner", EntityID: "owner-id", Outcome: OutcomeDenied,
		CorrelationID: "audit-test", Details: OwnerMutationRejectionDetails{
			Operation: "delivery.reclaim_authorize", Reason: "delivery_not_reclaimable",
		}, IdempotencyKey: "delivery-reclaim-rejected",
	}
	if _, _, err := validate(event); err != nil {
		t.Fatalf("delivery terminal rejection reason rejected: %v", err)
	}
}
