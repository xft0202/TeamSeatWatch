package runtime

import (
	"testing"

	"github.com/teamseatwatch/teamseatwatch/internal/generated/ownerapi"
)

func TestValidDeliveryRecordFiltersRejectUnknownValues(t *testing.T) {
	service := ownerapi.DeliveryServiceFilter("unknown")
	if validDeliveryRecordFilters(ownerapi.ListDeliveryRecordsParams{ServiceStatus: &service}) {
		t.Fatal("unknown service filter was accepted")
	}

	card := ownerapi.DeliveryCardFilter("unknown")
	if validDeliveryRecordFilters(ownerapi.ListDeliveryRecordsParams{CardStatus: &card}) {
		t.Fatal("unknown card filter was accepted")
	}

	order := ownerapi.DeliveryOrderFilter("unknown")
	if validDeliveryRecordFilters(ownerapi.ListDeliveryRecordsParams{OrderStatus: &order}) {
		t.Fatal("unknown order filter was accepted")
	}

	valid := ownerapi.DeliveryServiceFilterActive
	if !validDeliveryRecordFilters(ownerapi.ListDeliveryRecordsParams{ServiceStatus: &valid}) {
		t.Fatal("known service filter was rejected")
	}
}
