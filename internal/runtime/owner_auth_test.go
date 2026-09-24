package runtime

import (
	"testing"

	"github.com/teamseatwatch/teamseatwatch/internal/generated/ownerapi"
)

func TestValidLoginRequestUsesPasswordOnly(t *testing.T) {
	if !validLoginRequest(ownerapi.LoginOwnerJSONRequestBody{Username: "owner", Password: "a sufficiently long password"}) {
		t.Fatal("password-only Owner login was rejected")
	}
}

func TestValidLoginRequestRejectsMissingPassword(t *testing.T) {
	if validLoginRequest(ownerapi.LoginOwnerJSONRequestBody{Username: "owner"}) {
		t.Fatal("Owner login without a password was accepted")
	}
}
