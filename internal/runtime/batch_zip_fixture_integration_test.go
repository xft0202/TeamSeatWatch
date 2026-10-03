//go:build integration

package runtime

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
)

// zipWholeBatchFixture seeds only upstream facts for this ticket's aggregate
// API test. The template is obtained from one valid production join/credential/
// usage chain against typed mocks. Existing immutable journals are seeded in a
// private fixture transaction, with triggers restored before production ready,
// association, archive, receiver and HTTP gates run. It is not a platform proof.
func zipWholeBatchFixture(t *testing.T, n int) (*removalFixture, ownerContext, []uuid.UUID) {
	t.Helper()
	ctx := context.Background()
	one, o, slot, d, _ := usageFixture(t)
	usageObserve(t, one, o, slot, false)
	tables := []string{"tsw_rotation_removal_evidence", "tsw_rotation_candidate_join_intents", "tsw_rotation_join_executions", "tsw_rotation_join_execution_attempts", "tsw_rotation_join_personal_bindings", "tsw_rotation_join_membership_evidence", "tsw_rotation_join_credential_attempts", "tsw_rotation_join_credential_components", "tsw_rotation_join_credential_generations", "tsw_rotation_join_usage_attempts", "tsw_rotation_join_usage_evidence"}
	templates := map[string][]map[string]any{}
	for _, table := range tables {
		q := `SELECT to_jsonb(t) FROM public.` + table + ` t`
		if table == "tsw_rotation_join_execution_attempts" {
			q += ` WHERE id=(SELECT request_start_event_id FROM public.tsw_rotation_join_personal_bindings)`
		}
		rows, e := one.pool.Query(ctx, q)
		if e != nil {
			t.Fatal(e)
		}
		for rows.Next() {
			var raw []byte
			if e = rows.Scan(&raw); e != nil {
				t.Fatal(e)
			}
			var record map[string]any
			if e = json.Unmarshal(raw, &record); e != nil {
				t.Fatal(e)
			}
			templates[table] = append(templates[table], record)
		}
		e = rows.Err()
		rows.Close()
		if e != nil {
			t.Fatal(e)
		}
	}
	ca, e := readJoinCredentialAttempt(ctx, one.pool, slot)
	if e != nil {
		t.Fatal(e)
	}
	var web platform.WorkspaceAccess
	var oauth platform.DeliveryCredentialSet
	if _, e = one.h.readCredentialComponent(ctx, one.pool, ca, "web", &web); e != nil {
		t.Fatal(e)
	}
	if _, e = one.h.readCredentialComponent(ctx, one.pool, ca, "oauth", &oauth); e != nil {
		t.Fatal(e)
	}
	f := newJoinFixture(t, n)
	progress := f.start(t)
	owner := joinOwner(t, f)
	var epochs any
	var rawEpoch []byte
	var exchange uuid.UUID
	if e = f.pool.QueryRow(ctx, `SELECT p.epoch_versions,d.token_exchange_id FROM public.tsw_expiry_rotation_previews p JOIN public.tsw_workspace_verifications d ON d.id=p.verification_id WHERE p.id=$1`, f.preview.Id).Scan(&rawEpoch, &exchange); e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(rawEpoch, &epochs); e != nil {
		t.Fatal(e)
	}
	tx, e := f.pool.Begin(ctx)
	if e != nil {
		t.Fatal(e)
	}
	defer tx.Rollback(ctx)
	// This applies only to construction of already accepted upstream fixture rows.
	// It is transaction-local, never modifies a production migration/function, and
	// is explicitly restored before the current ticket's qualification checks.
	if _, e = tx.Exec(ctx, `SET LOCAL session_replication_role='replica'`); e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	expiry := now.Truncate(time.Second).Add(time.Hour)
	token := func(value, email string) string {
		parts := strings.Split(value, ".")
		raw, _ := base64.RawURLEncoding.DecodeString(parts[1])
		var claims map[string]any
		_ = json.Unmarshal(raw, &claims)
		claims["exp"] = expiry.Unix()
		claims["email"] = email
		nested := claims["https://api.openai.com/auth"].(map[string]any)
		nested["chatgpt_user_id"] = "mock-" + email
		if nested["chatgpt_plan_type"] != "free" {
			nested["chatgpt_account_id"] = f.space.String()
		}
		raw, _ = json.Marshal(claims)
		return parts[0] + "." + base64.RawURLEncoding.EncodeToString(raw) + "." + parts[2]
	}
	slots := []uuid.UUID{}
	for _, s := range progress.Slots {
		slots = append(slots, s.Id)
		var identifier string
		if e = tx.QueryRow(ctx, `SELECT identifier FROM public.tsw_target_accounts WHERE id=$1`, s.CandidateAccountId).Scan(&identifier); e != nil {
			t.Fatal(e)
		}
		evidence, attempt, generation, usage, event, personalGeneration := uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New()
		personal := d.session
		personal.AccessToken = token(personal.AccessToken, identifier)
		personal.ExpiresAt = expiry
		version, nonce, sealed, e := sealSessionFor("target", f.h.keyRing, s.CandidateAccountId, 1, personal)
		if e != nil {
			t.Fatal(e)
		}
		digest := sha256.Sum256(sealed)
		if _, e = tx.Exec(ctx, `INSERT INTO public.tsw_target_personal_access(target_account_id,secret_revision,status)VALUES($1,1,'ready');`, s.CandidateAccountId); e != nil {
			t.Fatal(e)
		}
		if _, e = tx.Exec(ctx, `INSERT INTO public.tsw_target_personal_sessions(target_account_id,secret_revision,attempt,generation,key_version,nonce,sealed_session,expires_at)VALUES($1,1,1,$2,$3,$4,$5,$6)`, s.CandidateAccountId, personalGeneration, version, nonce, sealed, expiry); e != nil {
			t.Fatal(e)
		}
		w := web
		w.WorkspaceID = f.space.String()
		w.AccessToken = token(w.AccessToken, identifier)
		w.ExpiresAt = expiry
		w.Cookies = append([]platform.SessionCookie(nil), web.Cookies...)
		for i := range w.Cookies {
			if w.Cookies[i].Name == "_account" || w.Cookies[i].Name == "oai-workspace" {
				w.Cookies[i].Value = f.space.String()
			}
		}
		oc := oauth
		oc.WorkspaceID = f.space.String()
		oc.PlatformSubjectID = "mock-" + identifier
		oc.AccessToken = token(oc.AccessToken, identifier)
		oc.IDToken = token(oc.IDToken, identifier)
		binding := joinCredentialBinding{target: s.CandidateAccountId, workspace: f.space, slot: s.Id, attempt: attempt, generation: generation, revision: 1, platformWorkspace: f.space.String()}
		components := map[string]map[string]any{}
		for _, kind := range []string{"web", "oauth"} {
			b := binding
			b.kind = kind
			var value any = w
			if kind == "oauth" {
				value = oc
			}
			v, n, c, e := sealJoinCredential(f.h.keyRing, b, value)
			if e != nil {
				t.Fatal(e)
			}
			hash := sha256.Sum256(c)
			components[kind] = map[string]any{"key_version": v, "nonce": "\\x" + hex.EncodeToString(n), "sealed": "\\x" + hex.EncodeToString(c), "sealed_digest": hex.EncodeToString(hash[:])}
		}
		membershipDigest := rotationHash([]any{"typed_mock_membership", s.Id, s.CandidateAccountId, f.space})
		for _, table := range tables {
			for _, template := range templates[table] {
				record := map[string]any{}
				for k, v := range template {
					record[k] = v
				}
				common := map[string]any{"slot_id": s.Id, "preview_id": f.preview.Id, "workspace_id": f.space, "owner_id": f.owner, "candidate_account_id": s.CandidateAccountId, "target_account_id": s.CandidateAccountId, "candidate_identifier": identifier, "original_platform_member_id": s.PlatformMemberId, "authorization_digest": *f.preview.AuthorizationDigest, "authorized_session": owner.SessionID, "owner_session": owner.SessionID, "epoch_versions": epochs, "released_verification_id": evidence, "platform_workspace_id": f.space.String(), "subject_id": "mock-" + identifier}
				for k, v := range common {
					if old, present := record[k]; present && (k != "owner_session" || old != nil) {
						record[k] = v
					}
				}
				for _, k := range []string{"observed_at", "created_at", "updated_at", "identity_observed_at", "bound_at", "verified_at"} {
					if _, present := record[k]; present {
						record[k] = now
					}
				}
				if _, present := record["attempt_id"]; present {
					record["attempt_id"] = attempt
				}
				if _, present := record["generation"]; present {
					record["generation"] = generation
				}
				if _, present := record["membership_digest"]; present {
					record["membership_digest"] = membershipDigest
				}
				if table == "tsw_rotation_join_membership_evidence" {
					record["evidence_digest"] = membershipDigest
				}
				switch table {
				case "tsw_rotation_removal_evidence":
					record["id"] = evidence
					record["token_exchange_id"] = exchange
					record["members"] = []any{}
					record["lease_epoch"] = 1
				case "tsw_rotation_join_execution_attempts":
					record["id"] = event
				case "tsw_rotation_join_personal_bindings":
					record["generation"] = personalGeneration
					record["key_version"] = version
					record["sealed_digest"] = hex.EncodeToString(digest[:])
					record["db_expiry"] = expiry
					record["decoded_expiry"] = expiry
					record["request_start_event_id"] = event
				case "tsw_rotation_join_credential_components":
					for k, v := range components[record["kind"].(string)] {
						record[k] = v
					}
					record["expires_at"] = expiry
				case "tsw_rotation_join_credential_generations":
					record["web_digest"] = components["web"]["sealed_digest"]
					record["oauth_digest"] = components["oauth"]["sealed_digest"]
					record["expires_at"] = expiry
				case "tsw_rotation_join_usage_attempts":
					record["id"] = usage
					record["credential_attempt_id"] = attempt
				case "tsw_rotation_join_usage_evidence":
					record["attempt_id"] = usage
					record["expires_at"] = now.Add(5 * time.Minute)
					record["evidence_digest"] = rotationHash([]any{"typed_mock_usage", usage, generation, s.CandidateAccountId, f.space, now})
					record["windows"] = []platform.RotationUsageWindow{{Seconds: 18000, ResetsAt: expiry}, {Seconds: 604800, ResetsAt: expiry}}
				}
				raw, e := json.Marshal(record)
				if e != nil {
					t.Fatal(e)
				}
				if _, e = tx.Exec(ctx, `INSERT INTO public.`+table+` SELECT (jsonb_populate_record(NULL::public.`+table+`,$1::jsonb)).*`, raw); e != nil {
					t.Fatal(table, e)
				}
			}
		}
		if _, e = tx.Exec(ctx, `UPDATE public.tsw_rotation_removal_slots SET state='absent_verified',verification_id=$2,absent_verified_at=$3,lease_epoch=1 WHERE id=$1`, s.Id, evidence, now); e != nil {
			t.Fatal(e)
		}
	}
	if _, e = tx.Exec(ctx, `SET LOCAL session_replication_role='origin'`); e != nil {
		t.Fatal(e)
	}
	if e = tx.Commit(ctx); e != nil {
		t.Fatal(e)
	}
	for _, slot := range slots {
		if !usageReady(t, f, slot) {
			t.Fatal("mock qualification failed actual production readiness", slot)
		}
	}
	f.h.pool = f.pool
	return f, owner, slots
}
