package runtime

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/batchzip"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/platform"
	targetdomain "github.com/xft0202/Apophis-TeamSeatWatch/internal/target"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/writerfence"
)

var errBatchZIPPending = errors.New("original batch ZIP pending")
var errBatchZIPProtected = errors.New("account protected by original customer package")

// BatchZIPRecipient is supplied only after the caller's channel-specific
// authorization. A customer identity is global; Owner/Public authorization IDs
// are independent and are never inferred to be the same order.
type BatchZIPRecipient struct{ Channel, CustomerID, AuthorizationID string }

func (r BatchZIPRecipient) valid() bool {
	if r.Channel != "owner_channel" && r.Channel != "public" {
		return false
	}
	for _, s := range []string{r.CustomerID, r.AuthorizationID} {
		if len(s) < 1 || len(s) > 255 || strings.TrimSpace(s) != s || strings.ContainsAny(s, "\r\n\x00") {
			return false
		}
	}
	return true
}

type batchZIPRecord struct {
	id, preview, owner, workspace, batch uuid.UUID
	batchVersion                         int64
	snapshot, filename, digest           string
	count                                int
	created                              time.Time
	key                                  int16
	nonce, sealed                        []byte
}

func batchZIPAAD(a batchZIPRecord) []byte {
	v, _ := json.Marshal([]any{"teamseatwatch:batch-zip:v1", a.id, a.preview, a.owner, a.workspace, a.batch, a.batchVersion, a.snapshot, a.filename, a.digest, a.count, a.created.UTC()})
	return v
}
func (h *OwnerAuthHandler) sealBatchZIP(a *batchZIPRecord, data []byte) error {
	if h.keyRing == nil {
		return errBatchZIPPending
	}
	version, _ := h.keyRing.Current()
	gcm, e := joinCredentialCipher(h.keyRing, version)
	if e != nil {
		return e
	}
	a.key = int16(version)
	a.nonce = make([]byte, gcm.NonceSize())
	if _, e = rand.Read(a.nonce); e != nil {
		return e
	}
	a.sealed = gcm.Seal(nil, a.nonce, data, batchZIPAAD(*a))
	return nil
}
func (h *OwnerAuthHandler) openBatchZIP(a batchZIPRecord) ([]byte, error) {
	gcm, e := joinCredentialCipher(h.keyRing, uint16(a.key))
	if e != nil {
		return nil, e
	}
	if len(a.nonce) != gcm.NonceSize() {
		return nil, errBatchZIPPending
	}
	data, e := gcm.Open(nil, a.nonce, a.sealed, batchZIPAAD(a))
	if e != nil {
		return nil, errBatchZIPPending
	}
	hash := sha256.Sum256(data)
	if hex.EncodeToString(hash[:]) != a.digest {
		clear(data)
		return nil, errBatchZIPPending
	}
	return data, nil
}
func readBatchZIP(ctx context.Context, db rotationRow, owner, preview uuid.UUID) (batchZIPRecord, error) {
	var a batchZIPRecord
	e := db.QueryRow(ctx, `SELECT id,preview_id,owner_id,workspace_id,batch_id,batch_version,snapshot_digest,filename,content_sha256,account_count,created_at,key_version,nonce,sealed_archive FROM public.tsw_batch_zip_archives WHERE owner_id=$1 AND preview_id=$2`, owner, preview).Scan(&a.id, &a.preview, &a.owner, &a.workspace, &a.batch, &a.batchVersion, &a.snapshot, &a.filename, &a.digest, &a.count, &a.created, &a.key, &a.nonce, &a.sealed)
	return a, e
}

type batchZIPMember struct {
	slot, account, credential, usage uuid.UUID
	value                            batchzip.Account
}

// prepareBatchZIP consumes the entire confirmed preview, never a client-selected
// subset. Every source/action fence is held through the atomic archive/member
// commit; generation writes no release, membership, usage or customer success.
func (h *OwnerAuthHandler) prepareBatchZIP(ctx context.Context, owner ownerContext, preview uuid.UUID) (batchZIPRecord, error) {
	oid := uuid.MustParse(owner.OwnerID)
	if a, e := readBatchZIP(ctx, h.pool, oid, preview); e == nil {
		return a, nil
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return a, e
	}
	auth, e := loadRemovalAuthorization(ctx, h.pool, oid, preview)
	if e != nil {
		return batchZIPRecord{}, e
	}
	keys := rotationAuthorizationKeys(oid, auth.preview)
	// Account source writers and usage readers use the same action namespace.
	// Acquire in sorted order before Workspace, so no observation can stale the
	// source snapshot between qualification and deferred association checks.
	conn, e := h.pool.Acquire(ctx)
	if e != nil {
		return batchZIPRecord{}, e
	}
	gate := &removalGate{conn: conn, workspace: auth.preview.WorkspaceId}
	defer gate.close()
	sort.Slice(keys, func(i, j int) bool {
		return string(keys[i].Kind)+keys[i].ID.String() < string(keys[j].Kind)+keys[j].ID.String()
	})
	for _, key := range keys {
		scope := string(key.Kind) + "/" + key.ID.String()
		if _, e = conn.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended('tsw.rotation.action.'||$1,0))`, scope); e != nil {
			return batchZIPRecord{}, e
		}
		gate.keys = append(gate.keys, key)
	}
	if e = gate.lockWorkspace(ctx); e != nil {
		return batchZIPRecord{}, e
	}
	tx, _, e := writerfence.BeginLockedOnConn(ctx, conn, keys)
	if e != nil {
		return batchZIPRecord{}, e
	}
	defer tx.Rollback(ctx)
	if a, e := readBatchZIP(ctx, tx, oid, preview); e == nil {
		return a, nil
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return a, e
	}
	var originalOwner string
	if e = tx.QueryRow(ctx, `SELECT owner_id::text FROM public.tsw_expiry_rotation_previews WHERE id=$1`, preview).Scan(&originalOwner); e != nil || originalOwner != owner.OwnerID {
		return batchZIPRecord{}, errBatchZIPPending
	}
	rows, e := tx.Query(ctx, `SELECT s.id,s.candidate_account_id FROM public.tsw_rotation_removal_slots s WHERE s.preview_id=$1 ORDER BY s.id`, preview)
	if e != nil {
		return batchZIPRecord{}, e
	}
	members := []batchZIPMember{}
	for rows.Next() {
		var m batchZIPMember
		if e = rows.Scan(&m.slot, &m.account); e != nil {
			rows.Close()
			return batchZIPRecord{}, e
		}
		members = append(members, m)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return batchZIPRecord{}, e
	}
	if len(members) != len(auth.assignments) || len(members) == 0 {
		return batchZIPRecord{}, errBatchZIPPending
	}
	now := time.Now().UTC().Truncate(time.Microsecond)
	values := make([]batchzip.Account, 0, len(members))
	platformWorkspace := ""
	for index := range members {
		m := &members[index]
		var ready bool
		if e = tx.QueryRow(ctx, `SELECT public.tsw_rotation_join_usage_ready($1)`, m.slot).Scan(&ready); e != nil {
			return batchZIPRecord{}, e
		}
		if !ready {
			return batchZIPRecord{}, errBatchZIPPending
		}
		ca, err := readJoinCredentialAttempt(ctx, tx, m.slot)
		if err != nil {
			return batchZIPRecord{}, err
		}
		if ca.binding.target != m.account || ca.binding.workspace != auth.preview.WorkspaceId {
			return batchZIPRecord{}, errBatchZIPPending
		}
		if platformWorkspace != "" && platformWorkspace != ca.binding.platformWorkspace {
			return batchZIPRecord{}, errBatchZIPPending
		}
		platformWorkspace = ca.binding.platformWorkspace
		if _, _, e = h.validateSavedJoinCredentials(ctx, tx, ca); e != nil {
			return batchZIPRecord{}, e
		}
		var oauth platform.DeliveryCredentialSet
		o, err := h.readCredentialComponent(ctx, tx, ca, "oauth", &oauth)
		if err != nil {
			return batchZIPRecord{}, err
		}
		var pw, totp []byte
		if e = tx.QueryRow(ctx, `SELECT a.identifier,c.password_secret,c.totp_secret FROM public.tsw_target_accounts a JOIN public.tsw_target_credentials c ON c.target_account_id=a.id WHERE a.id=$1 AND a.status='active' AND c.secret_revision=$2 AND c.materials_sealed AND c.material_status='complete'`, m.account, ca.binding.revision).Scan(&m.value.Identifier, &pw, &totp); e != nil {
			return batchZIPRecord{}, e
		}
		if m.value.Password, e = targetdomain.OpenMaterial(pw, h.keyRing); e != nil {
			return batchZIPRecord{}, e
		}
		if m.value.TOTP, e = targetdomain.OpenMaterial(totp, h.keyRing); e != nil {
			return batchZIPRecord{}, e
		}
		var scope, result string
		if e = tx.QueryRow(ctx, `SELECT ua.id,ev.scope,ev.result,ev.observed_at FROM public.tsw_rotation_join_usage_attempts ua JOIN public.tsw_rotation_join_usage_evidence ev ON ev.attempt_id=ua.id WHERE ua.slot_id=$1 ORDER BY ua.attempt_no DESC LIMIT 1`, m.slot).Scan(&m.usage, &scope, &result, &m.value.FirstOK); e != nil || scope != "workspace" || result != "zero" {
			return batchZIPRecord{}, errBatchZIPPending
		}
		m.credential = ca.binding.attempt
		m.value.OAuth = oauth
		m.value.Subject = ca.subject
		m.value.IssuedAt = o.observed
		m.value.ExpiresAt = o.expires
		values = append(values, m.value)
	}
	data, e := batchzip.Build(now, platformWorkspace, values)
	if e != nil {
		return batchZIPRecord{}, e
	}
	defer clear(data)
	hash := sha256.Sum256(data)
	a := batchZIPRecord{id: uuid.New(), preview: preview, owner: oid, workspace: auth.preview.WorkspaceId, batch: auth.preview.BatchId, batchVersion: auth.preview.BatchVersion, snapshot: auth.preview.Digest, filename: batchzip.Filename(now), digest: hex.EncodeToString(hash[:]), count: len(members), created: now}
	// Platform IDs need not equal local UUIDs. Use the credential target above.
	if e = h.sealBatchZIP(&a, data); e != nil {
		return batchZIPRecord{}, e
	}
	if _, e = tx.Exec(ctx, `INSERT INTO public.tsw_batch_zip_archives(id,preview_id,owner_id,workspace_id,batch_id,batch_version,snapshot_digest,filename,content_sha256,account_count,created_at,key_version,nonce,sealed_archive)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`, a.id, a.preview, a.owner, a.workspace, a.batch, a.batchVersion, a.snapshot, a.filename, a.digest, a.count, a.created, a.key, a.nonce, a.sealed); e != nil {
		return batchZIPRecord{}, e
	}
	for index, m := range members {
		if _, e = tx.Exec(ctx, `INSERT INTO public.tsw_batch_zip_members(package_id,ordinal,slot_id,target_account_id,credential_attempt_id,usage_attempt_id)VALUES($1,$2,$3,$4,$5,$6)`, a.id, index+1, m.slot, m.account, m.credential, m.usage); e != nil {
			return batchZIPRecord{}, e
		}
	}
	if e = tx.Commit(ctx); e != nil {
		return batchZIPRecord{}, e
	}
	return a, nil
}

// ReserveBatchZIP binds the already authorized recipient before a channel or
// customer can obtain full materials. It is permanent even if later I/O fails.
// Public callers must first validate their own inventory/card/token authority;
// Owner channel callers must first validate their frozen destination/order.
func (h *OwnerAuthHandler) ReserveBatchZIP(ctx context.Context, packageID uuid.UUID, r BatchZIPRecipient) error {
	if !r.valid() {
		return errBatchZIPProtected
	}
	tx, e := h.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	if e = h.reserveBatchZIPTx(ctx, tx, packageID, r); e != nil {
		return e
	}
	return tx.Commit(ctx)
}

// reserveBatchZIPTx lets independent Public inventory bind its order and global
// reservation in one transaction, using the same qualification and fences.
func (h *OwnerAuthHandler) reserveBatchZIPTx(ctx context.Context, tx pgx.Tx, packageID uuid.UUID, r BatchZIPRecipient) error {
	if !r.valid() {
		return errBatchZIPProtected
	}
	var e error
	if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('tsw.batch.zip.receiver.'||$1::text,0))`, packageID); e != nil {
		return e
	}
	var old BatchZIPRecipient
	e = tx.QueryRow(ctx, `SELECT channel,customer_id,authorization_id FROM public.tsw_batch_zip_receivers WHERE package_id=$1`, packageID).Scan(&old.Channel, &old.CustomerID, &old.AuthorizationID)
	if e == nil {
		if old != r {
			return errBatchZIPProtected
		}
		return nil
	}
	if !errors.Is(e, pgx.ErrNoRows) {
		return e
	}
	// Sorted target action locks serialize with generation and usage/source writes.
	rows, e := tx.Query(ctx, `SELECT target_account_id FROM public.tsw_batch_zip_members WHERE package_id=$1 ORDER BY target_account_id`, packageID)
	if e != nil {
		return e
	}
	ids := []uuid.UUID{}
	for rows.Next() {
		var id uuid.UUID
		if e = rows.Scan(&id); e != nil {
			rows.Close()
			return e
		}
		ids = append(ids, id)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return e
	}
	if len(ids) == 0 {
		return pgx.ErrNoRows
	}
	for _, id := range ids {
		if _, e = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended('tsw.rotation.action.target_account/'||$1::text,0))`, id); e != nil {
			return e
		}
		var blocked bool
		if e = tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.tsw_batch_zip_protections WHERE target_account_id=$1) OR EXISTS(SELECT 1 FROM public.tsw_rotation_global_protections WHERE target_account_id=$1 AND status<>'none') OR EXISTS(SELECT 1 FROM public.tsw_batch_memberships bm JOIN public.tsw_oauth_assets oa ON oa.membership_id=bm.id JOIN public.tsw_delivery_versions dv ON dv.oauth_asset_id=oa.id WHERE bm.target_account_id=$1)`, id).Scan(&blocked); e != nil {
			return e
		}
		if blocked {
			return errBatchZIPProtected
		}
		var ready bool
		if e = tx.QueryRow(ctx, `SELECT public.tsw_archived_batch_zip_ready(m.package_id,m.slot_id) AND ev.expires_at>clock_timestamp() AND ua.attempt_no=(SELECT max(attempt_no) FROM public.tsw_rotation_join_usage_attempts WHERE slot_id=m.slot_id) FROM public.tsw_batch_zip_members m JOIN public.tsw_rotation_join_usage_attempts ua ON ua.id=m.usage_attempt_id JOIN public.tsw_rotation_join_usage_evidence ev ON ev.attempt_id=ua.id WHERE m.package_id=$1 AND m.target_account_id=$2`, packageID, id).Scan(&ready); e != nil {
			return e
		}
		if !ready {
			return errBatchZIPPending
		}
		var slot uuid.UUID
		if e = tx.QueryRow(ctx, `SELECT slot_id FROM public.tsw_batch_zip_members WHERE package_id=$1 AND target_account_id=$2`, packageID, id).Scan(&slot); e != nil {
			return e
		}
		ca, err := readJoinCredentialAttempt(ctx, tx, slot)
		if err != nil {
			return err
		}
		if _, _, e = h.validateSavedJoinCredentials(ctx, tx, ca); e != nil {
			return e
		}
	}
	if _, e = tx.Exec(ctx, `INSERT INTO public.tsw_batch_zip_receivers(package_id,channel,customer_id,authorization_id)VALUES($1,$2,$3,$4)`, packageID, r.Channel, r.CustomerID, r.AuthorizationID); e != nil {
		return e
	}
	for _, id := range ids {
		if _, e = tx.Exec(ctx, `INSERT INTO public.tsw_batch_zip_protections(target_account_id,package_id,customer_id)VALUES($1,$2,$3)`, id, packageID, r.CustomerID); e != nil {
			return e
		}
	}
	return nil
}

// ReadBatchZIPForRecipient returns only that exact receiver's original bytes.
// Dynamic Public/Owner authorization must be performed on every request by the
// channel before this service call; a recipient string is not authentication.
func (h *OwnerAuthHandler) ReadBatchZIPForRecipient(ctx context.Context, id uuid.UUID, r BatchZIPRecipient) (string, []byte, error) {
	if !r.valid() {
		return "", nil, errBatchZIPProtected
	}
	var owner, preview uuid.UUID
	e := h.pool.QueryRow(ctx, `SELECT a.owner_id,a.preview_id FROM public.tsw_batch_zip_archives a JOIN public.tsw_batch_zip_receivers r ON r.package_id=a.id WHERE a.id=$1 AND r.channel=$2 AND r.customer_id=$3 AND r.authorization_id=$4 AND a.account_count=(SELECT count(*) FROM public.tsw_batch_zip_protections p WHERE p.package_id=a.id)`, id, r.Channel, r.CustomerID, r.AuthorizationID).Scan(&owner, &preview)
	if e != nil {
		return "", nil, e
	}
	a, e := readBatchZIP(ctx, h.pool, owner, preview)
	if e != nil {
		return "", nil, e
	}
	data, e := h.openBatchZIP(a)
	return a.filename, data, e
}

// MarkBatchZIPDelivered records a caller-verified final receipt. Reserving or
// reading bytes alone never becomes customer delivery completion.
func (h *OwnerAuthHandler) MarkBatchZIPDelivered(ctx context.Context, id uuid.UUID, r BatchZIPRecipient, receipt string) error {
	if !r.valid() || len(receipt) < 1 || len(receipt) > 255 || strings.ContainsAny(receipt, "\r\n\x00") {
		return errBatchZIPProtected
	}
	tag, e := h.pool.Exec(ctx, `INSERT INTO public.tsw_batch_zip_delivered(package_id,receipt_id)SELECT package_id,$5 FROM public.tsw_batch_zip_receivers WHERE package_id=$1 AND channel=$2 AND customer_id=$3 AND authorization_id=$4 ON CONFLICT(package_id) DO NOTHING`, id, r.Channel, r.CustomerID, r.AuthorizationID, receipt)
	if e != nil {
		return e
	}
	if tag.RowsAffected() == 0 {
		var same bool
		e = h.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.tsw_batch_zip_delivered d JOIN public.tsw_batch_zip_receivers r USING(package_id) WHERE package_id=$1 AND channel=$2 AND customer_id=$3 AND authorization_id=$4 AND receipt_id=$5)`, id, r.Channel, r.CustomerID, r.AuthorizationID, receipt).Scan(&same)
		if e != nil {
			return e
		}
		if !same {
			return errBatchZIPProtected
		}
	}
	return nil
}
