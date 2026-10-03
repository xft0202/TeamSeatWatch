package runtime

import (
	"archive/zip"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/xft0202/Apophis-TeamSeatWatch/internal/auth"
)

var errChannelPending = errors.New("original channel obligation pending")
var errChannelFinalUnavailable = errors.New("channel has no verified final customer receipt")

// ChannelDestination is the original configured target, never a current default.
// Secrets are passed only to the guarded adapter and never appear in results.
type ChannelDestination struct {
	ID                            uuid.UUID
	Revision                      int64
	Name, Endpoint, Group, Secret string
}
type ChannelObject struct {
	PackageID, AccountID, SlotID           uuid.UUID
	PackageDigest, WorkspaceID, Identifier string
	OAuth                                  json.RawMessage
}

// ChannelReception contains only a verified remote identity, not credentials.
type ChannelReception struct {
	RemoteObjectID, ReceiptID string
	ObservedAt                time.Time
}
type ChannelFinalReceipt struct {
	AccountID                                                             uuid.UUID
	RemoteObjectID, ReceiptID, CustomerID, AuthorizationID, PackageDigest string
	ObservedAt                                                            time.Time
}

// ChannelDeliveryAdapter separates OAuth inventory reception from customer ZIP
// delivery. Inspect operations are read-only. Receive/DeliverZIP are single
// attempts; the durable caller never blindly retries an uncertain mutation.
// Their callback must run once after read-only preparation, immediately before
// starting external writes. A preparation failure must not invoke the callback.
type ChannelDeliveryAdapter interface {
	Receive(context.Context, ChannelDestination, ChannelObject, func(context.Context) error) (ChannelReception, error)
	Inspect(context.Context, ChannelDestination, ChannelObject) (ChannelReception, error)
	AuthorizeZIP(context.Context, ChannelDestination, []ChannelObject) (BatchZIPRecipient, error)
	DeliverZIP(context.Context, ChannelDestination, []ChannelObject, BatchZIPRecipient, string, []byte, func(context.Context) error) ([]ChannelFinalReceipt, error)
	InspectZIP(context.Context, ChannelDestination, []ChannelObject, BatchZIPRecipient) ([]ChannelFinalReceipt, error)
}

type channelRecord struct {
	archive       batchZIPRecord
	destination   ChannelDestination
	key           int16
	nonce, sealed []byte
	authorization string
}

func (h *OwnerAuthHandler) readChannel(ctx context.Context, db rotationRow, a batchZIPRecord) (channelRecord, error) {
	c := channelRecord{archive: a}
	e := db.QueryRow(ctx, `SELECT destination_id,destination_revision,destination_name,endpoint,target_group,secret_key_version,secret_nonce,secret_ciphertext,authorization_digest FROM public.tsw_channel_deliveries WHERE package_id=$1`, a.id).Scan(&c.destination.ID, &c.destination.Revision, &c.destination.Name, &c.destination.Endpoint, &c.destination.Group, &c.key, &c.nonce, &c.sealed, &c.authorization)
	if e != nil {
		return c, e
	}
	return h.openChannel(c)
}
func (h *OwnerAuthHandler) openChannel(c channelRecord) (channelRecord, error) {
	secret, e := auth.DecryptSecret(uint16(c.key), c.nonce, c.sealed, h.keyRing)
	if e == nil {
		c.destination.Secret = string(secret)
		clear(secret)
	}
	return c, e
}
func (h *OwnerAuthHandler) channelObjects(ctx context.Context, a batchZIPRecord) ([]ChannelObject, error) {
	data, e := h.openBatchZIP(a)
	if e != nil {
		return nil, e
	}
	defer clear(data)
	z, e := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if e != nil {
		return nil, e
	}
	var entries []json.RawMessage
	for _, f := range z.File {
		if f.Name != "sub2api_all.json" {
			continue
		}
		r, e := f.Open()
		if e != nil {
			return nil, e
		}
		raw, e := io.ReadAll(io.LimitReader(r, 64<<20))
		_ = r.Close()
		if e != nil {
			return nil, e
		}
		var b struct {
			Accounts []json.RawMessage `json:"accounts"`
		}
		e = json.Unmarshal(raw, &b)
		clear(raw)
		if e != nil {
			return nil, e
		}
		entries = b.Accounts
	}
	if len(entries) != a.count {
		return nil, errChannelPending
	}
	rows, e := h.pool.Query(ctx, `SELECT m.target_account_id,m.slot_id,a.identifier,w.platform_workspace_id FROM public.tsw_batch_zip_members m JOIN public.tsw_target_accounts a ON a.id=m.target_account_id JOIN public.tsw_batch_zip_archives p ON p.id=m.package_id JOIN public.tsw_workspaces w ON w.id=p.workspace_id WHERE m.package_id=$1 ORDER BY m.ordinal`, a.id)
	if e != nil {
		return nil, e
	}
	defer rows.Close()
	objects := []ChannelObject{}
	for rows.Next() {
		o := ChannelObject{PackageID: a.id, PackageDigest: a.digest}
		if e = rows.Scan(&o.AccountID, &o.SlotID, &o.Identifier, &o.WorkspaceID); e != nil {
			return nil, e
		}
		if len(objects) >= len(entries) {
			return nil, errChannelPending
		}
		o.OAuth = entries[len(objects)]
		var entry map[string]any
		if e = json.Unmarshal(o.OAuth, &entry); e != nil {
			return nil, e
		}
		creds, ok := entry["credentials"].(map[string]any)
		if !ok || creds["chatgpt_account_id"] != o.WorkspaceID {
			return nil, errChannelPending
		}
		o.Identifier, _ = creds["email"].(string)
		if o.Identifier == "" {
			return nil, errChannelPending
		}
		objects = append(objects, o)
	}
	if e = rows.Err(); e != nil {
		return nil, e
	}
	if len(objects) != a.count {
		return nil, errChannelPending
	}
	return objects, nil
}

// channelGate uses the same source action locks as archive generation. The
// original package survives changes, but new exposure still needs current facts.
func (h *OwnerAuthHandler) channelGate(ctx context.Context, owner ownerContext, a batchZIPRecord) (*removalGate, error) {
	authorization, e := loadRemovalAuthorization(ctx, h.pool, a.owner, a.preview)
	if e != nil {
		return nil, e
	}
	keys := rotationAuthorizationKeys(a.owner, authorization.preview)
	sort.Slice(keys, func(i, j int) bool {
		return string(keys[i].Kind)+keys[i].ID.String() < string(keys[j].Kind)+keys[j].ID.String()
	})
	conn, e := h.pool.Acquire(ctx)
	if e != nil {
		return nil, e
	}
	g := &removalGate{conn: conn, workspace: a.workspace}
	fail := func(e error) (*removalGate, error) { g.close(); return nil, e }
	for _, key := range keys {
		if _, e = conn.Exec(ctx, `SELECT pg_advisory_lock(hashtextextended('tsw.rotation.action.'||$1,0))`, string(key.Kind)+"/"+key.ID.String()); e != nil {
			return fail(e)
		}
		g.keys = append(g.keys, key)
	}
	if e = g.lockWorkspace(ctx); e != nil {
		return fail(e)
	}
	return g, nil
}
func (h *OwnerAuthHandler) channelAuthority(ctx context.Context, db rotationRow, owner ownerContext, c channelRecord) error {
	var ok bool
	e := db.QueryRow(ctx, `SELECT p.owner_id=$2 AND p.status='authorized' AND p.revoked_at IS NULL AND p.expires_at>clock_timestamp() AND p.authorization_digest=$4 AND rem.stopped_at IS NULL AND NOT EXISTS(SELECT 1 FROM jsonb_each_text(p.epoch_versions) v LEFT JOIN public.tsw_rotation_epochs e ON v.key=e.kind||'/'||e.id::text WHERE e.version IS NULL OR e.version::text<>v.value) AND d.enabled AND d.revision=$5 AND d.endpoint=$6 AND d.target_group=$7 AND d.test_connection='connected' AND d.test_target='connected' AND d.test_revision=d.revision AND EXISTS(SELECT 1 FROM public.tsw_owner_sessions s JOIN public.tsw_owners o ON o.id=s.owner_id WHERE s.id=$3 AND s.owner_id=$2 AND s.auth_version=o.auth_version AND s.revoked_at IS NULL AND s.idle_expires_at>clock_timestamp() AND s.absolute_expires_at>clock_timestamp()) AND public.tsw_archived_batch_zip_ready($9,(SELECT slot_id FROM public.tsw_batch_zip_members WHERE package_id=$9 ORDER BY ordinal LIMIT 1)) FROM public.tsw_expiry_rotation_previews p JOIN public.tsw_rotation_removals rem ON rem.preview_id=p.id JOIN public.tsw_delivery_destinations d ON d.id=$8 WHERE p.id=$1`, c.archive.preview, owner.OwnerID, owner.SessionID, c.authorization, c.destination.Revision, c.destination.Endpoint, c.destination.Group, c.destination.ID, c.archive.id).Scan(&ok)
	if e != nil {
		return e
	}
	if !ok {
		return errChannelPending
	}
	return nil
}
func (h *OwnerAuthHandler) channelFresh(ctx context.Context, db rotationRow, c channelRecord, o ChannelObject) error {
	var ready bool
	e := db.QueryRow(ctx, `SELECT public.tsw_archived_batch_zip_ready($1,$3) AND EXISTS(SELECT 1 FROM public.tsw_batch_zip_members WHERE package_id=$1 AND target_account_id=$2 AND slot_id=$3)`, c.archive.id, o.AccountID, o.SlotID).Scan(&ready)
	if e != nil {
		return e
	}
	if !ready {
		return errChannelPending
	}
	ca, e := readJoinCredentialAttempt(ctx, db, o.SlotID)
	if e != nil {
		return e
	}
	if ca.binding.target != o.AccountID || ca.binding.workspace != c.archive.workspace {
		return errChannelPending
	}
	_, _, e = h.validateSavedJoinCredentials(ctx, db, ca)
	return e
}
func (h *OwnerAuthHandler) originalChannel(ctx context.Context, db rotationRow, a batchZIPRecord) (channelRecord, error) {
	c := channelRecord{archive: a}
	e := db.QueryRow(ctx, `SELECT d.id,d.revision,d.name,d.endpoint,d.target_group,d.secret_key_version,d.secret_nonce,d.secret_ciphertext,p.authorization_digest FROM public.tsw_expiry_rotation_previews p JOIN public.tsw_delivery_destinations d ON d.id=(p.facts->>'destinationId')::uuid AND d.revision=(p.facts->>'destinationRevision')::bigint WHERE p.id=$1 AND p.owner_id=$2 AND NOT EXISTS(SELECT 1 FROM public.tsw_batch_zip_receivers WHERE package_id=$3)`, a.preview, a.owner, a.id).Scan(&c.destination.ID, &c.destination.Revision, &c.destination.Name, &c.destination.Endpoint, &c.destination.Group, &c.key, &c.nonce, &c.sealed, &c.authorization)
	if e != nil {
		return c, e
	}
	return h.openChannel(c)
}
func (h *OwnerAuthHandler) freezeChannel(ctx context.Context, conn *pgxpool.Conn, owner ownerContext, a batchZIPRecord, objects []ChannelObject) (channelRecord, error) {
	if c, e := h.readChannel(ctx, conn, a); e == nil {
		return c, nil
	} else if !errors.Is(e, pgx.ErrNoRows) {
		return c, e
	}
	tx, e := conn.Begin(ctx)
	if e != nil {
		return channelRecord{}, e
	}
	defer tx.Rollback(ctx)
	c, e := h.originalChannel(ctx, tx, a)
	if e != nil {
		return c, e
	}
	if e = h.channelAuthority(ctx, tx, owner, c); e != nil {
		return c, e
	}
	_, e = tx.Exec(ctx, `INSERT INTO public.tsw_channel_deliveries(package_id,destination_id,destination_revision,destination_name,endpoint,target_group,secret_key_version,secret_nonce,secret_ciphertext,authorization_digest)VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`, a.id, c.destination.ID, c.destination.Revision, c.destination.Name, c.destination.Endpoint, c.destination.Group, c.key, c.nonce, c.sealed, c.authorization)
	if e != nil {
		return c, e
	}
	for _, o := range objects {
		if e = h.channelFresh(ctx, tx, c, o); e != nil {
			return c, e
		}
	}
	for _, o := range objects {
		if _, e = tx.Exec(ctx, `INSERT INTO public.tsw_channel_objects(package_id,target_account_id,slot_id)VALUES($1,$2,$3)`, a.id, o.AccountID, o.SlotID); e != nil {
			return c, e
		}
	}
	if e = tx.Commit(ctx); e != nil {
		return c, e
	}
	return h.readChannel(ctx, conn, a)
}
func channelText(s string) bool {
	return len(s) > 0 && len(s) <= 255 && bytes.IndexAny([]byte(s), "\r\n\x00") < 0
}
func (h *OwnerAuthHandler) saveReception(ctx context.Context, c channelRecord, o ChannelObject, r ChannelReception) error {
	if !channelText(r.RemoteObjectID) || !channelText(r.ReceiptID) || r.ObservedAt.IsZero() || r.ObservedAt.After(time.Now().Add(time.Second)) {
		return errChannelPending
	}
	_, e := h.pool.Exec(ctx, `INSERT INTO public.tsw_channel_receipts(package_id,target_account_id,stage,remote_object_id,receipt_id,observed_at)VALUES($1,$2,'received',$3,$4,$5)ON CONFLICT DO NOTHING`, c.archive.id, o.AccountID, r.RemoteObjectID, r.ReceiptID, r.ObservedAt)
	if e != nil {
		return e
	}
	var same bool
	e = h.pool.QueryRow(ctx, `SELECT remote_object_id=$3 AND receipt_id=$4 FROM public.tsw_channel_receipts WHERE package_id=$1 AND target_account_id=$2 AND stage='received'`, c.archive.id, o.AccountID, r.RemoteObjectID, r.ReceiptID).Scan(&same)
	if e != nil {
		return e
	}
	if !same {
		return errChannelPending
	}
	return h.associateChannel(ctx, c)
}
func (h *OwnerAuthHandler) associateChannel(ctx context.Context, c channelRecord) error {
	tx, e := h.pool.Begin(ctx)
	if e != nil {
		return e
	}
	defer tx.Rollback(ctx)
	for _, stage := range []string{"received", "delivered"} {
		if _, e = tx.Exec(ctx, `INSERT INTO public.tsw_channel_associations(package_id,target_account_id,stage) SELECT package_id,target_account_id,stage FROM public.tsw_channel_receipts WHERE package_id=$1 AND stage=$2 ON CONFLICT DO NOTHING`, c.archive.id, stage); e != nil {
			return e
		}
	}
	var complete bool
	e = tx.QueryRow(ctx, `SELECT $2=(SELECT count(*) FROM public.tsw_channel_associations WHERE package_id=$1 AND stage='delivered')`, c.archive.id, c.archive.count).Scan(&complete)
	if e != nil {
		return e
	}
	if complete {
		var receipt string
		e = tx.QueryRow(ctx, `SELECT 'channel:'||encode(sha256(convert_to(string_agg(receipt_id,',' ORDER BY target_account_id),'UTF8')),'hex') FROM public.tsw_channel_receipts WHERE package_id=$1 AND stage='delivered'`, c.archive.id).Scan(&receipt)
		if e != nil {
			return e
		}
		if _, e = tx.Exec(ctx, `INSERT INTO public.tsw_batch_zip_delivered(package_id,receipt_id)VALUES($1,$2) ON CONFLICT DO NOTHING`, c.archive.id, receipt); e != nil {
			return e
		}
	}
	return tx.Commit(ctx)
}
func (h *OwnerAuthHandler) saveFinal(ctx context.Context, c channelRecord, objects []ChannelObject, r BatchZIPRecipient, receipts []ChannelFinalReceipt) error {
	allowed := map[uuid.UUID]bool{}
	for _, o := range objects {
		allowed[o.AccountID] = true
	}
	for _, v := range receipts {
		if !allowed[v.AccountID] || v.PackageDigest != c.archive.digest || v.CustomerID != r.CustomerID || v.AuthorizationID != r.AuthorizationID || !channelText(v.ReceiptID) || !channelText(v.RemoteObjectID) || v.ObservedAt.IsZero() || v.ObservedAt.After(time.Now().Add(time.Second)) {
			return errChannelPending
		}
		var same bool
		e := h.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.tsw_channel_receipts WHERE package_id=$1 AND target_account_id=$2 AND stage='received' AND remote_object_id=$3)`, c.archive.id, v.AccountID, v.RemoteObjectID).Scan(&same)
		if e != nil {
			return e
		}
		if !same {
			return errChannelPending
		}
		_, e = h.pool.Exec(ctx, `INSERT INTO public.tsw_channel_receipts(package_id,target_account_id,stage,remote_object_id,receipt_id,customer_id,authorization_id,observed_at)VALUES($1,$2,'delivered',$3,$4,$5,$6,$7)ON CONFLICT DO NOTHING`, c.archive.id, v.AccountID, v.RemoteObjectID, v.ReceiptID, r.CustomerID, r.AuthorizationID, v.ObservedAt)
		if e != nil {
			return e
		}
		e = h.pool.QueryRow(ctx, `SELECT remote_object_id=$3 AND receipt_id=$4 AND customer_id=$5 AND authorization_id=$6 FROM public.tsw_channel_receipts WHERE package_id=$1 AND target_account_id=$2 AND stage='delivered'`, c.archive.id, v.AccountID, v.RemoteObjectID, v.ReceiptID, r.CustomerID, r.AuthorizationID).Scan(&same)
		if e != nil {
			return e
		}
		if !same {
			return errChannelPending
		}
	}
	return h.associateChannel(ctx, c)
}

func (h *OwnerAuthHandler) runChannel(ctx context.Context, owner ownerContext, preview uuid.UUID, receive bool) error {
	a, e := readBatchZIP(ctx, h.pool, uuid.MustParse(owner.OwnerID), preview)
	if e != nil {
		return e
	}
	lock, e := h.pool.Acquire(ctx)
	if e != nil {
		return e
	}
	defer lock.Release()
	var locked bool
	e = lock.QueryRow(ctx, `SELECT pg_try_advisory_lock(hashtextextended('tsw.channel.package.'||$1::text,0))`, a.id).Scan(&locked)
	if e != nil {
		return e
	}
	if !locked {
		return errChannelPending
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = lock.Exec(cleanup, `SELECT pg_advisory_unlock(hashtextextended('tsw.channel.package.'||$1::text,0))`, a.id)
	}()
	adapter := h.channelDelivery
	if adapter == nil {
		adapter = NewSub2APIChannel(Sub2APIProbeConfig{})
	}
	objects, e := h.channelObjects(ctx, a)
	if e != nil {
		return e
	}
	defer func() {
		for _, o := range objects {
			clear(o.OAuth)
		}
	}()
	c, e := h.readChannel(ctx, h.pool, a)
	if errors.Is(e, pgx.ErrNoRows) {
		if !receive {
			return errChannelPending
		}
		g, e := h.channelGate(ctx, owner, a)
		if e != nil {
			return e
		}
		c, e = h.freezeChannel(ctx, g.conn, owner, a, objects)
		g.close()
		if e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	if e = h.associateChannel(ctx, c); e != nil {
		return e
	}
	for _, o := range objects {
		var received, attempted bool
		e = h.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.tsw_channel_associations WHERE package_id=$1 AND target_account_id=$2 AND stage='received'),EXISTS(SELECT 1 FROM public.tsw_channel_attempts WHERE package_id=$1 AND target_account_id=$2)`, a.id, o.AccountID).Scan(&received, &attempted)
		if e != nil {
			return e
		}
		if received {
			continue
		}
		var receipt ChannelReception
		if attempted {
			receipt, e = adapter.Inspect(ctx, c.destination, o)
		} else if receive {
			g, ge := h.channelGate(ctx, owner, a)
			if ge != nil {
				return ge
			}
			fence := func(ctx context.Context) error {
				if e := h.channelAuthority(ctx, g.conn, owner, c); e != nil {
					return e
				}
				return h.channelFresh(ctx, g.conn, c, o)
			}
			beforeWrite := func(ctx context.Context) error {
				if e := fence(ctx); e != nil {
					return e
				}
				_, e := g.conn.Exec(ctx, `INSERT INTO public.tsw_channel_attempts(package_id,target_account_id)VALUES($1,$2)`, a.id, o.AccountID)
				return e
			}
			if e = fence(ctx); e == nil {
				receipt, e = adapter.Receive(ctx, c.destination, o, beforeWrite)
			}
			g.close()
		} else {
			continue
		}
		// A verified partial receipt is useful even when the transport returned an
		// error. Unknown results remain attempted and can only be inspected.
		if receipt.RemoteObjectID != "" {
			finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
			save := h.saveReception(finish, c, o, receipt)
			cancel()
			if save != nil {
				return save
			}
		}
		if e != nil && !errors.Is(e, errChannelPending) {
			return e
		}
	}
	return h.finishChannelZIP(ctx, owner, c, objects, adapter)
}
func (h *OwnerAuthHandler) finishChannelZIP(ctx context.Context, owner ownerContext, c channelRecord, objects []ChannelObject, adapter ChannelDeliveryAdapter) error {
	var n int
	e := h.pool.QueryRow(ctx, `SELECT count(*) FROM public.tsw_channel_associations WHERE package_id=$1 AND stage='received'`, c.archive.id).Scan(&n)
	if e != nil {
		return e
	}
	if n != c.archive.count {
		return nil
	}
	var recipient BatchZIPRecipient
	e = h.pool.QueryRow(ctx, `SELECT channel,customer_id,authorization_id FROM public.tsw_batch_zip_receivers WHERE package_id=$1`, c.archive.id).Scan(&recipient.Channel, &recipient.CustomerID, &recipient.AuthorizationID)
	if errors.Is(e, pgx.ErrNoRows) {
		// The production OAuth channel has no customer identity/final proof. It
		// returns unavailable here; reception must remain a pending obligation.
		recipient, e = adapter.AuthorizeZIP(ctx, c.destination, objects)
		if errors.Is(e, errChannelFinalUnavailable) {
			return nil
		}
		if e != nil {
			return e
		}
		if recipient.Channel != "owner_channel" || !recipient.valid() {
			return errChannelPending
		}
		if e = h.channelAuthority(ctx, h.pool, owner, c); e != nil {
			return e
		}
		if e = h.ReserveBatchZIP(ctx, c.archive.id, recipient); e != nil {
			return e
		}
	} else if e != nil {
		return e
	}
	if recipient.Channel != "owner_channel" {
		return errChannelPending
	}
	var attempted, delivered bool
	e = h.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM public.tsw_channel_final_attempts WHERE package_id=$1),EXISTS(SELECT 1 FROM public.tsw_batch_zip_delivered WHERE package_id=$1)`, c.archive.id).Scan(&attempted, &delivered)
	if e != nil {
		return e
	}
	if delivered {
		return nil
	}
	var receipts []ChannelFinalReceipt
	if attempted {
		receipts, e = adapter.InspectZIP(ctx, c.destination, objects, recipient)
	} else {
		g, ge := h.channelGate(ctx, owner, c.archive)
		if ge != nil {
			return ge
		}
		defer g.close()
		fence := func(ctx context.Context) error {
			if e := h.channelAuthority(ctx, g.conn, owner, c); e != nil {
				return e
			}
			for _, o := range objects {
				if e := h.channelFresh(ctx, g.conn, c, o); e != nil {
					return e
				}
			}
			return nil
		}
		if e = fence(ctx); e != nil {
			return e
		}
		filename, data, ge := h.ReadBatchZIPForRecipient(ctx, c.archive.id, recipient)
		if ge != nil {
			return ge
		}
		defer clear(data)
		beforeWrite := func(ctx context.Context) error {
			if e := fence(ctx); e != nil {
				return e
			}
			_, e := g.conn.Exec(ctx, `INSERT INTO public.tsw_channel_final_attempts(package_id)VALUES($1)`, c.archive.id)
			return e
		}
		receipts, e = adapter.DeliverZIP(ctx, c.destination, objects, recipient, filename, data, beforeWrite)
	}
	if len(receipts) > 0 {
		finish, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
		save := h.saveFinal(finish, c, objects, recipient, receipts)
		cancel()
		if save != nil {
			return save
		}
	}
	if errors.Is(e, errChannelFinalUnavailable) {
		return nil
	}
	return e
}
