-- +goose Up
-- Shared37/38 predicate is supplied by37 when channel delivery is present.
-- Standalone38 uses the byte-identical shared definition without channel tables.
-- +goose StatementBegin
DO $fallback$
BEGIN
 IF to_regprocedure('public.tsw_archived_batch_zip_ready(uuid,uuid)') IS NULL THEN
  EXECUTE $definition$
CREATE FUNCTION public.tsw_archived_batch_zip_ready(package uuid,slot uuid) RETURNS boolean LANGUAGE sql VOLATILE SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT EXISTS(SELECT 1 FROM public.tsw_batch_zip_members m
 JOIN public.tsw_batch_zip_archives archive ON archive.id=m.package_id
 JOIN public.tsw_rotation_candidate_join_intents intent ON intent.slot_id=m.slot_id
 JOIN public.tsw_rotation_join_executions execution ON execution.slot_id=m.slot_id
 JOIN public.tsw_rotation_join_credential_attempts ca ON ca.attempt_id=m.credential_attempt_id AND ca.slot_id=m.slot_id
 JOIN public.tsw_rotation_join_credential_generations generation ON generation.attempt_id=ca.attempt_id
 JOIN public.tsw_rotation_join_usage_attempts ua ON ua.id=m.usage_attempt_id AND ua.credential_attempt_id=ca.attempt_id
 JOIN public.tsw_rotation_join_usage_evidence usage ON usage.attempt_id=ua.id
 JOIN public.tsw_target_accounts account ON account.id=m.target_account_id
 JOIN public.tsw_target_credentials material ON material.target_account_id=account.id
 JOIN public.tsw_expiry_rotation_previews preview ON preview.id=archive.preview_id
 JOIN public.tsw_rotation_removals removal ON removal.preview_id=preview.id
 JOIN public.tsw_owner_sessions session ON session.id=preview.authorized_session::uuid
 JOIN public.tsw_owners owner ON owner.id=session.owner_id
 WHERE m.package_id=package AND m.slot_id=slot AND account.status='active'
 AND ca.candidate_account_id=m.target_account_id AND ca.workspace_id=archive.workspace_id
 AND intent.candidate_account_id=m.target_account_id AND intent.workspace_id=archive.workspace_id AND execution.state='reconcile_required'
 AND account.identifier=intent.candidate_identifier AND material.secret_revision=ca.secret_revision AND material.materials_sealed AND material.material_status='complete'
 AND (material.platform_subject_id IS NULL OR material.platform_subject_id=ca.subject_id)
 AND generation.expires_at>clock_timestamp()+interval '1 minute'
 AND ua.state='complete' AND ua.attempt_no=(SELECT max(attempt_no) FROM public.tsw_rotation_join_usage_attempts WHERE slot_id=m.slot_id)
 AND usage.target_account_id=m.target_account_id AND usage.workspace_id=archive.workspace_id AND usage.scope='workspace' AND usage.result='zero'
 AND usage.observed_at<=clock_timestamp() AND usage.observed_at>clock_timestamp()-interval '5 minutes' AND usage.expires_at>clock_timestamp()
 AND EXISTS(SELECT 1 FROM public.tsw_rotation_join_membership_evidence membership WHERE membership.slot_id=m.slot_id AND membership.reconciliation_attempt=(SELECT max(reconciliation_attempt) FROM public.tsw_rotation_join_membership_evidence WHERE slot_id=m.slot_id) AND membership.result='confirmed' AND membership.platform_member_id=ca.platform_member_id)
 AND preview.status='authorized' AND preview.revoked_at IS NULL AND preview.expires_at>clock_timestamp() AND removal.stopped_at IS NULL
 AND intent.preview_id=archive.preview_id AND intent.owner_id=archive.owner_id
 AND intent.authorization_digest=preview.authorization_digest AND removal.authorization_digest=preview.authorization_digest
 AND intent.authorized_session=preview.authorized_session::uuid AND intent.epoch_versions=preview.epoch_versions
 AND EXISTS(SELECT 1 FROM public.tsw_rotation_removal_slots original JOIN public.tsw_rotation_removal_evidence released ON released.id=original.verification_id
  WHERE original.id=m.slot_id AND original.preview_id=archive.preview_id AND original.candidate_account_id=m.target_account_id
  AND original.state='absent_verified' AND NOT original.uncertain_obligation AND released.id=intent.released_verification_id
  AND released.slot_id=original.id AND released.target_absent AND released.complete AND released.observed_at<=clock_timestamp()
  AND released.authorization_digest=preview.authorization_digest)
 AND session.owner_id=archive.owner_id AND session.auth_version=owner.auth_version AND session.idle_expires_at>clock_timestamp() AND session.absolute_expires_at>clock_timestamp()
 AND (session.revoked_at IS NULL OR EXISTS(
  WITH RECURSIVE lineage(id,path) AS (
   SELECT session.id,ARRAY[session.id]
   UNION ALL
   SELECT successor.id,lineage.path||successor.id
   FROM lineage JOIN public.tsw_owner_sessions predecessor ON predecessor.id=lineage.id
   JOIN public.tsw_audit_events rotated ON rotated.event_type='owner.session_rotated' AND rotated.owner_id=predecessor.owner_id AND rotated.details->>'predecessor_session_id'=predecessor.id::text
   JOIN public.tsw_audit_events revoked ON revoked.event_type='owner.session_revoked' AND revoked.owner_id=predecessor.owner_id AND revoked.entity_id=predecessor.id AND revoked.details->>'reason'='rotation'
    AND revoked.correlation_id=rotated.correlation_id AND revoked.occurred_at=rotated.occurred_at
   JOIN public.tsw_owner_sessions successor ON successor.id=rotated.entity_id AND successor.owner_id=predecessor.owner_id AND successor.auth_version=predecessor.auth_version
   WHERE predecessor.revocation_reason='rotation' AND predecessor.revoked_at=revoked.occurred_at
    AND predecessor.idle_expires_at>clock_timestamp() AND predecessor.absolute_expires_at>clock_timestamp()
    AND successor.created_at=rotated.occurred_at AND successor.absolute_expires_at=predecessor.absolute_expires_at
    AND NOT successor.id=ANY(lineage.path)
  ) SELECT 1 FROM lineage JOIN public.tsw_owner_sessions current ON current.id=lineage.id
   WHERE current.revoked_at IS NULL AND current.idle_expires_at>clock_timestamp() AND current.absolute_expires_at>clock_timestamp()))
 AND NOT EXISTS(SELECT 1 FROM jsonb_each_text(preview.epoch_versions) v LEFT JOIN public.tsw_rotation_epochs e ON v.key=e.kind||'/'||e.id::text WHERE e.version IS NULL OR e.version::text<>v.value)
 AND NOT EXISTS(SELECT 1 FROM public.tsw_rotation_join_usage_evidence history WHERE history.target_account_id=m.target_account_id AND history.result='positive' AND (history.scope='account' OR history.workspace_id=archive.workspace_id))
 AND NOT EXISTS(SELECT 1 FROM public.tsw_rotation_usage_ledger history WHERE history.target_account_id=m.target_account_id AND history.workspace_id=archive.workspace_id AND history.ever_used)
 AND NOT EXISTS(SELECT 1 FROM public.tsw_rotation_global_protections protection WHERE protection.target_account_id=m.target_account_id AND protection.status<>'none')
 AND NOT EXISTS(SELECT 1 FROM public.tsw_batch_zip_protections protection WHERE protection.target_account_id=m.target_account_id AND protection.package_id<>package)
 AND NOT EXISTS(SELECT 1 FROM public.tsw_batch_memberships bm JOIN public.tsw_oauth_assets oa ON oa.membership_id=bm.id JOIN public.tsw_delivery_versions dv ON dv.oauth_asset_id=oa.id WHERE bm.target_account_id=m.target_account_id));
$$;
$definition$;
 END IF;
END;
$fallback$;
-- +goose StatementEnd
-- Public inventory and customer orders are explicit, independent authorizations.
CREATE TABLE public.tsw_public_zip_inventory (
 id uuid PRIMARY KEY,
 package_id uuid NOT NULL UNIQUE REFERENCES public.tsw_batch_zip_archives(id) ON DELETE RESTRICT,
 owner_id uuid NOT NULL REFERENCES public.tsw_owners(id) ON DELETE RESTRICT,
 hmac_key_version smallint NOT NULL CHECK(hmac_key_version>0),
 lookup_hmac bytea NOT NULL CHECK(octet_length(lookup_hmac)=32),
 display_suffix text NOT NULL CHECK(length(display_suffix)=8),
 claim_expires_at timestamptz NOT NULL,
 access_expires_at timestamptz NOT NULL CHECK(access_expires_at>=claim_expires_at),
 enabled boolean NOT NULL DEFAULT true,
 revoked_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(hmac_key_version,lookup_hmac)
);
CREATE TABLE public.tsw_public_zip_orders (
 id uuid PRIMARY KEY,
 inventory_id uuid NOT NULL UNIQUE REFERENCES public.tsw_public_zip_inventory(id) ON DELETE RESTRICT,
 package_id uuid NOT NULL UNIQUE REFERENCES public.tsw_batch_zip_archives(id) ON DELETE RESTRICT,
 customer_id text NOT NULL UNIQUE CHECK(length(customer_id) BETWEEN 1 AND 255),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(id,inventory_id,package_id,customer_id)
);
CREATE TABLE public.tsw_public_zip_tokens (
 id uuid PRIMARY KEY,
 order_id uuid NOT NULL REFERENCES public.tsw_public_zip_orders(id) ON DELETE RESTRICT,
 token_hash bytea NOT NULL UNIQUE CHECK(octet_length(token_hash)=32),
 expires_at timestamptz NOT NULL,
 revoked_at timestamptz,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON public.tsw_public_zip_inventory,public.tsw_public_zip_orders,public.tsw_public_zip_tokens FROM PUBLIC;
-- +goose StatementBegin
CREATE FUNCTION public.tsw_public_zip_inventory_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF TG_OP='INSERT' THEN PERFORM pg_advisory_xact_lock(hashtextextended('tsw.card.lookup.'||NEW.hmac_key_version::text||'/'||encode(NEW.lookup_hmac,'hex'),0)); END IF;
 IF TG_OP='DELETE' OR (TG_OP='UPDATE' AND ROW(NEW.id,NEW.package_id,NEW.owner_id,NEW.hmac_key_version,NEW.lookup_hmac,NEW.display_suffix,NEW.claim_expires_at,NEW.access_expires_at,NEW.created_at) IS DISTINCT FROM ROW(OLD.id,OLD.package_id,OLD.owner_id,OLD.hmac_key_version,OLD.lookup_hmac,OLD.display_suffix,OLD.claim_expires_at,OLD.access_expires_at,OLD.created_at)) THEN RAISE EXCEPTION 'Public inventory binding is immutable'; END IF;
 IF TG_OP='UPDATE' AND OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS DISTINCT FROM OLD.revoked_at THEN RAISE EXCEPTION 'Public revocation is permanent'; END IF;
 IF NOT EXISTS(SELECT 1 FROM public.tsw_batch_zip_archives WHERE id=NEW.package_id AND owner_id=NEW.owner_id) THEN RAISE EXCEPTION 'Public inventory requires owned original package'; END IF;
 IF TG_OP='INSERT' AND EXISTS(SELECT 1 FROM public.tsw_cards WHERE hmac_key_version=NEW.hmac_key_version AND lookup_hmac=NEW.lookup_hmac) THEN RAISE EXCEPTION 'card already authorizes legacy inventory'; END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER tsw_public_zip_inventory_guard BEFORE INSERT OR UPDATE OR DELETE ON public.tsw_public_zip_inventory FOR EACH ROW EXECUTE FUNCTION public.tsw_public_zip_inventory_guard();
CREATE TRIGGER tsw_public_zip_order_immutable BEFORE UPDATE OR DELETE ON public.tsw_public_zip_orders FOR EACH ROW EXECUTE FUNCTION public.tsw_batch_zip_immutable();
-- +goose StatementBegin
CREATE FUNCTION public.tsw_public_zip_order_binding() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF NOT EXISTS(SELECT 1 FROM public.tsw_public_zip_inventory i JOIN public.tsw_batch_zip_receivers r ON r.package_id=i.package_id WHERE i.id=NEW.inventory_id AND i.package_id=NEW.package_id AND i.enabled AND i.revoked_at IS NULL AND i.claim_expires_at>clock_timestamp() AND r.channel='public' AND r.customer_id=NEW.customer_id AND r.authorization_id=NEW.id::text) THEN RAISE EXCEPTION 'Public order requires its exact authorized original reservation'; END IF;
 RETURN NULL;
END;
$$;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER tsw_public_zip_order_binding AFTER INSERT ON public.tsw_public_zip_orders DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.tsw_public_zip_order_binding();
-- +goose StatementBegin
CREATE FUNCTION public.tsw_public_zip_legacy_card_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('tsw.card.lookup.'||NEW.hmac_key_version::text||'/'||encode(NEW.lookup_hmac,'hex'),0));
 IF EXISTS(SELECT 1 FROM public.tsw_public_zip_inventory WHERE hmac_key_version=NEW.hmac_key_version AND lookup_hmac=NEW.lookup_hmac) THEN RAISE EXCEPTION 'card already authorizes ZIP inventory'; END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER tsw_public_zip_legacy_card_guard BEFORE INSERT ON public.tsw_cards FOR EACH ROW EXECUTE FUNCTION public.tsw_public_zip_legacy_card_guard();
-- Receiver/protection base guard uses shared original archived qualification.
-- Independent37 channel hold/publication guards are not replaced.
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.tsw_batch_zip_reservation_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE package uuid:=NEW.package_id; account uuid;
BEGIN
 FOR account IN SELECT target_account_id FROM public.tsw_batch_zip_members WHERE package_id=package ORDER BY target_account_id LOOP
  PERFORM pg_advisory_xact_lock(hashtextextended('tsw.rotation.action.target_account/'||account::text,0));
  IF EXISTS(SELECT 1 FROM public.tsw_batch_memberships m JOIN public.tsw_oauth_assets a ON a.membership_id=m.id JOIN public.tsw_delivery_versions v ON v.oauth_asset_id=a.id WHERE m.target_account_id=account) THEN RAISE EXCEPTION 'existing legacy delivery blocks ZIP reservation'; END IF;
 END LOOP;
 IF TG_TABLE_NAME='tsw_batch_zip_receivers' AND EXISTS(SELECT 1 FROM public.tsw_batch_zip_members m JOIN public.tsw_rotation_join_usage_evidence ev ON ev.attempt_id=m.usage_attempt_id WHERE m.package_id=package AND (NOT public.tsw_archived_batch_zip_ready(m.package_id,m.slot_id) OR ev.expires_at<=clock_timestamp() OR m.usage_attempt_id IS DISTINCT FROM (SELECT id FROM public.tsw_rotation_join_usage_attempts WHERE slot_id=m.slot_id ORDER BY attempt_no DESC LIMIT 1))) THEN RAISE EXCEPTION 'first customer exposure requires latest fresh original qualification'; END IF;
 IF TG_TABLE_NAME='tsw_batch_zip_protections' THEN
  IF EXISTS(SELECT 1 FROM public.tsw_rotation_global_protections p WHERE p.target_account_id=(NEW).target_account_id AND p.status<>'none') THEN RAISE EXCEPTION 'existing global account protection blocks reservation'; END IF;
 END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
CREATE OR REPLACE FUNCTION public.tsw_batch_zip_reservation_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE package uuid:=NEW.package_id; account uuid;
BEGIN
 FOR account IN SELECT target_account_id FROM public.tsw_batch_zip_members WHERE package_id=package ORDER BY target_account_id LOOP
  PERFORM pg_advisory_xact_lock(hashtextextended('tsw.rotation.action.target_account/'||account::text,0));
  IF EXISTS(SELECT 1 FROM public.tsw_batch_memberships m JOIN public.tsw_oauth_assets a ON a.membership_id=m.id JOIN public.tsw_delivery_versions v ON v.oauth_asset_id=a.id WHERE m.target_account_id=account) THEN RAISE EXCEPTION 'existing legacy delivery blocks ZIP reservation'; END IF;
 END LOOP;
 IF TG_TABLE_NAME='tsw_batch_zip_receivers' AND EXISTS(SELECT 1 FROM public.tsw_batch_zip_members m JOIN public.tsw_rotation_join_usage_evidence ev ON ev.attempt_id=m.usage_attempt_id WHERE m.package_id=package AND (NOT public.tsw_rotation_join_usage_ready(m.slot_id) OR ev.expires_at<=clock_timestamp() OR m.usage_attempt_id IS DISTINCT FROM (SELECT id FROM public.tsw_rotation_join_usage_attempts WHERE slot_id=m.slot_id ORDER BY attempt_no DESC LIMIT 1))) THEN RAISE EXCEPTION 'first customer exposure requires latest fresh original qualification'; END IF;
 IF TG_TABLE_NAME='tsw_batch_zip_protections' THEN
  IF EXISTS(SELECT 1 FROM public.tsw_rotation_global_protections p WHERE p.target_account_id=(NEW).target_account_id AND p.status<>'none') THEN RAISE EXCEPTION 'existing global account protection blocks reservation'; END IF;
 END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
DROP TRIGGER tsw_public_zip_legacy_card_guard ON public.tsw_cards;
DROP FUNCTION public.tsw_public_zip_legacy_card_guard();
DROP TABLE public.tsw_public_zip_tokens;
DROP TABLE public.tsw_public_zip_orders;
DROP TABLE public.tsw_public_zip_inventory;
DROP FUNCTION public.tsw_public_zip_order_binding();
DROP FUNCTION public.tsw_public_zip_inventory_guard();
-- +goose StatementBegin
DO $cleanup$
BEGIN
 IF to_regprocedure('public.tsw_channel_original_ready(uuid,uuid)') IS NULL THEN
  DROP FUNCTION public.tsw_archived_batch_zip_ready(uuid,uuid);
 END IF;
END;
$cleanup$;
-- +goose StatementEnd
