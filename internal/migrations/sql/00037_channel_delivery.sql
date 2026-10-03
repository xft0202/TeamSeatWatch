-- +goose Up
CREATE TABLE public.tsw_channel_deliveries (
 package_id uuid PRIMARY KEY REFERENCES public.tsw_batch_zip_archives(id) ON DELETE RESTRICT,
 destination_id uuid NOT NULL REFERENCES public.tsw_delivery_destinations(id) ON DELETE RESTRICT,
 destination_revision bigint NOT NULL CHECK(destination_revision>0),
 destination_name text NOT NULL, endpoint text NOT NULL, target_group text NOT NULL,
 secret_key_version smallint NOT NULL, secret_nonce bytea NOT NULL, secret_ciphertext bytea NOT NULL,
 authorization_digest text NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE public.tsw_channel_objects (
 package_id uuid NOT NULL REFERENCES public.tsw_channel_deliveries(package_id) ON DELETE RESTRICT,
 target_account_id uuid NOT NULL UNIQUE, slot_id uuid NOT NULL UNIQUE,
 PRIMARY KEY(package_id,target_account_id),
 FOREIGN KEY(package_id,target_account_id) REFERENCES public.tsw_batch_zip_members(package_id,target_account_id) ON DELETE RESTRICT
);
CREATE TABLE public.tsw_channel_attempts (
 package_id uuid NOT NULL, target_account_id uuid NOT NULL,
 attempted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 PRIMARY KEY(package_id,target_account_id),
 FOREIGN KEY(package_id,target_account_id) REFERENCES public.tsw_channel_objects(package_id,target_account_id) ON DELETE RESTRICT
);
CREATE TABLE public.tsw_channel_receipts (
 package_id uuid NOT NULL, target_account_id uuid NOT NULL,
 stage text NOT NULL CHECK(stage IN ('received','delivered')), remote_object_id text NOT NULL CHECK(length(remote_object_id) BETWEEN 1 AND 255),
 receipt_id text NOT NULL CHECK(length(receipt_id) BETWEEN 1 AND 255),
 customer_id text, authorization_id text, observed_at timestamptz NOT NULL,
 PRIMARY KEY(package_id,target_account_id,stage),
 FOREIGN KEY(package_id,target_account_id) REFERENCES public.tsw_channel_objects(package_id,target_account_id) ON DELETE RESTRICT,
 CHECK((stage='received' AND customer_id IS NULL AND authorization_id IS NULL) OR (stage='delivered' AND length(customer_id) BETWEEN 1 AND 255 AND length(authorization_id) BETWEEN 1 AND 255))
);
CREATE TABLE public.tsw_channel_associations (
 package_id uuid NOT NULL, target_account_id uuid NOT NULL, stage text NOT NULL,
 PRIMARY KEY(package_id,target_account_id,stage),
 FOREIGN KEY(package_id,target_account_id,stage) REFERENCES public.tsw_channel_receipts(package_id,target_account_id,stage) ON DELETE RESTRICT
);
CREATE TABLE public.tsw_channel_final_attempts (
 package_id uuid PRIMARY KEY REFERENCES public.tsw_batch_zip_receivers(package_id) ON DELETE RESTRICT,
 attempted_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON public.tsw_channel_deliveries,public.tsw_channel_objects,public.tsw_channel_attempts,public.tsw_channel_receipts,public.tsw_channel_associations,public.tsw_channel_final_attempts FROM PUBLIC;
-- +goose StatementBegin
-- Shared37/38 original archived package qualification. No channel dependence.
-- Historical completed release is retained without its former30-second action
-- deadline. Current usage/member/material/token/authorization/epochs remain live.
-- Controlled rotation continuity requires registered server audit facts and a
-- explicit predecessor chains paired by same-transaction audit timestamps/IDs;
-- same-owner/auth-version successors retain the absolute deadline. An
-- original logout/revocation/reset or expired original authority remains denied.
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
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION public.tsw_channel_original_ready(package uuid,slot uuid) RETURNS boolean LANGUAGE sql VOLATILE SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT public.tsw_archived_batch_zip_ready(package,slot) AND EXISTS(
  SELECT 1 FROM public.tsw_channel_deliveries channel
  JOIN public.tsw_batch_zip_archives archive ON archive.id=channel.package_id
  JOIN public.tsw_expiry_rotation_previews preview ON preview.id=archive.preview_id
  WHERE channel.package_id=package AND preview.authorization_digest=channel.authorization_digest);
$$;
-- +goose StatementEnd
ALTER FUNCTION public.tsw_rotation_join_usage_ready(uuid) RENAME TO tsw_rotation_join_usage_ready_before_channel;
-- +goose StatementBegin
CREATE FUNCTION public.tsw_rotation_join_usage_ready(slot uuid) RETURNS boolean LANGUAGE sql VOLATILE SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT public.tsw_rotation_join_usage_ready_before_channel(slot) OR EXISTS(SELECT 1 FROM public.tsw_channel_objects object WHERE object.slot_id=slot AND public.tsw_channel_original_ready(object.package_id,slot) AND NOT EXISTS(SELECT 1 FROM public.tsw_batch_zip_protections protection WHERE protection.target_account_id=object.target_account_id));
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION public.tsw_channel_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE a public.tsw_batch_zip_archives; p public.tsw_expiry_rotation_previews; d public.tsw_delivery_destinations; r public.tsw_channel_receipts;
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'channel obligations and evidence are immutable'; END IF;
 SELECT * INTO a FROM public.tsw_batch_zip_archives WHERE id=NEW.package_id;
 IF TG_TABLE_NAME='tsw_channel_deliveries' THEN
  SELECT * INTO p FROM public.tsw_expiry_rotation_previews WHERE id=a.preview_id;
  SELECT * INTO d FROM public.tsw_delivery_destinations WHERE id=(p.facts->>'destinationId')::uuid;
  IF ROW(NEW.destination_id,NEW.destination_revision,NEW.destination_name,NEW.endpoint,NEW.target_group,NEW.secret_key_version,NEW.secret_nonce,NEW.secret_ciphertext,NEW.authorization_digest) IS DISTINCT FROM ROW(d.id,d.revision,d.name,d.endpoint,d.target_group,d.secret_key_version,d.secret_nonce,d.secret_ciphertext,p.authorization_digest) OR d.revision::text IS DISTINCT FROM p.facts->>'destinationRevision' OR NOT d.enabled OR d.test_connection<>'connected' OR d.test_target<>'connected' OR d.test_revision<>d.revision OR EXISTS(SELECT 1 FROM public.tsw_batch_zip_receivers WHERE package_id=a.id) THEN RAISE EXCEPTION 'channel requires exact original tested destination'; END IF;
 ELSIF TG_TABLE_NAME='tsw_channel_objects' THEN
  PERFORM pg_advisory_xact_lock(hashtextextended('tsw.rotation.action.target_account/'||NEW.target_account_id::text,0));
  IF NOT EXISTS(SELECT 1 FROM public.tsw_batch_zip_members WHERE package_id=NEW.package_id AND target_account_id=NEW.target_account_id AND slot_id=NEW.slot_id AND public.tsw_channel_original_ready(NEW.package_id,slot_id)) OR EXISTS(SELECT 1 FROM public.tsw_batch_zip_protections WHERE target_account_id=NEW.target_account_id) OR EXISTS(SELECT 1 FROM public.tsw_rotation_global_protections WHERE target_account_id=NEW.target_account_id AND status<>'none') OR EXISTS(SELECT 1 FROM public.tsw_batch_memberships bm JOIN public.tsw_oauth_assets oa ON oa.membership_id=bm.id JOIN public.tsw_delivery_versions dv ON dv.oauth_asset_id=oa.id WHERE bm.target_account_id=NEW.target_account_id) THEN RAISE EXCEPTION 'channel object requires unheld exact original qualification'; END IF;
 ELSIF TG_TABLE_NAME='tsw_channel_associations' THEN
  SELECT * INTO r FROM public.tsw_channel_receipts WHERE package_id=NEW.package_id AND target_account_id=NEW.target_account_id AND stage=NEW.stage;
  IF NEW.stage='delivered' AND (NOT EXISTS(SELECT 1 FROM public.tsw_channel_receipts received JOIN public.tsw_channel_associations associated USING(package_id,target_account_id,stage) WHERE received.package_id=r.package_id AND received.target_account_id=r.target_account_id AND received.stage='received' AND received.remote_object_id=r.remote_object_id) OR NOT EXISTS(SELECT 1 FROM public.tsw_batch_zip_receivers WHERE package_id=r.package_id AND channel='owner_channel' AND customer_id=r.customer_id AND authorization_id=r.authorization_id)) THEN RAISE EXCEPTION 'final delivery requires original reception and authorized customer'; END IF;
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER tsw_channel_delivery_guard BEFORE INSERT OR UPDATE OR DELETE ON public.tsw_channel_deliveries FOR EACH ROW EXECUTE FUNCTION public.tsw_channel_guard();
CREATE TRIGGER tsw_channel_object_guard BEFORE INSERT OR UPDATE OR DELETE ON public.tsw_channel_objects FOR EACH ROW EXECUTE FUNCTION public.tsw_channel_guard();
CREATE TRIGGER tsw_channel_attempt_guard BEFORE INSERT OR UPDATE OR DELETE ON public.tsw_channel_attempts FOR EACH ROW EXECUTE FUNCTION public.tsw_channel_guard();
CREATE TRIGGER tsw_channel_receipt_guard BEFORE INSERT OR UPDATE OR DELETE ON public.tsw_channel_receipts FOR EACH ROW EXECUTE FUNCTION public.tsw_channel_guard();
CREATE TRIGGER tsw_channel_association_guard BEFORE INSERT OR UPDATE OR DELETE ON public.tsw_channel_associations FOR EACH ROW EXECUTE FUNCTION public.tsw_channel_guard();
CREATE TRIGGER tsw_channel_final_guard BEFORE INSERT OR UPDATE OR DELETE ON public.tsw_channel_final_attempts FOR EACH ROW EXECUTE FUNCTION public.tsw_channel_guard();
-- +goose StatementBegin
CREATE FUNCTION public.tsw_channel_complete() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF (SELECT count(*) FROM public.tsw_channel_objects WHERE package_id=NEW.package_id)<>(SELECT account_count FROM public.tsw_batch_zip_archives WHERE id=NEW.package_id) THEN RAISE EXCEPTION 'channel requires complete original batch'; END IF;
 RETURN NULL;
END; $$;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER tsw_channel_complete AFTER INSERT ON public.tsw_channel_deliveries DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.tsw_channel_complete();
-- +goose StatementBegin
CREATE FUNCTION public.tsw_channel_receiver_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF TG_TABLE_NAME='tsw_batch_zip_receivers' THEN
  IF NEW.channel<>'owner_channel' AND EXISTS(SELECT 1 FROM public.tsw_channel_objects WHERE package_id=NEW.package_id) THEN RAISE EXCEPTION 'original channel obligation cannot become Public sale'; END IF;
 ELSE
  IF EXISTS(SELECT 1 FROM public.tsw_channel_objects WHERE target_account_id=NEW.target_account_id AND package_id<>NEW.package_id) THEN RAISE EXCEPTION 'account held by original channel obligation'; END IF;
 END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER tsw_channel_receiver_guard BEFORE INSERT ON public.tsw_batch_zip_receivers FOR EACH ROW EXECUTE FUNCTION public.tsw_channel_receiver_guard();
CREATE TRIGGER tsw_channel_protection_guard BEFORE INSERT ON public.tsw_batch_zip_protections FOR EACH ROW EXECUTE FUNCTION public.tsw_channel_receiver_guard();
-- Existing legacy publishers and new ZIP associations cannot bypass a channel
-- obligation through another Workspace or batch.
-- +goose StatementBegin
CREATE FUNCTION public.tsw_channel_publication_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE account uuid;
BEGIN
 IF TG_TABLE_NAME='tsw_delivery_versions' THEN
  SELECT m.target_account_id INTO STRICT account FROM public.tsw_oauth_assets a JOIN public.tsw_batch_memberships m ON m.id=a.membership_id WHERE a.id=NEW.oauth_asset_id;
 ELSE account:=NEW.target_account_id;
 END IF;
 PERFORM pg_advisory_xact_lock(hashtextextended('tsw.rotation.action.target_account/'||account::text,0));
 IF EXISTS(SELECT 1 FROM public.tsw_channel_objects WHERE target_account_id=account) THEN RAISE EXCEPTION 'original channel account obligation blocks another publication'; END IF;
 RETURN NEW;
END; $$;
-- +goose StatementEnd
CREATE TRIGGER tsw_channel_legacy_guard BEFORE INSERT ON public.tsw_delivery_versions FOR EACH ROW EXECUTE FUNCTION public.tsw_channel_publication_guard();
CREATE TRIGGER tsw_channel_zip_guard BEFORE INSERT ON public.tsw_batch_zip_members FOR EACH ROW EXECUTE FUNCTION public.tsw_channel_publication_guard();
CREATE OR REPLACE VIEW public.tsw_rotation_effective_protections AS
 SELECT p.target_account_id,CASE WHEN d.package_id IS NULL THEN 'sale_reserved' ELSE 'delivered' END AS status,a.content_sha256 AS evidence_id,r.reserved_at AS observed_at
 FROM public.tsw_batch_zip_protections p JOIN public.tsw_batch_zip_archives a ON a.id=p.package_id JOIN public.tsw_batch_zip_receivers r ON r.package_id=p.package_id LEFT JOIN public.tsw_batch_zip_delivered d ON d.package_id=p.package_id
 UNION ALL SELECT o.target_account_id,'delivery_pending',a.content_sha256,c.created_at FROM public.tsw_channel_objects o JOIN public.tsw_channel_deliveries c USING(package_id) JOIN public.tsw_batch_zip_archives a ON a.id=o.package_id WHERE NOT EXISTS(SELECT 1 FROM public.tsw_batch_zip_protections p WHERE p.target_account_id=o.target_account_id)
 UNION ALL SELECT target_account_id,status,evidence_id,observed_at FROM public.tsw_rotation_global_protections old WHERE NOT EXISTS(SELECT 1 FROM public.tsw_batch_zip_protections p WHERE p.target_account_id=old.target_account_id) AND NOT EXISTS(SELECT 1 FROM public.tsw_channel_objects o WHERE o.target_account_id=old.target_account_id);
-- +goose Down
DROP FUNCTION public.tsw_rotation_join_usage_ready(uuid);
ALTER FUNCTION public.tsw_rotation_join_usage_ready_before_channel(uuid) RENAME TO tsw_rotation_join_usage_ready;
DROP FUNCTION public.tsw_channel_original_ready(uuid,uuid);
DROP FUNCTION public.tsw_archived_batch_zip_ready(uuid,uuid);
CREATE OR REPLACE VIEW public.tsw_rotation_effective_protections AS
 SELECT p.target_account_id,CASE WHEN d.package_id IS NULL THEN 'sale_reserved' ELSE 'delivered' END AS status,a.content_sha256 AS evidence_id,r.reserved_at AS observed_at
 FROM public.tsw_batch_zip_protections p JOIN public.tsw_batch_zip_archives a ON a.id=p.package_id JOIN public.tsw_batch_zip_receivers r ON r.package_id=p.package_id LEFT JOIN public.tsw_batch_zip_delivered d ON d.package_id=p.package_id
 UNION ALL SELECT target_account_id,status,evidence_id,observed_at FROM public.tsw_rotation_global_protections old WHERE NOT EXISTS(SELECT 1 FROM public.tsw_batch_zip_protections p WHERE p.target_account_id=old.target_account_id);
DROP TRIGGER tsw_channel_legacy_guard ON public.tsw_delivery_versions;
DROP TRIGGER tsw_channel_zip_guard ON public.tsw_batch_zip_members;
DROP FUNCTION public.tsw_channel_publication_guard();
DROP TRIGGER tsw_channel_receiver_guard ON public.tsw_batch_zip_receivers;
DROP TRIGGER tsw_channel_protection_guard ON public.tsw_batch_zip_protections;
DROP TABLE public.tsw_channel_final_attempts,public.tsw_channel_associations,public.tsw_channel_receipts,public.tsw_channel_attempts,public.tsw_channel_objects,public.tsw_channel_deliveries;
DROP FUNCTION public.tsw_channel_complete(),public.tsw_channel_guard(),public.tsw_channel_receiver_guard();
