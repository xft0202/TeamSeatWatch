-- +goose Up
-- Derived package/receiver journals do not rewrite source epochs or released
-- slot obligations. A customer reservation is permanent and precedes exposure.
CREATE TABLE public.tsw_batch_zip_archives (
 id uuid PRIMARY KEY,
 preview_id uuid NOT NULL UNIQUE REFERENCES public.tsw_expiry_rotation_previews(id) ON DELETE RESTRICT,
 owner_id uuid NOT NULL REFERENCES public.tsw_owners(id) ON DELETE RESTRICT,
 workspace_id uuid NOT NULL REFERENCES public.tsw_workspaces(id) ON DELETE RESTRICT,
 batch_id uuid NOT NULL REFERENCES public.tsw_standby_child_batches(id) ON DELETE RESTRICT,
 batch_version bigint NOT NULL CHECK(batch_version>0),
 snapshot_digest text NOT NULL CHECK(snapshot_digest ~ '^[a-f0-9]{64}$'),
 account_count integer NOT NULL CHECK(account_count BETWEEN 1 AND 999),
 filename text NOT NULL CHECK(filename ~ '^Apophis-TeamSeatWatch-[0-9]{4}(-[0-9]{2}){5}\.zip$'),
 content_sha256 text NOT NULL CHECK(content_sha256 ~ '^[a-f0-9]{64}$'),
 key_version smallint NOT NULL CHECK(key_version>0), nonce bytea NOT NULL CHECK(octet_length(nonce)=12),
 sealed_archive bytea NOT NULL CHECK(octet_length(sealed_archive)>16),
 created_at timestamptz NOT NULL
);
CREATE TABLE public.tsw_batch_zip_members (
 package_id uuid NOT NULL REFERENCES public.tsw_batch_zip_archives(id) ON DELETE RESTRICT,
 ordinal integer NOT NULL CHECK(ordinal>0),
 slot_id uuid NOT NULL UNIQUE REFERENCES public.tsw_rotation_join_credential_attempts(slot_id) ON DELETE RESTRICT,
 target_account_id uuid NOT NULL REFERENCES public.tsw_target_accounts(id) ON DELETE RESTRICT,
 credential_attempt_id uuid NOT NULL REFERENCES public.tsw_rotation_join_credential_generations(attempt_id) ON DELETE RESTRICT,
 usage_attempt_id uuid NOT NULL REFERENCES public.tsw_rotation_join_usage_evidence(attempt_id) ON DELETE RESTRICT,
 PRIMARY KEY(package_id,target_account_id), UNIQUE(package_id,ordinal)
);
CREATE TABLE public.tsw_batch_zip_receivers (
 package_id uuid PRIMARY KEY REFERENCES public.tsw_batch_zip_archives(id) ON DELETE RESTRICT,
 channel text NOT NULL CHECK(channel IN ('owner_channel','public')),
 customer_id text NOT NULL CHECK(length(customer_id) BETWEEN 1 AND 255),
 authorization_id text NOT NULL CHECK(length(authorization_id) BETWEEN 1 AND 255),
 reserved_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 UNIQUE(package_id,customer_id)
);
CREATE TABLE public.tsw_batch_zip_protections (
 target_account_id uuid PRIMARY KEY REFERENCES public.tsw_target_accounts(id) ON DELETE RESTRICT,
 package_id uuid NOT NULL,
 customer_id text NOT NULL,
 FOREIGN KEY(package_id,target_account_id) REFERENCES public.tsw_batch_zip_members(package_id,target_account_id) ON DELETE RESTRICT,
 FOREIGN KEY(package_id,customer_id) REFERENCES public.tsw_batch_zip_receivers(package_id,customer_id) ON DELETE RESTRICT
);
CREATE TABLE public.tsw_batch_zip_delivered (
 package_id uuid PRIMARY KEY REFERENCES public.tsw_batch_zip_receivers(package_id) ON DELETE RESTRICT,
 receipt_id text NOT NULL CHECK(length(receipt_id) BETWEEN 1 AND 255),
 delivered_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
REVOKE ALL ON public.tsw_batch_zip_archives,public.tsw_batch_zip_members,public.tsw_batch_zip_receivers,public.tsw_batch_zip_protections,public.tsw_batch_zip_delivered FROM PUBLIC;
-- +goose StatementBegin
CREATE FUNCTION public.tsw_batch_zip_immutable() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN RAISE EXCEPTION 'batch ZIP and customer obligations are immutable'; END;
$$;
-- +goose StatementEnd
CREATE TRIGGER tsw_batch_zip_archive_immutable BEFORE UPDATE OR DELETE ON public.tsw_batch_zip_archives FOR EACH ROW EXECUTE FUNCTION public.tsw_batch_zip_immutable();
CREATE TRIGGER tsw_batch_zip_member_immutable BEFORE UPDATE OR DELETE ON public.tsw_batch_zip_members FOR EACH ROW EXECUTE FUNCTION public.tsw_batch_zip_immutable();
CREATE TRIGGER tsw_batch_zip_receiver_immutable BEFORE UPDATE OR DELETE ON public.tsw_batch_zip_receivers FOR EACH ROW EXECUTE FUNCTION public.tsw_batch_zip_immutable();
CREATE TRIGGER tsw_batch_zip_protection_immutable BEFORE UPDATE OR DELETE ON public.tsw_batch_zip_protections FOR EACH ROW EXECUTE FUNCTION public.tsw_batch_zip_immutable();
CREATE TRIGGER tsw_batch_zip_delivered_immutable BEFORE UPDATE OR DELETE ON public.tsw_batch_zip_delivered FOR EACH ROW EXECUTE FUNCTION public.tsw_batch_zip_immutable();
-- +goose StatementBegin
CREATE FUNCTION public.tsw_batch_zip_binding_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE a public.tsw_batch_zip_archives; i public.tsw_rotation_candidate_join_intents; ca public.tsw_rotation_join_credential_attempts;
BEGIN
 SELECT * INTO a FROM public.tsw_batch_zip_archives WHERE id=NEW.package_id;
 SELECT * INTO i FROM public.tsw_rotation_candidate_join_intents WHERE slot_id=NEW.slot_id;
 SELECT * INTO ca FROM public.tsw_rotation_join_credential_attempts WHERE slot_id=NEW.slot_id;
 PERFORM pg_advisory_xact_lock(hashtextextended('tsw.rotation.action.target_account/'||NEW.target_account_id::text,0));
 IF a.id IS NULL OR ROW(i.preview_id,i.workspace_id,i.candidate_account_id,i.owner_id) IS DISTINCT FROM ROW(a.preview_id,a.workspace_id,NEW.target_account_id,a.owner_id)
 OR ca.attempt_id IS DISTINCT FROM NEW.credential_attempt_id OR ca.candidate_account_id IS DISTINCT FROM NEW.target_account_id
 OR NOT public.tsw_rotation_join_usage_ready(NEW.slot_id)
 OR NOT EXISTS(SELECT 1 FROM public.tsw_rotation_join_usage_attempts ua WHERE ua.id=NEW.usage_attempt_id AND ua.slot_id=NEW.slot_id AND ua.credential_attempt_id=NEW.credential_attempt_id AND ua.attempt_no=(SELECT max(attempt_no) FROM public.tsw_rotation_join_usage_attempts WHERE slot_id=NEW.slot_id))
 THEN RAISE EXCEPTION 'batch ZIP member requires exact ready original object'; END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER tsw_batch_zip_binding_guard BEFORE INSERT ON public.tsw_batch_zip_members FOR EACH ROW EXECUTE FUNCTION public.tsw_batch_zip_binding_guard();
-- +goose StatementBegin
CREATE FUNCTION public.tsw_batch_zip_complete_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE a public.tsw_batch_zip_archives; p public.tsw_expiry_rotation_previews;
BEGIN
 IF TG_TABLE_NAME='tsw_batch_zip_archives' THEN
 SELECT * INTO a FROM public.tsw_batch_zip_archives WHERE id=NEW.id;
 ELSE
 SELECT * INTO a FROM public.tsw_batch_zip_archives WHERE id=NEW.package_id;
 END IF;
 SELECT * INTO p FROM public.tsw_expiry_rotation_previews WHERE id=a.preview_id;
 IF a.owner_id<>p.owner_id OR a.workspace_id<>p.workspace_id OR a.batch_id::text IS DISTINCT FROM p.facts->>'batchId' OR a.batch_version::text IS DISTINCT FROM p.facts->>'batchVersion' OR a.snapshot_digest<>p.digest
 OR a.account_count<>jsonb_array_length(p.assignments) OR a.account_count<>(SELECT count(*) FROM public.tsw_rotation_removal_slots WHERE preview_id=p.id)
 OR a.account_count<>(SELECT count(*) FROM public.tsw_batch_zip_members WHERE package_id=a.id)
 OR EXISTS(SELECT 1 FROM public.tsw_rotation_removal_slots s WHERE s.preview_id=p.id AND NOT EXISTS(SELECT 1 FROM public.tsw_batch_zip_members m WHERE m.package_id=a.id AND m.slot_id=s.id AND m.target_account_id=s.candidate_account_id))
 THEN RAISE EXCEPTION 'batch ZIP archive requires complete original batch association'; END IF;
 RETURN NULL;
END;
$$;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER tsw_batch_zip_archive_complete AFTER INSERT ON public.tsw_batch_zip_archives DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.tsw_batch_zip_complete_guard();
CREATE CONSTRAINT TRIGGER tsw_batch_zip_members_complete AFTER INSERT ON public.tsw_batch_zip_members DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.tsw_batch_zip_complete_guard();
-- +goose StatementBegin
CREATE FUNCTION public.tsw_batch_zip_reservation_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
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
CREATE TRIGGER tsw_batch_zip_reservation_guard BEFORE INSERT ON public.tsw_batch_zip_receivers FOR EACH ROW EXECUTE FUNCTION public.tsw_batch_zip_reservation_guard();
CREATE TRIGGER tsw_batch_zip_protection_guard BEFORE INSERT ON public.tsw_batch_zip_protections FOR EACH ROW EXECUTE FUNCTION public.tsw_batch_zip_reservation_guard();
-- +goose StatementBegin
CREATE FUNCTION public.tsw_batch_zip_receiver_complete() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 IF EXISTS(SELECT 1 FROM public.tsw_batch_zip_members m WHERE m.package_id=NEW.package_id AND NOT EXISTS(SELECT 1 FROM public.tsw_batch_zip_protections p WHERE p.package_id=m.package_id AND p.target_account_id=m.target_account_id)) THEN RAISE EXCEPTION 'customer reservation requires whole account protection'; END IF;
 RETURN NULL;
END;
$$;
-- +goose StatementEnd
CREATE CONSTRAINT TRIGGER tsw_batch_zip_receiver_complete AFTER INSERT ON public.tsw_batch_zip_receivers DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION public.tsw_batch_zip_receiver_complete();
-- Every legacy publisher, including direct SQL and reclaim, shares the same
-- account fence as ZIP reservation. Existing versions remain readable.
-- +goose StatementBegin
CREATE FUNCTION public.tsw_batch_zip_legacy_publication_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE account uuid;
BEGIN
 SELECT m.target_account_id INTO STRICT account FROM public.tsw_oauth_assets a JOIN public.tsw_batch_memberships m ON m.id=a.membership_id WHERE a.id=NEW.oauth_asset_id;
 PERFORM pg_advisory_xact_lock(hashtextextended('tsw.rotation.action.target_account/'||account::text,0));
 IF EXISTS(SELECT 1 FROM public.tsw_batch_zip_protections WHERE target_account_id=account) THEN RAISE EXCEPTION 'ZIP account protection blocks legacy delivery publication'; END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER tsw_batch_zip_legacy_publication_guard BEFORE INSERT ON public.tsw_delivery_versions FOR EACH ROW EXECUTE FUNCTION public.tsw_batch_zip_legacy_publication_guard();
CREATE VIEW public.tsw_rotation_effective_protections AS
 SELECT p.target_account_id,CASE WHEN d.package_id IS NULL THEN 'sale_reserved' ELSE 'delivered' END AS status,a.content_sha256 AS evidence_id,r.reserved_at AS observed_at
 FROM public.tsw_batch_zip_protections p JOIN public.tsw_batch_zip_archives a ON a.id=p.package_id JOIN public.tsw_batch_zip_receivers r ON r.package_id=p.package_id LEFT JOIN public.tsw_batch_zip_delivered d ON d.package_id=p.package_id
 UNION ALL SELECT target_account_id,status,evidence_id,observed_at FROM public.tsw_rotation_global_protections old WHERE NOT EXISTS(SELECT 1 FROM public.tsw_batch_zip_protections p WHERE p.target_account_id=old.target_account_id);
REVOKE ALL ON public.tsw_rotation_effective_protections FROM PUBLIC;
ALTER FUNCTION public.tsw_rotation_join_credential_authority(uuid,uuid) RENAME TO tsw_rotation_join_credential_authority_before_zip;
-- +goose StatementBegin
CREATE FUNCTION public.tsw_rotation_join_credential_authority(slot uuid,session uuid) RETURNS boolean LANGUAGE sql VOLATILE SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT public.tsw_rotation_join_credential_authority_before_zip(slot,session) AND NOT EXISTS(SELECT 1 FROM public.tsw_batch_zip_protections p JOIN public.tsw_rotation_join_credential_attempts ca ON ca.candidate_account_id=p.target_account_id WHERE ca.slot_id=slot);
$$;
-- +goose StatementEnd
ALTER FUNCTION public.tsw_rotation_join_usage_ready(uuid) RENAME TO tsw_rotation_join_usage_ready_before_zip;
-- +goose StatementBegin
CREATE FUNCTION public.tsw_rotation_join_usage_ready(slot uuid) RETURNS boolean LANGUAGE sql VOLATILE SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT public.tsw_rotation_join_usage_ready_before_zip(slot) AND NOT EXISTS(SELECT 1 FROM public.tsw_batch_zip_protections p JOIN public.tsw_rotation_join_credential_attempts ca ON ca.candidate_account_id=p.target_account_id WHERE ca.slot_id=slot);
$$;
-- +goose StatementEnd
-- +goose Down
DROP TRIGGER tsw_batch_zip_legacy_publication_guard ON public.tsw_delivery_versions;
DROP FUNCTION public.tsw_batch_zip_legacy_publication_guard();
DROP FUNCTION public.tsw_rotation_join_credential_authority(uuid,uuid);
ALTER FUNCTION public.tsw_rotation_join_credential_authority_before_zip(uuid,uuid) RENAME TO tsw_rotation_join_credential_authority;
DROP VIEW public.tsw_rotation_effective_protections;
DROP FUNCTION public.tsw_rotation_join_usage_ready(uuid);
ALTER FUNCTION public.tsw_rotation_join_usage_ready_before_zip(uuid) RENAME TO tsw_rotation_join_usage_ready;
DROP TABLE public.tsw_batch_zip_delivered;
DROP TABLE public.tsw_batch_zip_protections;
DROP TABLE public.tsw_batch_zip_receivers;
DROP TABLE public.tsw_batch_zip_members;
DROP TABLE public.tsw_batch_zip_archives;
DROP FUNCTION public.tsw_batch_zip_receiver_complete();
DROP FUNCTION public.tsw_batch_zip_reservation_guard();
DROP FUNCTION public.tsw_batch_zip_complete_guard();
DROP FUNCTION public.tsw_batch_zip_binding_guard();
DROP FUNCTION public.tsw_batch_zip_immutable();
