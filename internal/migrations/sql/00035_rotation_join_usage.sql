-- +goose Up
-- Original-slot first usage journal. Its own writes are not a source epoch:
-- writing a fact cannot silently reauthorize (or invalidate) sibling slots.
-- Positive history lives in immutable evidence and is consumed by later gates.
CREATE TABLE public.tsw_rotation_join_usage_attempts (
 id uuid PRIMARY KEY,
 slot_id uuid NOT NULL REFERENCES public.tsw_rotation_join_credential_attempts(slot_id) ON DELETE RESTRICT,
 attempt_no integer NOT NULL CHECK(attempt_no>0),
 credential_attempt_id uuid NOT NULL REFERENCES public.tsw_rotation_join_credential_generations(attempt_id) ON DELETE RESTRICT,
 state text NOT NULL DEFAULT 'pending' CHECK(state IN ('pending','complete')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 lease_owner uuid,
 lease_token uuid,
 lease_epoch bigint NOT NULL DEFAULT 0 CHECK(lease_epoch>=0),
 lease_expires_at timestamptz,
 owner_session uuid,
 UNIQUE(slot_id,attempt_no),
 CHECK((lease_owner IS NULL AND lease_token IS NULL AND lease_expires_at IS NULL AND owner_session IS NULL) OR
       (lease_owner IS NOT NULL AND lease_token IS NOT NULL AND lease_expires_at IS NOT NULL AND owner_session IS NOT NULL AND lease_epoch>0))
);
CREATE TABLE public.tsw_rotation_join_usage_evidence (
 attempt_id uuid PRIMARY KEY REFERENCES public.tsw_rotation_join_usage_attempts(id) ON DELETE RESTRICT,
 target_account_id uuid NOT NULL REFERENCES public.tsw_target_accounts(id) ON DELETE RESTRICT,
 workspace_id uuid NOT NULL REFERENCES public.tsw_workspaces(id) ON DELETE RESTRICT,
 scope text NOT NULL CHECK(scope IN ('workspace','account')),
 result text NOT NULL CHECK(result IN ('zero','positive','unknown')),
 diagnostic text NOT NULL CHECK(diagnostic IN ('usage_zero','usage_positive','usage_unknown','usage_incomplete','usage_credentials_invalid','usage_scope_mismatch','usage_scope_unknown')),
 windows jsonb NOT NULL CHECK(jsonb_typeof(windows)='array'),
 evidence_digest text NOT NULL CHECK(evidence_digest ~ '^[a-f0-9]{64}$'),
 observed_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 lease_owner uuid NOT NULL,
 lease_token uuid NOT NULL,
 lease_epoch bigint NOT NULL,
 owner_session uuid NOT NULL,
 CHECK(expires_at>observed_at AND expires_at<=observed_at+interval '5 minutes')
);
CREATE INDEX tsw_rotation_join_usage_history ON public.tsw_rotation_join_usage_evidence(target_account_id,scope,workspace_id) WHERE result='positive';
REVOKE ALL ON public.tsw_rotation_join_usage_attempts,public.tsw_rotation_join_usage_evidence FROM PUBLIC;
-- +goose StatementBegin
CREATE FUNCTION public.tsw_rotation_join_usage_authority(slot uuid,session uuid) RETURNS boolean LANGUAGE sql VOLATILE SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT public.tsw_rotation_join_credential_authority(slot,session) AND EXISTS(
 SELECT 1 FROM public.tsw_rotation_join_credential_attempts ca
 JOIN public.tsw_rotation_join_credential_generations cg USING(attempt_id)
 JOIN public.tsw_rotation_candidate_join_intents i USING(slot_id)
 JOIN public.tsw_rotation_removals r ON r.preview_id=i.preview_id AND r.workspace_id=i.workspace_id
 JOIN public.tsw_expiry_rotation_previews p ON p.id=i.preview_id
 WHERE ca.slot_id=slot AND cg.candidate_account_id=i.candidate_account_id AND cg.workspace_id=i.workspace_id
 AND cg.expires_at>clock_timestamp()+interval '1 minute' AND r.stopped_at IS NULL
 AND p.status='authorized' AND p.revoked_at IS NULL AND p.expires_at>clock_timestamp()
 AND NOT EXISTS(SELECT 1 FROM jsonb_each_text(p.epoch_versions) v LEFT JOIN public.tsw_rotation_epochs e ON v.key=e.kind||'/'||e.id::text WHERE e.version IS NULL OR e.version::text<>v.value));
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION public.tsw_rotation_join_usage_attempt_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
BEGIN
 PERFORM pg_advisory_xact_lock(hashtextextended('tsw.rotation.action.target_account/'||(SELECT candidate_account_id::text FROM public.tsw_rotation_join_credential_attempts WHERE slot_id=COALESCE(NEW.slot_id,OLD.slot_id)),0));
 IF TG_OP='DELETE' THEN RAISE EXCEPTION 'usage obligation cannot be erased'; END IF;
 IF TG_OP='INSERT' THEN
  IF NEW.state<>'pending' OR NEW.lease_epoch<>0 OR NEW.lease_owner IS NOT NULL OR NOT EXISTS(SELECT 1 FROM public.tsw_rotation_join_credential_attempts ca JOIN public.tsw_rotation_join_credential_generations cg USING(attempt_id) WHERE ca.slot_id=NEW.slot_id AND ca.attempt_id=NEW.credential_attempt_id)
  OR EXISTS(SELECT 1 FROM public.tsw_rotation_join_usage_attempts prior WHERE prior.slot_id=NEW.slot_id AND prior.state='pending')
  OR NEW.attempt_no<>COALESCE((SELECT max(attempt_no)+1 FROM public.tsw_rotation_join_usage_attempts prior WHERE prior.slot_id=NEW.slot_id),1)
  THEN RAISE EXCEPTION 'usage attempt requires original completed credentials and sequential obligation'; END IF;
 ELSE
  IF ROW(NEW.id,NEW.slot_id,NEW.attempt_no,NEW.credential_attempt_id,NEW.created_at) IS DISTINCT FROM ROW(OLD.id,OLD.slot_id,OLD.attempt_no,OLD.credential_attempt_id,OLD.created_at) OR OLD.state='complete' THEN RAISE EXCEPTION 'usage attempt binding is immutable'; END IF;
  IF NEW.lease_epoch=OLD.lease_epoch+1 THEN
   IF NEW.state<>OLD.state OR OLD.lease_expires_at>clock_timestamp() OR NEW.lease_owner IS NULL OR NEW.lease_token IS NOT DISTINCT FROM OLD.lease_token OR NEW.lease_expires_at<=clock_timestamp() OR NOT public.tsw_rotation_join_usage_authority(NEW.slot_id,NEW.owner_session) THEN RAISE EXCEPTION 'usage lease claim stale'; END IF;
  ELSIF NEW.lease_epoch<>OLD.lease_epoch OR OLD.lease_owner IS NULL OR OLD.lease_expires_at<=clock_timestamp() OR NEW.lease_owner IS NOT NULL OR NEW.lease_token IS NOT NULL OR NEW.owner_session IS NOT NULL OR NEW.lease_expires_at IS NOT NULL THEN RAISE EXCEPTION 'usage lease permits exact release or completion';
  ELSIF NEW.state='complete' AND (NOT public.tsw_rotation_join_usage_authority(OLD.slot_id,OLD.owner_session) OR NOT EXISTS(SELECT 1 FROM public.tsw_rotation_join_usage_evidence e WHERE e.attempt_id=OLD.id AND e.lease_epoch=OLD.lease_epoch AND e.lease_owner=OLD.lease_owner AND e.lease_token=OLD.lease_token)) THEN RAISE EXCEPTION 'usage completion requires atomic evidence'; END IF;
 END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER tsw_rotation_join_usage_attempt_guard BEFORE INSERT OR UPDATE OR DELETE ON public.tsw_rotation_join_usage_attempts FOR EACH ROW EXECUTE FUNCTION public.tsw_rotation_join_usage_attempt_guard();
-- +goose StatementBegin
CREATE FUNCTION public.tsw_rotation_join_usage_evidence_guard() RETURNS trigger LANGUAGE plpgsql SET search_path=pg_catalog,public,pg_temp AS $$
DECLARE a public.tsw_rotation_join_usage_attempts; ca public.tsw_rotation_join_credential_attempts; w jsonb; positive boolean:=false; seen text[]:=ARRAY[]::text[];
BEGIN
 IF TG_OP<>'INSERT' THEN RAISE EXCEPTION 'usage evidence is append-only'; END IF;
 SELECT * INTO a FROM public.tsw_rotation_join_usage_attempts WHERE id=NEW.attempt_id FOR UPDATE;
 SELECT * INTO ca FROM public.tsw_rotation_join_credential_attempts WHERE attempt_id=a.credential_attempt_id;
 PERFORM pg_advisory_xact_lock(hashtextextended('tsw.rotation.action.target_account/'||ca.candidate_account_id::text,0));
 IF a.id IS NULL OR a.state<>'pending' OR ca.attempt_id IS NULL OR ROW(a.lease_owner,a.lease_token,a.lease_epoch,a.owner_session) IS DISTINCT FROM ROW(NEW.lease_owner,NEW.lease_token,NEW.lease_epoch,NEW.owner_session)
 OR a.lease_expires_at<=clock_timestamp() OR NOT public.tsw_rotation_join_usage_authority(a.slot_id,NEW.owner_session)
 OR ROW(NEW.target_account_id,NEW.workspace_id) IS DISTINCT FROM ROW(ca.candidate_account_id,ca.workspace_id)
 OR NEW.observed_at>clock_timestamp() OR NEW.observed_at<clock_timestamp()-interval '30 seconds' OR NEW.expires_at<=clock_timestamp()
 THEN RAISE EXCEPTION 'usage evidence requires original binding and live lease'; END IF;
 FOR w IN SELECT * FROM jsonb_array_elements(NEW.windows) LOOP
  IF NOT (w ? 'usedPercent' AND w ? 'seconds' AND w ? 'resetsAt') OR jsonb_typeof(w->'usedPercent') IS DISTINCT FROM 'number' OR (w->>'usedPercent')::numeric<0 OR (w->>'usedPercent')::numeric>100 OR COALESCE((w->>'seconds')::bigint,0)<=0 OR (w->>'seconds')::bigint>31536000 OR (w->>'resetsAt')::timestamptz<=NEW.observed_at OR w->>'seconds'=ANY(seen) THEN RAISE EXCEPTION 'usage window invalid'; END IF;
  seen:=array_append(seen,w->>'seconds'); positive:=positive OR (w->>'usedPercent')::numeric>0;
 END LOOP;
 IF NEW.result='positive' AND NOT positive OR NEW.result='zero' AND (positive OR COALESCE(array_length(seen,1),0)<>2 OR NOT ('18000'=ANY(seen) AND '604800'=ANY(seen)) OR NEW.diagnostic<>'usage_zero') THEN RAISE EXCEPTION 'usage verdict lacks measured windows'; END IF;
 RETURN NEW;
END;
$$;
-- +goose StatementEnd
CREATE TRIGGER tsw_rotation_join_usage_evidence_guard BEFORE INSERT OR UPDATE OR DELETE ON public.tsw_rotation_join_usage_evidence FOR EACH ROW EXECUTE FUNCTION public.tsw_rotation_join_usage_evidence_guard();
-- +goose StatementBegin
CREATE FUNCTION public.tsw_rotation_join_usage_blocks_candidate(account uuid,workspace uuid) RETURNS boolean LANGUAGE sql VOLATILE SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT EXISTS(SELECT 1 FROM public.tsw_rotation_join_usage_evidence e WHERE e.target_account_id=account AND e.result='positive' AND (e.scope='account' OR e.workspace_id=workspace))
 OR EXISTS(SELECT 1 FROM public.tsw_rotation_join_credential_attempts ca JOIN public.tsw_rotation_join_usage_attempts a ON a.credential_attempt_id=ca.attempt_id LEFT JOIN public.tsw_rotation_join_usage_evidence e ON e.attempt_id=a.id WHERE ca.candidate_account_id=account AND ca.workspace_id=workspace AND a.attempt_no=(SELECT max(attempt_no) FROM public.tsw_rotation_join_usage_attempts WHERE slot_id=a.slot_id) AND (a.state='pending' OR e.result='unknown' OR e.scope<>'workspace'));
$$;
-- +goose StatementEnd
-- +goose StatementBegin
CREATE FUNCTION public.tsw_rotation_join_usage_ready(slot uuid) RETURNS boolean LANGUAGE sql VOLATILE SET search_path=pg_catalog,public,pg_temp AS $$
 SELECT EXISTS(SELECT 1 FROM public.tsw_rotation_join_usage_attempts a
 JOIN public.tsw_rotation_join_usage_evidence e ON e.attempt_id=a.id
 JOIN public.tsw_rotation_join_credential_attempts ca ON ca.attempt_id=a.credential_attempt_id
 JOIN public.tsw_rotation_join_credential_generations g ON g.attempt_id=ca.attempt_id
 JOIN public.tsw_rotation_candidate_join_intents i ON i.slot_id=a.slot_id
 WHERE a.slot_id=slot AND a.attempt_no=(SELECT max(attempt_no) FROM public.tsw_rotation_join_usage_attempts WHERE slot_id=slot)
 AND a.state='complete' AND e.result='zero' AND e.scope='workspace'
 AND e.observed_at<=clock_timestamp() AND e.observed_at>clock_timestamp()-interval '5 minutes' AND e.expires_at>clock_timestamp()
 AND public.tsw_rotation_join_usage_authority(slot,i.authorized_session)
 AND NOT EXISTS(SELECT 1 FROM public.tsw_rotation_join_usage_evidence history WHERE history.target_account_id=e.target_account_id AND history.result='positive' AND (history.scope='account' OR history.workspace_id=e.workspace_id))
 AND NOT EXISTS(SELECT 1 FROM public.tsw_rotation_usage_ledger history WHERE history.target_account_id=e.target_account_id AND history.workspace_id=e.workspace_id AND history.ever_used)
 AND NOT EXISTS(SELECT 1 FROM public.tsw_batch_memberships bm JOIN public.tsw_oauth_assets oa ON oa.membership_id=bm.id JOIN public.tsw_delivery_versions dv ON dv.oauth_asset_id=oa.id WHERE bm.target_account_id=e.target_account_id));
$$;
-- +goose StatementEnd
-- +goose Down
DROP FUNCTION public.tsw_rotation_join_usage_blocks_candidate(uuid,uuid);
DROP FUNCTION public.tsw_rotation_join_usage_ready(uuid);
DROP TABLE public.tsw_rotation_join_usage_evidence;
DROP TABLE public.tsw_rotation_join_usage_attempts;
DROP FUNCTION public.tsw_rotation_join_usage_evidence_guard();
DROP FUNCTION public.tsw_rotation_join_usage_attempt_guard();
DROP FUNCTION public.tsw_rotation_join_usage_authority(uuid,uuid);
