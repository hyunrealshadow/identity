-- Transactional security journal. Never copy credential data or token payloads.
CREATE TABLE IF NOT EXISTS security_audit (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    transaction_id bigint NOT NULL DEFAULT txid_current(),
    resource_type text NOT NULL,
    resource_oid uuid NOT NULL,
    subject_oid uuid,
    operation text NOT NULL,
    credential_type text,
    previous_status text,
    status text
);
CREATE INDEX IF NOT EXISTS security_audit_subject_time ON security_audit(subject_oid, id);
CREATE INDEX IF NOT EXISTS security_audit_time ON security_audit(occurred_at, id);

CREATE OR REPLACE FUNCTION identity_security_audit() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
DECLARE row_data jsonb; old_data jsonb; subject uuid;
BEGIN
    IF TG_OP = 'DELETE' THEN row_data := to_jsonb(OLD);
    ELSE row_data := to_jsonb(NEW); END IF;
    IF TG_OP = 'UPDATE' THEN
        old_data := to_jsonb(OLD);
        -- Activity touches and JSONB TOTP counter updates are not credential changes.
        IF TG_TABLE_NAME = 'session' AND
            (old_data->'status', old_data->'revoked_at', old_data->'authenticated_at', old_data->'acr') IS NOT DISTINCT FROM
            (row_data->'status', row_data->'revoked_at', row_data->'authenticated_at', row_data->'acr') THEN RETURN NEW;
        ELSIF TG_TABLE_NAME = 'user_credential' AND row_data->>'type' = 'otp' AND
            ((old_data->'data') - 'last_used_counter') IS NOT DISTINCT FROM
            ((row_data->'data') - 'last_used_counter') THEN RETURN NEW;
        ELSIF TG_TABLE_NAME = 'login' AND
            (old_data->'status', old_data->'failed_attempts') IS NOT DISTINCT FROM
            (row_data->'status', row_data->'failed_attempts') THEN RETURN NEW;
        END IF;
    END IF;
    IF TG_TABLE_NAME = 'client_authorization' THEN
        IF row_data->>'type' <> 'device_authorization' THEN
            IF TG_OP <> 'UPDATE' OR old_data->'revoked_at' IS NOT DISTINCT FROM row_data->'revoked_at' THEN
                IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
            END IF;
        END IF;
        subject := NULLIF(row_data->'data'->>'user_oid', '')::uuid;
    ELSIF TG_TABLE_NAME = 'user' THEN subject := (row_data->>'oid')::uuid;
    ELSE SELECT oid INTO subject FROM public."user" WHERE id = (row_data->>'user_id')::bigint;
    END IF;
    INSERT INTO public.security_audit(resource_type, resource_oid, subject_oid, operation, credential_type, previous_status, status)
        VALUES (TG_TABLE_NAME, (row_data->>'oid')::uuid, subject, TG_OP,
            CASE WHEN TG_TABLE_NAME IN ('user_credential', 'client_authorization') THEN row_data->>'type' END,
            old_data->>'status', row_data->>'status');
    IF TG_OP = 'DELETE' THEN RETURN OLD; ELSE RETURN NEW; END IF;
END;
$$;

CREATE OR REPLACE FUNCTION identity_security_audit_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'security_audit is append-only'; END; $$;
DROP TRIGGER IF EXISTS identity_audit_append_only ON security_audit;
CREATE TRIGGER identity_audit_append_only BEFORE UPDATE OR DELETE OR TRUNCATE ON security_audit
FOR EACH STATEMENT EXECUTE FUNCTION identity_security_audit_append_only();

DROP TRIGGER IF EXISTS identity_audit ON "user";
CREATE TRIGGER identity_audit AFTER INSERT OR UPDATE OR DELETE ON "user"
FOR EACH ROW EXECUTE FUNCTION identity_security_audit();
DROP TRIGGER IF EXISTS identity_audit ON user_credential;
CREATE TRIGGER identity_audit AFTER INSERT OR UPDATE OR DELETE ON user_credential
FOR EACH ROW EXECUTE FUNCTION identity_security_audit();
DROP TRIGGER IF EXISTS identity_audit ON session;
CREATE TRIGGER identity_audit AFTER INSERT OR UPDATE OR DELETE ON session
FOR EACH ROW EXECUTE FUNCTION identity_security_audit();
DROP TRIGGER IF EXISTS identity_audit ON login;
CREATE TRIGGER identity_audit AFTER INSERT OR UPDATE OR DELETE ON login
FOR EACH ROW EXECUTE FUNCTION identity_security_audit();
DROP TRIGGER IF EXISTS identity_audit ON client_authorization;
CREATE TRIGGER identity_audit AFTER INSERT OR UPDATE OR DELETE ON client_authorization
FOR EACH ROW EXECUTE FUNCTION identity_security_audit();
