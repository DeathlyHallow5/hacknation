-- Rotation of the encryption-at-rest key with keys from the environment (core/src/keyring.rs).
-- The operator sets the new key as ASI_DATA_KEY and the old one as ASI_DATA_KEY_PREVIOUS; the core
-- puts the previous key into each of its connections (asi.data_key_previous) and reads go through
-- asi_decrypt, which falls back to it, until POST /api/v1/security/encryption/rotate has
-- re-encrypted every row. Keys are only ever bound parameters or session settings, never stored.

-- pgp_sym_decrypt with the given key; if that fails ("Wrong key or corrupt data", SQLSTATE 39000)
-- and this session has a previous key, with that one. Without a previous key no exception block
-- (no subtransaction per row) is entered.
CREATE OR REPLACE FUNCTION asi_decrypt(data bytea, key text) RETURNS text
LANGUAGE plpgsql STABLE STRICT AS $$
DECLARE
    previous text := current_setting('asi.data_key_previous', true);
BEGIN
    IF previous IS NULL OR previous = '' THEN
        RETURN pgp_sym_decrypt(data, key);
    END IF;
    BEGIN
        RETURN pgp_sym_decrypt(data, key);
    EXCEPTION WHEN external_routine_invocation_exception THEN
        RETURN pgp_sym_decrypt(data, previous);
    END;
END
$$;

-- 1-based position of the first key in `keys` that decrypts `data`; 0 when none does.
-- (pgp_sym_decrypt_bytea also accepts data encrypted as text, and skips the encoding check.)
CREATE OR REPLACE FUNCTION asi_key_index(data bytea, keys text[]) RETURNS integer
LANGUAGE plpgsql STABLE STRICT AS $$
BEGIN
    FOR i IN 1 .. coalesce(array_length(keys, 1), 0) LOOP
        BEGIN
            PERFORM pgp_sym_decrypt_bytea(data, keys[i]);
            RETURN i;
        EXCEPTION WHEN external_routine_invocation_exception THEN
            NULL;
        END;
    END LOOP;
    RETURN 0;
END
$$;

-- annotation_history stays append-only, except for one change: the key rotation (which sets
-- asi.key_rotation for its own transaction) may replace notes_enc and nothing else.
CREATE OR REPLACE FUNCTION annotation_history_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP = 'DELETE' AND pg_trigger_depth() > 1 THEN
        RETURN OLD;
    END IF;
    IF TG_OP = 'UPDATE' AND current_setting('asi.key_rotation', true) = 'on'
       AND to_jsonb(NEW) - 'notes_enc' = to_jsonb(OLD) - 'notes_enc' THEN
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'annotation_history is append-only: % is not allowed', TG_OP;
END
$$;
