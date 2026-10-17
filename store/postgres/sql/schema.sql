-- tamperlog PostgreSQL schema, version 1. Idempotent: safe to run again.
-- __SCHEMA__ is replaced by the configured schema name (default "public").
--
-- The application computes every hash; this schema stores links and checks
-- their shape at insert time, and refuses every change after insert. What it
-- cannot stop (the table owner, a superuser, anyone who can disable a
-- trigger) is detected by seals and anchors, not here. See
-- docs/backends/postgres.md.

CREATE SCHEMA IF NOT EXISTS __SCHEMA__;

CREATE TABLE IF NOT EXISTS __SCHEMA__.tamperlog_schema (
  version    integer     PRIMARY KEY,
  applied_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS __SCHEMA__.tamperlog_event (
  stream       text        NOT NULL CHECK (stream ~ '^[a-z_][a-z0-9_]*(\.[a-z0-9_]+)*$' AND octet_length(stream) <= 63),
  seq          bigint      NOT NULL CHECK (seq > 0 AND seq <= 9007199254740991),
  at           timestamptz NOT NULL,
  encoder      text        NOT NULL CHECK (encoder ~ '^[a-z0-9][a-z0-9._/-]*$' AND octet_length(encoder) <= 63),
  hasher       text        NOT NULL CHECK (hasher ~ '^[a-z0-9][a-z0-9._-]*$' AND octet_length(hasher) <= 63),
  actor        text        NOT NULL DEFAULT '' CHECK (octet_length(actor) <= 255),
  subject      text        NOT NULL DEFAULT '' CHECK (octet_length(subject) <= 255),
  action       text        NOT NULL CHECK (action ~ '^[a-z][a-z0-9]*([._][a-z0-9]+)*$' AND octet_length(action) <= 63),
  entity       text        NOT NULL CHECK (entity ~ '^[a-z][a-z0-9]*([._][a-z0-9]+)*$' AND octet_length(entity) <= 63),
  entity_id    text        NOT NULL DEFAULT '' CHECK (octet_length(entity_id) <= 255),
  payload_hash bytea       CHECK (payload_hash IS NULL OR octet_length(payload_hash) = octet_length(hash)),
  attributes   jsonb       NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(attributes) = 'object'),
  prev_hash    bytea       NOT NULL CHECK (octet_length(prev_hash) = octet_length(hash)),
  hash         bytea       NOT NULL CHECK (octet_length(hash) BETWEEN 32 AND 64),
  PRIMARY KEY (stream, seq)
);

CREATE INDEX IF NOT EXISTS tamperlog_event_at ON __SCHEMA__.tamperlog_event (at);

-- One row per stream, used only as a lock target by the head-row lock mode.
CREATE TABLE IF NOT EXISTS __SCHEMA__.tamperlog_stream_head (
  stream text PRIMARY KEY
);

CREATE TABLE IF NOT EXISTS __SCHEMA__.tamperlog_seal (
  seq       bigint      PRIMARY KEY CHECK (seq > 0),
  sealed_at timestamptz NOT NULL,
  hash      bytea       NOT NULL CHECK (octet_length(hash) = 32),
  body      bytea       NOT NULL
);

CREATE TABLE IF NOT EXISTS __SCHEMA__.tamperlog_proof (
  seal_seq    bigint      NOT NULL REFERENCES __SCHEMA__.tamperlog_seal (seq),
  provider    text        NOT NULL CHECK (provider ~ '^[a-z0-9][a-z0-9._-]*$' AND octet_length(provider) <= 63),
  obtained_at timestamptz NOT NULL,
  body        bytea       NOT NULL,
  PRIMARY KEY (seal_seq, provider, obtained_at)
);

-- Refuses UPDATE, DELETE and TRUNCATE on every tamperlog table, for every
-- role including the owner. ENABLE ALWAYS makes it fire even under
-- session_replication_role = replica.
CREATE OR REPLACE FUNCTION __SCHEMA__.tamperlog_refuse_change() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  RAISE EXCEPTION 'tamperlog: % is append-only, % refused', TG_TABLE_NAME, TG_OP
    USING ERRCODE = 'insufficient_privilege';
END
$$;

-- Checks the shape of a new link against the stream head under the same
-- advisory lock the Go appender takes (re-entrant within a transaction):
-- dense sequence, prev_hash equals the head's hash (or all zero bytes for
-- seq 1), at within 5 seconds of the database clock and not more than one
-- second before the head, and the same encoder and hasher as the head. Go computes the hash; the database checks what Go
-- asserts, so a client holding only INSERT cannot backdate or poison a stream.
CREATE OR REPLACE FUNCTION __SCHEMA__.tamperlog_check_link() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  head   record;
  now_ts timestamptz := clock_timestamp();
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('tamperlog:' || NEW.stream, 0));

  SELECT e.seq, e.hash, e.at, e.encoder, e.hasher INTO head
  FROM __SCHEMA__.tamperlog_event AS e
  WHERE e.stream = NEW.stream
  ORDER BY e.seq DESC
  LIMIT 1;

  IF head.seq IS NULL THEN
    IF NEW.seq <> 1 THEN
      RAISE EXCEPTION 'tamperlog: %/%: first record must have seq 1', NEW.stream, NEW.seq
        USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.prev_hash <> decode(repeat('00', octet_length(NEW.hash)), 'hex') THEN
      RAISE EXCEPTION 'tamperlog: %/%: first record must link to genesis', NEW.stream, NEW.seq
        USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  ELSE
    IF NEW.seq <> head.seq + 1 THEN
      RAISE EXCEPTION 'tamperlog: %/%: head is %', NEW.stream, NEW.seq, head.seq
        USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.prev_hash <> head.hash THEN
      RAISE EXCEPTION 'tamperlog: %/%: prev_hash does not match head', NEW.stream, NEW.seq
        USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.at < head.at - interval '1 second' THEN
      RAISE EXCEPTION 'tamperlog: %/%: at precedes head', NEW.stream, NEW.seq
        USING ERRCODE = 'integrity_constraint_violation';
    END IF;
    IF NEW.encoder <> head.encoder OR NEW.hasher <> head.hasher THEN
      RAISE EXCEPTION 'tamperlog: %/%: stream uses %/%', NEW.stream, NEW.seq, head.encoder, head.hasher
        USING ERRCODE = 'integrity_constraint_violation';
    END IF;
  END IF;

  IF NEW.at < now_ts - interval '5 seconds' OR NEW.at > now_ts + interval '5 seconds' THEN
    RAISE EXCEPTION 'tamperlog: %/%: at is not the database clock', NEW.stream, NEW.seq
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;

  RETURN NEW;
END
$$;

-- Seals form their own chain: dense sequence numbers.
CREATE OR REPLACE FUNCTION __SCHEMA__.tamperlog_check_seal() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  last_seq bigint;
BEGIN
  PERFORM pg_advisory_xact_lock(hashtextextended('tamperlog:seal', 0));
  SELECT max(seq) INTO last_seq FROM __SCHEMA__.tamperlog_seal;
  IF NEW.seq <> coalesce(last_seq, 0) + 1 THEN
    RAISE EXCEPTION 'tamperlog: seal seq % does not follow %', NEW.seq, coalesce(last_seq, 0)
      USING ERRCODE = 'integrity_constraint_violation';
  END IF;
  RETURN NEW;
END
$$;

DROP TRIGGER IF EXISTS tamperlog_event_append_only ON __SCHEMA__.tamperlog_event;
CREATE TRIGGER tamperlog_event_append_only
  BEFORE UPDATE OR DELETE ON __SCHEMA__.tamperlog_event
  FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.tamperlog_refuse_change();
ALTER TABLE __SCHEMA__.tamperlog_event ENABLE ALWAYS TRIGGER tamperlog_event_append_only;

DROP TRIGGER IF EXISTS tamperlog_event_no_truncate ON __SCHEMA__.tamperlog_event;
CREATE TRIGGER tamperlog_event_no_truncate
  BEFORE TRUNCATE ON __SCHEMA__.tamperlog_event
  FOR EACH STATEMENT EXECUTE FUNCTION __SCHEMA__.tamperlog_refuse_change();
ALTER TABLE __SCHEMA__.tamperlog_event ENABLE ALWAYS TRIGGER tamperlog_event_no_truncate;

DROP TRIGGER IF EXISTS tamperlog_event_check_link ON __SCHEMA__.tamperlog_event;
CREATE TRIGGER tamperlog_event_check_link
  BEFORE INSERT ON __SCHEMA__.tamperlog_event
  FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.tamperlog_check_link();
ALTER TABLE __SCHEMA__.tamperlog_event ENABLE ALWAYS TRIGGER tamperlog_event_check_link;

DROP TRIGGER IF EXISTS tamperlog_seal_append_only ON __SCHEMA__.tamperlog_seal;
CREATE TRIGGER tamperlog_seal_append_only
  BEFORE UPDATE OR DELETE ON __SCHEMA__.tamperlog_seal
  FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.tamperlog_refuse_change();
ALTER TABLE __SCHEMA__.tamperlog_seal ENABLE ALWAYS TRIGGER tamperlog_seal_append_only;

DROP TRIGGER IF EXISTS tamperlog_seal_no_truncate ON __SCHEMA__.tamperlog_seal;
CREATE TRIGGER tamperlog_seal_no_truncate
  BEFORE TRUNCATE ON __SCHEMA__.tamperlog_seal
  FOR EACH STATEMENT EXECUTE FUNCTION __SCHEMA__.tamperlog_refuse_change();
ALTER TABLE __SCHEMA__.tamperlog_seal ENABLE ALWAYS TRIGGER tamperlog_seal_no_truncate;

DROP TRIGGER IF EXISTS tamperlog_seal_check ON __SCHEMA__.tamperlog_seal;
CREATE TRIGGER tamperlog_seal_check
  BEFORE INSERT ON __SCHEMA__.tamperlog_seal
  FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.tamperlog_check_seal();
ALTER TABLE __SCHEMA__.tamperlog_seal ENABLE ALWAYS TRIGGER tamperlog_seal_check;

DROP TRIGGER IF EXISTS tamperlog_proof_append_only ON __SCHEMA__.tamperlog_proof;
CREATE TRIGGER tamperlog_proof_append_only
  BEFORE UPDATE OR DELETE ON __SCHEMA__.tamperlog_proof
  FOR EACH ROW EXECUTE FUNCTION __SCHEMA__.tamperlog_refuse_change();
ALTER TABLE __SCHEMA__.tamperlog_proof ENABLE ALWAYS TRIGGER tamperlog_proof_append_only;

DROP TRIGGER IF EXISTS tamperlog_proof_no_truncate ON __SCHEMA__.tamperlog_proof;
CREATE TRIGGER tamperlog_proof_no_truncate
  BEFORE TRUNCATE ON __SCHEMA__.tamperlog_proof
  FOR EACH STATEMENT EXECUTE FUNCTION __SCHEMA__.tamperlog_refuse_change();
ALTER TABLE __SCHEMA__.tamperlog_proof ENABLE ALWAYS TRIGGER tamperlog_proof_no_truncate;

INSERT INTO __SCHEMA__.tamperlog_schema (version) VALUES (1) ON CONFLICT DO NOTHING;
