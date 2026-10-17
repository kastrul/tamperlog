-- tamperlog SQLite schema, version 1. Idempotent: safe to run again.
--
-- The application computes every hash; this schema stores links and checks
-- their shape at insert time, and refuses every change after insert. SQLite
-- has no roles: anyone who can open the file for writing can drop a trigger
-- or edit pages directly, so these triggers stop mistakes and careless
-- clients, not the file owner. Seals and anchors detect what the triggers
-- cannot stop. See docs/backends/sqlite.md.
--
-- Timestamps are INTEGER microseconds since the Unix epoch, UTC. Hashes are
-- BLOBs. Attributes are a JSON object in TEXT.

CREATE TABLE IF NOT EXISTS tamperlog_schema (
  version    INTEGER PRIMARY KEY,
  applied_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS tamperlog_event (
  stream       TEXT    NOT NULL
                       CHECK (typeof(stream) = 'text'
                              AND length(CAST(stream AS BLOB)) <= 63
                              AND stream GLOB '[a-z_]*'
                              AND stream NOT GLOB '*[^a-z0-9_.]*'
                              AND stream NOT GLOB '*..*'
                              AND stream NOT GLOB '*.'),
  seq          INTEGER NOT NULL CHECK (typeof(seq) = 'integer' AND seq > 0 AND seq <= 9007199254740991),
  at           INTEGER NOT NULL CHECK (typeof(at) = 'integer'),
  actor        TEXT    NOT NULL DEFAULT '' CHECK (typeof(actor) = 'text' AND length(CAST(actor AS BLOB)) <= 255),
  subject      TEXT    NOT NULL DEFAULT '' CHECK (typeof(subject) = 'text' AND length(CAST(subject AS BLOB)) <= 255),
  action       TEXT    NOT NULL
                       CHECK (typeof(action) = 'text'
                              AND length(CAST(action AS BLOB)) <= 63
                              AND action GLOB '[a-z]*'
                              AND action NOT GLOB '*[^a-z0-9._]*'
                              AND action NOT GLOB '*[._][._]*'
                              AND action NOT GLOB '*[._]'),
  entity       TEXT    NOT NULL
                       CHECK (typeof(entity) = 'text'
                              AND length(CAST(entity AS BLOB)) <= 63
                              AND entity GLOB '[a-z]*'
                              AND entity NOT GLOB '*[^a-z0-9._]*'
                              AND entity NOT GLOB '*[._][._]*'
                              AND entity NOT GLOB '*[._]'),
  entity_id    TEXT    NOT NULL DEFAULT '' CHECK (typeof(entity_id) = 'text' AND length(CAST(entity_id AS BLOB)) <= 255),
  encoder      TEXT    NOT NULL CHECK (typeof(encoder) = 'text' AND length(CAST(encoder AS BLOB)) BETWEEN 1 AND 63),
  hasher       TEXT    NOT NULL CHECK (typeof(hasher) = 'text' AND length(CAST(hasher AS BLOB)) BETWEEN 1 AND 63),
  payload_hash BLOB    CHECK (payload_hash IS NULL OR (typeof(payload_hash) = 'blob' AND length(payload_hash) = length(hash))),
  attributes   TEXT    NOT NULL DEFAULT '{}' CHECK (json_valid(attributes) AND json_type(attributes) = 'object'),
  prev_hash    BLOB    NOT NULL CHECK (typeof(prev_hash) = 'blob' AND length(prev_hash) = length(hash)),
  hash         BLOB    NOT NULL CHECK (typeof(hash) = 'blob' AND length(hash) BETWEEN 32 AND 64),
  PRIMARY KEY (stream, seq)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS tamperlog_event_at ON tamperlog_event (at);

-- One row per stream. The Go store inserts the row (INSERT OR IGNORE) as the
-- first statement of Head: the write takes SQLite's single writer lock for
-- the rest of the transaction, which is how streams are serialised.
CREATE TABLE IF NOT EXISTS tamperlog_stream_head (
  stream TEXT PRIMARY KEY
) WITHOUT ROWID;

CREATE TABLE IF NOT EXISTS tamperlog_seal (
  seq       INTEGER PRIMARY KEY CHECK (typeof(seq) = 'integer' AND seq > 0),
  sealed_at INTEGER NOT NULL CHECK (typeof(sealed_at) = 'integer'),
  hash      BLOB    NOT NULL CHECK (typeof(hash) = 'blob' AND length(hash) = 32),
  body      BLOB    NOT NULL CHECK (typeof(body) = 'blob')
);

CREATE TABLE IF NOT EXISTS tamperlog_proof (
  seal_seq    INTEGER NOT NULL REFERENCES tamperlog_seal (seq),
  provider    TEXT    NOT NULL
                      CHECK (typeof(provider) = 'text'
                             AND length(CAST(provider AS BLOB)) <= 63
                             AND provider GLOB '[a-z0-9]*'
                             AND provider NOT GLOB '*[^a-z0-9._-]*'),
  obtained_at INTEGER NOT NULL CHECK (typeof(obtained_at) = 'integer'),
  body        BLOB    NOT NULL CHECK (typeof(body) = 'blob'),
  PRIMARY KEY (seal_seq, provider)
) WITHOUT ROWID;

-- Append-only: UPDATE and DELETE are refused on every tamperlog table. SQLite
-- has no TRUNCATE; DELETE without WHERE fires these triggers too.
DROP TRIGGER IF EXISTS tamperlog_event_no_update;
CREATE TRIGGER tamperlog_event_no_update BEFORE UPDATE ON tamperlog_event
BEGIN
  SELECT RAISE(ABORT, 'tamperlog: tamperlog_event is append-only, UPDATE refused');
END;

DROP TRIGGER IF EXISTS tamperlog_event_no_delete;
CREATE TRIGGER tamperlog_event_no_delete BEFORE DELETE ON tamperlog_event
BEGIN
  SELECT RAISE(ABORT, 'tamperlog: tamperlog_event is append-only, DELETE refused');
END;

DROP TRIGGER IF EXISTS tamperlog_seal_no_update;
CREATE TRIGGER tamperlog_seal_no_update BEFORE UPDATE ON tamperlog_seal
BEGIN
  SELECT RAISE(ABORT, 'tamperlog: tamperlog_seal is append-only, UPDATE refused');
END;

DROP TRIGGER IF EXISTS tamperlog_seal_no_delete;
CREATE TRIGGER tamperlog_seal_no_delete BEFORE DELETE ON tamperlog_seal
BEGIN
  SELECT RAISE(ABORT, 'tamperlog: tamperlog_seal is append-only, DELETE refused');
END;

DROP TRIGGER IF EXISTS tamperlog_proof_no_update;
CREATE TRIGGER tamperlog_proof_no_update BEFORE UPDATE ON tamperlog_proof
BEGIN
  SELECT RAISE(ABORT, 'tamperlog: tamperlog_proof is append-only, UPDATE refused');
END;

DROP TRIGGER IF EXISTS tamperlog_proof_no_delete;
CREATE TRIGGER tamperlog_proof_no_delete BEFORE DELETE ON tamperlog_proof
BEGIN
  SELECT RAISE(ABORT, 'tamperlog: tamperlog_proof is append-only, DELETE refused');
END;

-- Checks the shape of a new link against the stream head: dense sequence,
-- prev_hash equal to the head's hash (or all zero bytes for seq 1), the same
-- encoder and hasher as the head, at within 5 seconds of the SQLite clock and
-- not more than one second before the head. Go computes the hash; the
-- database checks what Go asserts. The SQLite clock is the process clock, the
-- same clock the Go store stamps with.
DROP TRIGGER IF EXISTS tamperlog_event_check_link;
CREATE TRIGGER tamperlog_event_check_link BEFORE INSERT ON tamperlog_event
BEGIN
  SELECT RAISE(ABORT, 'tamperlog: at is not the database clock')
  WHERE abs(NEW.at - CAST((julianday('now') - 2440587.5) * 86400000000 AS INTEGER)) > 5000000;

  SELECT RAISE(ABORT, 'tamperlog: seq does not follow the stream head')
  WHERE NEW.seq <> coalesce((SELECT max(seq) FROM tamperlog_event WHERE stream = NEW.stream), 0) + 1;

  SELECT RAISE(ABORT, 'tamperlog: prev_hash does not match the stream head')
  WHERE NEW.prev_hash <> coalesce(
    (SELECT hash FROM tamperlog_event WHERE stream = NEW.stream ORDER BY seq DESC LIMIT 1),
    zeroblob(length(NEW.hash)));

  SELECT RAISE(ABORT, 'tamperlog: encoder or hasher differs from the stream head')
  WHERE EXISTS (
    SELECT 1 FROM tamperlog_event WHERE stream = NEW.stream ORDER BY seq DESC LIMIT 1
  ) AND (
    NEW.encoder <> (SELECT encoder FROM tamperlog_event WHERE stream = NEW.stream ORDER BY seq DESC LIMIT 1)
    OR NEW.hasher <> (SELECT hasher FROM tamperlog_event WHERE stream = NEW.stream ORDER BY seq DESC LIMIT 1));

  SELECT RAISE(ABORT, 'tamperlog: at precedes the stream head')
  WHERE NEW.at < (SELECT at FROM tamperlog_event WHERE stream = NEW.stream ORDER BY seq DESC LIMIT 1) - 1000000;
END;

-- Seals form their own chain: dense sequence numbers.
DROP TRIGGER IF EXISTS tamperlog_seal_check;
CREATE TRIGGER tamperlog_seal_check BEFORE INSERT ON tamperlog_seal
BEGIN
  SELECT RAISE(ABORT, 'tamperlog: seal seq does not follow the last seal')
  WHERE NEW.seq <> coalesce((SELECT max(seq) FROM tamperlog_seal), 0) + 1;
END;

-- A proof must point at a stored seal. The foreign key above says the same
-- but is enforced only when the connection has PRAGMA foreign_keys = ON; the
-- trigger holds regardless. The duplicate check refuses INSERT OR REPLACE,
-- which would otherwise delete the old row without firing the DELETE trigger
-- when recursive_triggers is off.
DROP TRIGGER IF EXISTS tamperlog_proof_check;
CREATE TRIGGER tamperlog_proof_check BEFORE INSERT ON tamperlog_proof
BEGIN
  SELECT RAISE(ABORT, 'tamperlog: proof for an unknown seal')
  WHERE NOT EXISTS (SELECT 1 FROM tamperlog_seal WHERE seq = NEW.seal_seq);
  SELECT RAISE(ABORT, 'tamperlog: proof already exists for this seal and provider')
  WHERE EXISTS (SELECT 1 FROM tamperlog_proof WHERE seal_seq = NEW.seal_seq AND provider = NEW.provider);
END;

INSERT OR IGNORE INTO tamperlog_schema (version, applied_at)
VALUES (1, CAST((julianday('now') - 2440587.5) * 86400000000 AS INTEGER));
