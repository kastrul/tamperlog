// Package tamperlog implements tamper-evident audit trails: per-stream hash
// chains computed in the application, written in the caller's database
// transaction, sealed periodically to write-once storage and anchored with
// external timestamps, with a verifier that starts from the outermost layer.
//
// # Model
//
// An [Event] is what a handler records: which actor did which action on which
// entity, optionally about which subject, with a commitment to a payload kept
// elsewhere. [Appender.Append] links the event into its stream as a [Record]
// carrying the next sequence number, the store's clock, the previous record's
// hash and its own hash:
//
//	hash = H( "tamperlog/v1" ‖ len(encoderID) ‖ encoderID ‖ len(hasherID) ‖ hasherID
//	          ‖ prev_hash ‖ canonical(record) )
//
// Lengths are 4-byte big-endian. The canonical form is produced by an
// [Encoder] (default [BinaryV1]) and H by a [Hasher] (default [SHA256]); every
// record names the pair it was linked with, and a stream keeps one pair for
// its lifetime. The first record of a stream links to a genesis value of
// H.Size() zero bytes. [Chain.Walk] verifies a range of records.
//
// # Storage
//
// A [Store] is bound to one open database transaction: Head locks the stream
// until the transaction ends and returns the last link and the store clock,
// Insert writes a record, Range reads records back. Backends live in
// store/memory, store/pgx, store/pgsql and store/sqlite. Callers that record an
// event with a business change use [Appender.Append] with a Store bound to
// their own transaction and call it last, since the stream lock is held until
// commit. Callers without a transaction use [Log.Append], which opens one.
//
// # Layers above the chain
//
// Package seal writes chained seals of every stream head to write-once sinks,
// package anchor obtains RFC 3161 timestamps on seals, and package verify
// compares anchors, seals and chain. See THREAT_MODEL.md for what each layer
// defends against and SPEC.md for the byte-exact formats.
//
// # What the chain alone cannot do
//
// An unkeyed chain whose head lives only in the database is a consistency
// check: anyone who can rewrite rows can recompute the chain. Tamper evidence
// against privileged users comes from seals stored where they cannot write and
// from anchors they cannot forge. The chain also cannot detect events that
// were never written; callers must fail the business operation when Append
// fails.
package tamperlog
