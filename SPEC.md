# tamperlog wire formats

This document is normative. A verifier written in any language that follows
it reproduces every hash the library produces. Every format carries an
identifier; once an identifier ships in a tagged release its bytes never change
(ADR 0013). A change is a new identifier, and old identifiers stay verifiable.

Notation: `‖` is byte concatenation, `u32(n)` and `u64(n)` are unsigned
big-endian integers of 4 and 8 bytes, `lp(b)` is `u32(len(b)) ‖ b` (a
length-prefixed field), hex is lowercase.

## 1. Records

A record has these hashed fields:

| Field | Type | Rules |
|---|---|---|
| `stream` | string | `^[a-z_][a-z0-9_]*(\.[a-z0-9_]+)*$`, 1..63 bytes |
| `seq` | integer | 1..2^53-1, dense per stream, starting at 1 |
| `at` | time | Unix microseconds, 0..2^53-1, UTC, whole microseconds |
| `actor`, `subject`, `entity_id` | string | UTF-8, no control characters, 0..255 bytes; empty means absent |
| `action`, `entity` | string | `^[a-z][a-z0-9]*([._][a-z0-9]+)*$`, 1..63 bytes |
| `payload_hash` | bytes | absent, or exactly the hasher's output size |
| `attributes` | map string→string | at most 32 entries; keys `^[a-z][a-z0-9_]*(\.[a-z0-9_]+)*$` ≤ 63 bytes; values UTF-8 without control characters ≤ 1024 bytes |

and these linking fields, which are stored but not part of the canonical
form: `encoder` (identifier), `hasher` (identifier), `prev_hash`, `hash`.

### 1.1 Hashers

| Identifier | Function | Output |
|---|---|---|
| `sha256` | SHA-256 (FIPS 180-4) | 32 bytes |
| `sha3-256` | SHA3-256 (FIPS 202) | 32 bytes |
| `sha512-256` | SHA-512/256 (FIPS 180-4) | 32 bytes |

### 1.2 Encoder `binary/v1`

```
lp(stream) ‖ u64(seq) ‖ u64(at) ‖ lp(actor) ‖ lp(subject) ‖ lp(action)
‖ lp(entity) ‖ lp(entity_id) ‖ lp(payload_hash) ‖ u64(count)
‖ ( lp(key) ‖ lp(value) )*
```

`count` is the number of attributes; pairs follow in byte-wise ascending key
order. An absent identifier or payload hash is `lp("")` = `00000000`. The
encoding is injective: every variable-length field is length-prefixed and
every fixed-width field has a fixed position.

### 1.3 Encoder `jcs/v1`

The record as a JSON object serialised per RFC 8785 (JSON Canonicalization
Scheme): members sorted by UTF-16 code units, no whitespace, minimal string
escaping, integers as plain digits.

```
{"action":…,"actor":…,"at":<at as integer>,"attributes":{…},"entity":…,
 "entity_id":…,"payload_hash":"<hex or empty>","seq":<integer>,"stream":…,
 "subject":…}
```

All ten members are always present; absent identifiers are `""`, an absent
payload hash is `""`, no attributes is `{}`.

### 1.4 Link hash

```
hash = H( "tamperlog/v1" ‖ lp(encoder_id) ‖ lp(hasher_id) ‖ prev_hash ‖ canonical(record) )
```

`prev_hash` of the first record (`seq` 1) is `H.Size()` zero bytes (the
genesis value). Every record of a stream carries the same `encoder_id` and
`hasher_id`; an appender refuses to extend a stream with another pair.

### 1.5 Test vectors

Record: stream `chat`, seq 1, at `2026-10-13T12:00:00.123456Z`
(1791892800123456 µs), actor `0199f5a0-0000-7000-8000-000000000001`, subject
absent, action `message.read`, entity `chat_message`, entity_id
`0199f5a0-0000-7000-8000-000000000002`, payload_hash 32 bytes of `0xaa`,
attributes `channel=web`, `purpose=treatment`, prev_hash genesis.

`binary/v1` canonical bytes (hex):

```
0000000463686174 0000000000000001 00065db78dd3b240
0000002430313939663561302d303030302d373030302d383030302d303030303030303030303031
00000000
0000000c6d6573736167652e72656164
0000000c636861745f6d657373616765
0000002430313939663561302d303030302d373030302d383030302d303030303030303030303032
00000020aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
0000000000000002
000000076368616e6e656c 00000003776562
00000007707572706f7365 0000000974726561746d656e74
```

`jcs/v1` canonical bytes:

```
{"action":"message.read","actor":"0199f5a0-0000-7000-8000-000000000001","at":1791892800123456,"attributes":{"channel":"web","purpose":"treatment"},"entity":"chat_message","entity_id":"0199f5a0-0000-7000-8000-000000000002","payload_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","seq":1,"stream":"chat","subject":""}
```

Link hashes:

| Encoder | Hasher | hash |
|---|---|---|
| binary/v1 | sha256 | `05442837467699a6f80ddecbe2411c1229d57eeeabdc31f14f4cab453df790a8` |
| binary/v1 | sha3-256 | `1a5631c53e73c04f3e1b6ebcaabf95ae78d1f2f2d14c2c7763cb692fcee8f177` |
| binary/v1 | sha512-256 | `1d878357873dcf8f42aa467dbf49f43fc62fd0d86c299783075adedc4219457d` |
| jcs/v1 | sha256 | `b64ded7ed62482209e126edabf485588d40175ca0825e4a8fb1691284a593bea` |
| jcs/v1 | sha3-256 | `15b2c7818c12ce5b38b1594899354f925bfcead9fd254bb1eea6f53716448c12` |
| jcs/v1 | sha512-256 | `951c040b8002b26f3f20eb8c1be28c19db2a5e1cef72471996151cafb74f0e33` |

These vectors are asserted by `golden_test.go`.

## 2. Payload commitments

`Commit(h, salt, payload) = HMAC_h(salt, payload)`. Vector with `sha256`,
salt `salt`, payload `payload`:
`a210c5e361d74c746baa8733b32260efa121a1c579a7361acbc08dd229daeea1`.

## 3. Retention drops

A drop of records `first_seq..last_seq` of `stream` is committed to by

```
digest = H( "tamperlog.drop/v1" ‖ lp(stream) ‖ u64(first_seq) ‖ lp(first_prev_hash)
            ‖ u64(last_seq) ‖ lp(last_hash) )
```

where `first_prev_hash` is the `prev_hash` of the first dropped record and
`last_hash` the `hash` of the last. The digest is the `payload_hash` of a
record in the system stream (default `_tamperlog`) with action
`retention.drop`, entity `stream`, entity_id `stream`, and attributes
`first_seq`, `first_prev_hash` (hex), `last_seq`, `last_hash` (hex). Vector
with `sha256`, stream `s`, 1..10, `first_prev_hash` 32 zero bytes,
`last_hash` 32 bytes of `0x01`:
`58d29f1d2731ffcac13c51658d408ba042f00a26d67adc516616c1dc52855cb2`.

A verifier accepts a gap only when drop events chain across it: the first
drop's `first_prev_hash` equals the hash of the record before the gap (or
genesis), each next drop's `first_prev_hash` equals the previous drop's
`last_hash`, and the record after the gap has `prev_hash` equal to the last
drop's `last_hash`. A stream's newest record is never dropped.

## 4. Seals: `tamperlog.seal/1`

A seal is a JSON object serialised per RFC 8785:

```
{"drops":[<hex>…],"key_id":<string, optional>,"prev_seal_hash":<hex>,
 "schema":"tamperlog.seal/1","sealed_at":<RFC 3339, UTC, "Z", nanoseconds trimmed>,
 "seq":<integer>,"signature":<hex, optional>,
 "streams":[{"encoder":…,"first_kept_seq":n,"hasher":…,"head_hash":<hex>,
             "head_seq":n,"stream":…}…],"writer":<string>}
```

Rules: `seq` starts at 1 and is dense; `prev_seal_hash` is SHA-256 of the
previous seal's canonical bytes, 32 zero bytes for `seq` 1; `sealed_at`
strictly increases; `streams` is sorted by `stream` with no duplicates and
lists every non-empty stream; `first_kept_seq ≥ 1`, `head_seq ≥
first_kept_seq`; `drops` lists the digests of drop events appended to the
system stream since the previous seal, in sequence order; `writer` is
non-empty. `key_id` and `signature` appear together: the signature covers
the canonical serialisation of the object **without** the `signature` member.
`sealed_at` is written with Go's RFC 3339 nanosecond format at microsecond
precision, so trailing zeros are trimmed (`14:00:00Z`, `14:00:00.5Z`,
`14:00:00.123456Z`).

The seal hash is `SHA-256(canonical bytes)` regardless of the streams'
hashers. Anchors bind to this value.

Signers: `ed25519` signatures are 64 bytes over the signing bytes;
`hmac-sha256` tags are 32 bytes. The scheme is implied by the key the
verifier holds under `key_id`.

Vector (unsigned):

```
{"drops":["0303030303030303030303030303030303030303030303030303030303030303"],"prev_seal_hash":"0000000000000000000000000000000000000000000000000000000000000000","schema":"tamperlog.seal/1","sealed_at":"2026-10-17T14:00:00Z","seq":1,"streams":[{"encoder":"binary/v1","first_kept_seq":1,"hasher":"sha256","head_hash":"0101010101010101010101010101010101010101010101010101010101010101","head_seq":10,"stream":"audit"},{"encoder":"binary/v1","first_kept_seq":3,"hasher":"sha256","head_hash":"0202020202020202020202020202020202020202020202020202020202020202","head_seq":3,"stream":"auth"}],"writer":"tamperlog-test"}
```

## 5. Sink keys

| Object | Key |
|---|---|
| seal `n` | `seals/<n as 12 decimal digits, zero padded>.json` |
| proof from provider `p` for seal `n` | `seals/<n>.<p>.proof` |

Fixed-width digits keep lexical order equal to numeric order. A sink is
write-once: a second object under a seal key is evidence of tampering.

## 6. Anchors

Provider `rfc3161`: the proof is the DER `TimeStampToken` (CMS
`ContentInfo`) of an RFC 3161 response for a `TimeStampReq` with
`messageImprint` = SHA-256 of the seal's canonical bytes, `certReq` true and
a random nonce. Verification requirements are listed in
`docs/anchors/rfc3161.md`.

## 7. Bundles: `tamperlog.bundle/1`

A directory holding `manifest.json`, `streams/<stream>.jsonl` and the sink
keys of section 5. Each line of a stream file is one record as JSON:

```
{"stream":…,"seq":n,"at":<RFC 3339 UTC>,"encoder":…,"hasher":…,"actor":…,
 "subject":…,"action":…,"entity":…,"entity_id":…,"payload_hash":<hex, omitted when absent>,
 "attributes":{…} (omitted when empty),"prev_hash":<hex>,"hash":<hex>}
```

The manifest lists, per stream, the file, first and last sequence, record
count and the SHA-256 of the file bytes; these digests protect transport, the
chain itself is re-verified from the records.

## 8. System stream events

| Action | Written by | Entity / entity_id | payload_hash | Attributes |
|---|---|---|---|---|
| `retention.drop` | application | `stream` / stream name | drop digest | `first_seq`, `first_prev_hash`, `last_seq`, `last_hash` |
| `anchor.failed` | anchor runner | `seal` / seal seq | seal hash (when sizes match) | `provider`, `grace` |
| `chain.verified` | verifier runner | `chain` / empty | heads digest | `streams`, `seals` |
| `chain.broken` | verifier runner | `chain` / empty | heads digest | `streams`, `seals`, `errors`, `first_code`, `first_stream`, `first_seq` |

The heads digest is `SHA-256(JCS({stream: {"head_hash": hex, "head_seq": n}, …}))`.
