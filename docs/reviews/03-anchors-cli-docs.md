# Codex review 3: RFC 3161, EU Trusted List, S3 sink, CLI, documentation

Date: 2026-10-17. Reviewer: Codex CLI (`codex exec --sandbox read-only`).
Scope: `anchor/rfc3161`, `anchor/rfc3161/eutl`, `seal/sinks/s3lock`,
`cmd/tamperlog`, and README.md, SPEC.md, THREAT_MODEL.md checked against the
code. The reviewer ran the targeted test suites and reproduced the accuracy
overflow arithmetically.

| # | Severity | Finding | Action |
|---|---|---|---|
| 1 | High | S3 `List` used ListObjectsV2, which omits keys behind delete markers, so later locked seals could be hidden from the verifier's sink inventory | `List` inventories with ListObjectVersions including delete markers; `Get` on a key hidden by a marker returns `ErrHidden` rather than not-found |
| 2 | High | EU Trusted List: identities from history periods were merged service-wide, so a retired key matched during a later qualified period | Identities are kept per status period and `QualifiedAt` requires an identity listed in the period that contains `genTime` |
| 3 | High | Weak identity matches (asserted SKI, subject name) could make `Qualified` true | Only an exact certificate or public-key match qualifies; SKI is recomputed from the public key, never read from the candidate; subject matches are informational |
| 4 | High | CLI `verify` could exit 0 with anchors, sinks or freshness silently unconfigured; `--tsa-policy`/`--eutl-cache` without roots were ignored | `verify` refuses to run unless each external layer is configured or explicitly skipped (`--no-anchors`, `--no-sinks`, `--no-freshness`), rejects orphan flags, and every report carries a `Scope` printed in text and JSON |
| 5 | Medium | EU Trusted List HTTPS requirement bypassable through redirects | Every redirect hop must be https; at most 5 hops |
| 6 | Medium | Qualification checks trusted expired or partially loaded lists indefinitely | `eutl.Policy` (require fresh lists by NextUpdate, require territories, historical identities opt-in) enforced by `Checker`; `LoadWithRefresh` reloads for long-running processes; the CLI requires fresh lists and every requested territory unless `--eutl-offline` |
| 7 | Medium | TSTInfo accuracy could overflow `time.Duration` and bypass `WithMaxAccuracy` | Bounded seconds, millis and micros in 1..999, overflow-checked conversion |
| 8 | Medium | RSA-PSS `saltLength` 0 mapped to Go's auto-detect sentinel | Zero salt rejected; declared length enforced exactly |
| 9 | Medium | Quadratic duplicate-attribute check and no size limits on `ParseToken`/`Verify` | OID set for duplicates; `MaxTokenSize`, attribute and certificate count limits; cancellation checked between phases |
| 10 | Medium | S3 preflight read any AccessDenied as retention protection; GOVERNANCE accepted | Probe conclusive only with a version id, lock metadata in the future and a denied versioned delete; `WithRequireCompliance`; `Info.String()`, `Adequate()` and `Problems`; the CLI runs the preflight at startup of `seal`, `anchor`, `verify` and `resync` and requires COMPLIANCE unless `--s3-allow-governance` |
| 11 | Medium | Client did not check the returned policy against the requested one | Mismatch rejected (RFC 3161 section 2.4.2) |
| 12 | Medium | Comment claimed per-object retention cannot shorten the bucket default; on AWS it overrides it | Comment corrected; `Check` fails when the configured retention is shorter or weaker than the bucket default |
| 13 | Low | CMS version, DER SET ordering, GeneralizedTime trailing zeros, SigningCertificate issuerSerial handling | SignedData version 3 required for this content type; sorted signed attributes enforced; trailing zeros rejected; issuerSerial must carry a matching directoryName |
| 14 | Low | Exit codes: operational failures reported as integrity failures; continuous mode exit status undefined; JSON encoding errors dropped | `Report.Operational()`; exit 2 for source and sink read errors and for rejected configuration, 1 for integrity findings; continuous mode exits with the status of the last report; encoding errors propagated |

Documentation corrections made: README no longer says timestamps are
qualified by default, states the scope requirement and the exit-code
contract, and qualifies "visible at the next verification"; SPEC.md section 3
now describes sealed-only, prefix-only gap bridging; THREAT_MODEL.md states
that anchors alone do not detect replacement of all history and evidence
with an older authentic state (freshness policy and external copies do), and
describes the delete-marker-aware sink inventory; docs/anchors/rfc3161.md no
longer implies that consecutive timestamps prove when an event happened;
docs/anchors/eutl.md explains why a subject match is not authentication and
what the cache trusts; the `WithCertReq` comment matches the verifier.

Confirmed sound by the reviewer: signature verification over the original
signed-attribute bytes with the SET tag; separate binding of imprint, content
digest, signer identity and ESS certificate hash; SHA-1 excluded from CMS
digests; RSA minimum size and PSS parameter agreement; explicit roots with no
system fallback and chain validation at `genTime`; nonce matching, deadlines
and bounded bodies on HTTP; S3 conditional creation and checksums; disclosed
limitations (unsigned trusted lists, no revocation checking).
