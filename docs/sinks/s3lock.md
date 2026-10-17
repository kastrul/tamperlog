# S3 Object Lock sink (`seal/sinks/s3lock`)

The `s3lock` sink pushes every seal and proof to an S3 bucket whose versions
are protected by Object Lock. It is the one place in the tamperlog design
where the database administrator, the host root and the cloud account owner
all lose the ability to rewrite history: a version written under COMPLIANCE
retention cannot be deleted or shortened by anyone, including the AWS root
user, until the retention date passes. Everything below is about making that
sentence true for your bucket and keeping it true.

Package: `github.com/kastrul/tamperlog/seal/sinks/s3lock`. Depends on
`github.com/aws/aws-sdk-go-v2` (`aws`, `config`, `credentials`,
`service/s3`); the core module does not import it (ADR 0012).

```go
cfg, _ := config.LoadDefaultConfig(ctx)
client := s3.NewFromConfig(cfg, func(o *s3.Options) {
    o.BaseEndpoint = aws.String("https://fsn1.your-objectstorage.com") // Hetzner; omit on AWS
    o.UsePathStyle = true
})
sink := s3lock.New(client, "acme-audit-seals",
    s3lock.WithPrefix("prod"),
    s3lock.WithRequireLockedBucket(true),
    s3lock.WithProbeKey("probe/check"), // only for the operator CLI, not the writer
)
if err := sink.Check(ctx); err != nil { ... }
```

## Bucket requirements

1. **Object Lock enabled at creation.** Neither AWS nor Hetzner can turn it
   on for an existing bucket (AWS: only via support for old buckets; Hetzner:
   not at all). Create a new, dedicated bucket. Do not share it with
   backups or application data: their lifecycle and access rules differ.
2. **Versioning Enabled.** Object Lock forces it on and it cannot be
   suspended afterwards. `Check` fails with `ErrNotVersioned` otherwise,
   because the sink's duplicate-key detection (below) needs versions.
3. **Default retention in COMPLIANCE mode** for the full statutory period.
   With a bucket default the writer credential needs no retention
   permissions at all and cannot shorten anything. Per-object retention
   (`WithRetention`) can only lengthen the default.
4. **Lifecycle rules do not remove locked versions.** An expiration rule on
   a locked bucket adds delete markers and removes versions only after their
   retain-until date; both AWS and Hetzner document this. A delete marker
   still hides the key from `GetObject`, which the sink reports as
   `ErrNotFound` and the verifier as a missing seal, so do not attach
   expiration rules to the seal prefix at all. If you need to reclaim space
   after retention, use a `NoncurrentVersionExpiration` rule that only
   touches noncurrent versions and understand that a legitimate seal key
   never has a noncurrent version.

Create the bucket (AWS CLI works against Hetzner with `--endpoint-url`):

```sh
EP=https://fsn1.your-objectstorage.com        # omit --endpoint-url on AWS
aws --endpoint-url $EP s3api create-bucket --bucket acme-audit-seals \
    --object-lock-enabled-for-bucket \
    --create-bucket-configuration LocationConstraint=fsn1
aws --endpoint-url $EP s3api put-object-lock-configuration --bucket acme-audit-seals \
    --object-lock-configuration '{"ObjectLockEnabled":"Enabled",
      "Rule":{"DefaultRetention":{"Mode":"COMPLIANCE","Years":10}}}'
aws --endpoint-url $EP s3api get-bucket-versioning --bucket acme-audit-seals   # Status: Enabled
```

Then run `Check` with a probe key (see "Preflight") before the first seal.

## What the sink does on each call

- **Put** sends `PutObject` with `If-None-Match: *`, the SHA-256 of the data
  in `x-amz-checksum-sha256`, `Content-Type` (`application/json` for `.json`
  keys, `application/octet-stream` otherwise, or `WithContentType`), and,
  only with `WithRetention`, `x-amz-object-lock-mode` and
  `x-amz-object-lock-retain-until-date = now + duration`. A 412
  `PreconditionFailed` or 409 `ConditionalRequestConflict` becomes
  `seal.ErrExists`. After a successful write the sink lists the key's
  versions and fails with `ErrMultipleVersions` if there is more than one.
- **Get** downloads the key, maps `NoSuchKey` to `seal.ErrNotFound`, and
  (by default) lists versions and fails with `ErrMultipleVersions` rather
  than returning any copy when two exist.
- **List** pages through `ListObjectsV2` under the prefix and returns keys
  relative to the prefix in lexical order; `seal.Key` uses fixed-width
  sequence numbers so lexical and numeric order agree.
- **Versions** returns every version and delete marker under a key (version
  id, time, size, ETag) for the verifier and the CLI.

## The "second version is a failure" rule

Object Lock protects *versions*, not *keys*. Retention "doesn't prevent new
versions of the object from being created, or delete markers to be added on
top of the object" (AWS). So on a locked bucket nobody can destroy seal 1234,
but anyone with `s3:PutObject` can write a second object under
`seals/000000001234.json`, and a naive reader that fetches "the object" gets
the newest version, which is the attacker's.

`If-None-Match: *` closes that door on stores that honour it (AWS since
2024; Hetzner must be verified, see below). Where it is ignored the second
Put succeeds and the key now has two versions. Either way the sink applies
one rule, and the verifier must apply the same one (ADR 0008, ADR 0015):

> A seal or proof key with more than one version, or with a delete marker,
> is a verification failure. The verifier reports it with the version list
> and never picks the newest, the oldest or the one that matches the
> database.

The rule is sound because the writer never legitimately writes a key twice:
seals are append-only with a strictly increasing sequence and proofs use a
provider-suffixed key. A transport retry whose first attempt reached the
store can produce `ErrExists` for data that was in fact written once; the
writer handles that by reading the key back and comparing bytes, which is
why `ErrExists` and `ErrMultipleVersions` are distinct errors.

`WithVerifyVersions(false)` removes the post-write and pre-read listing (and
the `s3:ListBucketVersions` permission from the writer). Use it only after
the probe has shown that the store refuses conditional overwrites, and keep
the verifier's version check regardless.

## Preflight: `Check`, `Describe` and the write probe

`Describe(ctx)` returns an `Info` with what the bucket reports:
`HeadBucket` reachability, `GetObjectLockConfiguration` (enabled, default
mode, days or years), `GetBucketVersioning`, and, with `WithProbeKey`, a
`ProbeResult`. `Check(ctx)` runs `Describe` and returns a joined error for
every problem: unreachable bucket, versioning not Enabled
(`ErrNotVersioned`), lock required but absent (`ErrNotLocked`), lock
present but no default retention and none configured on the sink
(`ErrUnprotected`), probe version deleted (`ErrUnprotected`), or a probe
delete that failed for a reason other than `AccessDenied`.

The probe writes a small `text/plain` object under the probe key, reads its
lock state with `HeadObject` (reported when the credential has
`s3:GetObjectRetention`) and issues `DeleteObject` with the version id. On a
retained version the store must answer 403 `AccessDenied`; that is the
observation you cite, not the configuration. Each run leaves one more locked
version under the probe key until retention expires, so pick a key outside
`seals/` (`probe/check`) and run it from the operator's credential, not from
the writer: the writer has no `s3:DeleteObjectVersion` and would report
`AccessDenied` for the wrong reason.

The probe cannot demonstrate COMPLIANCE as opposed to GOVERNANCE, because a
versioned delete without the bypass header is refused in both modes. Read
the mode from `ProbeResult.Mode` or `Info.DefaultMode` and, to be certain,
attempt the delete once with `--bypass-governance-retention` from a
credential that holds `s3:BypassGovernanceRetention`: a COMPLIANCE version
still refuses.

## Credentials and policy

Give the seal writer a credential that can add objects and nothing else.
Give the verifier a credential that can read and list. Neither can delete,
set or remove retention or legal holds, or change the bucket.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "SealWriter",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:user/tamperlog-writer"},
      "Action": ["s3:PutObject", "s3:ListBucketVersions", "s3:ListBucket"],
      "Resource": ["arn:aws:s3:::acme-audit-seals", "arn:aws:s3:::acme-audit-seals/prod/*"]
    },
    {
      "Sid": "SealVerifier",
      "Effect": "Allow",
      "Principal": {"AWS": "arn:aws:iam::123456789012:user/tamperlog-verifier"},
      "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket", "s3:ListBucketVersions"],
      "Resource": ["arn:aws:s3:::acme-audit-seals", "arn:aws:s3:::acme-audit-seals/prod/*"]
    },
    {
      "Sid": "NoShortRetention",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::acme-audit-seals/*",
      "Condition": {"NumericLessThan": {"s3:object-lock-remaining-retention-days": "3650"}}
    }
  ]
}
```

Notes:

- `s3:ListBucketVersions` on the writer is needed only for the default
  `WithVerifyVersions(true)`. `s3:ListBucket` lets the writer's `List` work
  and lets the SDK return `NoSuchKey` instead of `AccessDenied` for a
  missing key.
- The `NoShortRetention` statement is AWS-only (Hetzner does not document
  the condition key) and refuses any Put whose explicit retention is
  shorter than the policy's floor; with no explicit retention the bucket
  default applies and the condition passes.
- The operator credential that runs `Check` with a probe additionally needs
  `s3:GetObjectRetention` (to report the mode) and `s3:DeleteObjectVersion`
  (so that a refusal is a lock refusal, not a policy refusal), plus
  `s3:GetBucketObjectLockConfiguration` and `s3:GetBucketVersioning`.
- Hetzner Object Storage credentials are per project and bucket policies
  are supported with the exceptions listed on its "supported actions" page
  (no `NotAction`). Use a separate project for the seal bucket if you need a
  writer that cannot touch anything else.

## GOVERNANCE versus COMPLIANCE

Use COMPLIANCE for evidence. GOVERNANCE retention is removed or shortened by
any principal holding `s3:BypassGovernanceRetention` that also sends
`x-amz-bypass-governance-retention: true`, and the AWS console sends that
header by default, so a console delete by an administrator simply succeeds.
GOVERNANCE therefore protects against operators without the permission, not
against account administrators or a compromised admin credential. It is
suitable for staging, for rehearsing retention settings before committing to
ten years, and for operational artefacts a named break-glass identity should
be able to remove. The sink accepts either mode in `WithRetention`; `Check`
reports the mode it finds and does not refuse GOVERNANCE, because that is a
policy decision for the operator and the DPO.

COMPLIANCE is a cost and legal commitment: storage cannot be reclaimed
early even if the data turns out wrong, and a GDPR erasure request cannot
be honoured against it. Seals contain no personal data (stream names,
sequence numbers, hashes, times; ADR 0007, ADR 0008), which is what makes a
ten-year compliance lock defensible.

## Hetzner Object Storage

Hetzner's Object Storage (`fsn1|nbg1|hel1.your-objectstorage.com`) is
S3-compatible and supports Object Lock in both GOVERNANCE and COMPLIANCE
modes plus legal hold. Specifics from its documentation (dated 2024-09-23):

- Object Lock must be enabled when the bucket is created
  (`x-amz-bucket-object-lock-enabled: true`, or the
  `--object-lock-enabled-for-bucket` flag); it cannot be added later.
  Versioning is turned on with it and cannot be disabled.
- "In Compliance mode, no one can end the retention period earlier."
  Legal hold removal needs no special permission, so legal hold is not a
  substitute for retention.
- Lifecycle `NoncurrentVersionExpiration` supports only `NoncurrentDays`
  and skips locked versions.
- Use path-style addressing (`UsePathStyle = true`) and set `BaseEndpoint`;
  the region name is the location (`fsn1`).

What Hetzner does **not** document, and what you must therefore observe
rather than cite: whether `GetObjectLockConfiguration`,
`PutObjectRetention` and conditional `PutObject` (`If-None-Match`) are
supported at all (the supported-actions page lists exceptions but not the
Object Lock calls); and what happens to COMPLIANCE-locked objects when the
project or the account is deleted. AWS states that deleting the account is
the only way out of a compliance lock; Hetzner's documentation is silent,
and no third-party WORM assessment (of the kind Cohasset Associates
performed for AWS) was found. Before citing Hetzner retention to an auditor:

1. Run `Check` with `WithProbeKey` from the project owner's credential and
   keep the output: it records that a versioned delete of a freshly written
   object was refused with `AccessDenied` on that date.
2. Run the integration test (`go test -tags integration`) once against the
   bucket: it reports whether a duplicate Put was refused by `If-None-Match`
   (`ErrExists`) or detected after the fact (`ErrMultipleVersions`). If the
   latter, keep `WithVerifyVersions(true)` and say so in the system
   description.
3. Treat project or account deletion as an open residual risk and mitigate
   it the way the design notes do: a second sink in another provider or
   another legal entity's account, also under COMPLIANCE retention, and an
   alert on bucket deletion.

Hetzner has shown degraded Object Storage availability under load in some
locations. Seals are stored in the seal table before they are pushed to
sinks (ADR 0009) and business writes never wait for the seal writer, so a
sink outage delays the external copy; it does not block the application.
Monitor the writer's sink errors and alert when a seal has no sink copy
within the anchoring grace period.

## Cost of hourly seals

The default interval writes one seal per hour plus one proof per anchor
provider: 720 seals a month, 8 760 a year, each a few hundred bytes to a few
kilobytes depending on the number of streams. Ten years of hourly seals with
one proof each is under 200 000 objects and, at 2 KiB per seal and 6 KiB per
RFC 3161 token, roughly 1.4 GB. On Hetzner the base plan includes 1 TB and
charges nothing per request; on AWS the cost is dominated by PUT requests
(about 0.005 USD per thousand in eu-central-1) and comes to well under one
dollar a month. The sink's version check adds one `ListObjectVersions` per
Put and per Get, which doubles request count but not storage. The real cost
is the commitment: every one of those objects stays until its retention
date, so set the default retention to the statutory period and no longer.

## Operational checklist

- [ ] Dedicated bucket, Object Lock enabled at creation, versioning Enabled.
- [ ] Default retention COMPLIANCE, period equals the statutory retention.
- [ ] No lifecycle expiration rule on the seal prefix.
- [ ] Writer credential: `s3:PutObject` (+ `s3:ListBucket`,
      `s3:ListBucketVersions`); no delete, no retention, no bypass.
- [ ] Verifier credential: read and list only.
- [ ] `Check` with a probe key passed from the operator credential; output
      archived with the system description.
- [ ] Integration test run once per provider; conditional-write support
      recorded.
- [ ] Second sink in a different administrative domain for the
      bucket-deletion residual risk.
