# EU Trusted Lists (eIDAS qualified status)

Package `github.com/kastrul/tamperlog/anchor/rfc3161/eutl` loads the EU List
of Trusted Lists and the national trusted lists it points to, and answers one
question for the RFC 3161 verifier: was the time-stamping authority that signed
a token listed as a *granted qualified time-stamping service* at the token's
`genTime`? The answer feeds `anchor.Attestation.Qualified`.

## What the trusted list is

Under eIDAS (Regulation (EU) 910/2014, Art. 22) every member state publishes a
*trusted list* of the qualified trust service providers it supervises and the
qualified services they operate. The European Commission publishes the *List
of Trusted Lists* (LOTL), which points to each national list and names the
certificates that sign it. The format is ETSI TS 119 612 (XML namespace
`http://uri.etsi.org/02231/v2#`).

Facts confirmed against the live LOTL (sequence 397, October 2026):

- LOTL location: `https://ec.europa.eu/tools/lotl/eu-lotl.xml`
  (`TSLType` `.../TSLType/EUlistofthelists`, `SchemeTerritory` `EU`).
- `SchemeInformation` carries `TSLSequenceNumber`, `ListIssueDateTime`,
  `NextUpdate/dateTime` and `PointersToOtherTSL/OtherTSLPointer`. Each pointer
  has `ServiceDigitalIdentities` (the X.509 certificates entitled to sign the
  pointed list), `TSLLocation` (the URL) and `AdditionalInformation/
  OtherInformation` elements holding `TSLType`, `SchemeTerritory` and
  `MimeType` (the last in namespace
  `http://uri.etsi.org/02231/v2/additionaltypes#`). Only pointers with
  `MimeType` `application/vnd.etsi.tsl+xml` are machine-readable lists; the
  others are PDF renderings. The LOTL also points to itself and to the frozen
  post-Brexit UK list; the loader skips the self-pointer.
- A national list has `TrustServiceProviderList/TrustServiceProvider` with
  `TSPInformation/TSPName/Name` (multilingual, `xml:lang`) and
  `TSPServices/TSPService`. Each service has `ServiceInformation` with
  `ServiceTypeIdentifier`, `ServiceName`, `ServiceDigitalIdentity/DigitalId`
  (`X509Certificate` base64 DER, `X509SKI`, `X509SubjectName`), `ServiceStatus`
  and `StatusStartingTime`, plus `ServiceHistory/ServiceHistoryInstance`
  entries with the same shape for earlier periods. History instances carry
  their own digital identity and type; the loader merges them.
- Time-stamping types: `http://uri.etsi.org/TrstSvc/Svctype/TSA/QTST`
  (qualified), `.../TSA/TSS-QC` and `.../TSA` (not qualified).
- Statuses: `http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted` and
  `.../withdrawn` are the eIDAS statuses. Lists also still carry pre-2016
  Directive statuses (`accredited`, `undersupervision`,
  `supervisionincessation`, `supervisionceased`, `accreditationrevoked`) and
  national ones (`recognisedatnationallevel`, `deprecatedatnationallevel`).
  Only `granted` counts as qualified here.
- Estonia: `SchemeTerritory` `EE`, list at
  `https://sr.riik.ee/tsl/estonian-tsl.xml`, operator Estonian Information
  System Authority (RIA); the qualified time-stamping provider is SK ID
  Solutions AS.

## What "qualified" means for an auditor

A qualified electronic time stamp (eIDAS Art. 42: bound to the data so that
undetectable change is precluded, based on an accurate time source, signed by
a qualified trust service provider) enjoys the presumption of Art. 41(2): the
accuracy of the date and time it indicates and the integrity of the data bound
to it are presumed. In a dispute the party challenging the seal must rebut
that presumption; a non-qualified time stamp is merely admissible evidence
(Art. 41(1)) that the holder must support.

For a tamperlog seal, `Qualified = true` therefore means: the RFC 3161 token
verified cryptographically, its TSA certificate (or the CA that issued it) is
the digital identity of a service of type QTST on a member state's trusted
list, and that service's status at `genTime` was `granted`. An auditor can
reproduce this from the seal's proof bytes and an archived copy of the lists
(see "Reproducible verification" below).

## Loading and caching

```go
loader := eutl.NewLoader(
    eutl.WithCacheDir("/var/cache/tamperlog/eutl"), // <sha256(url)>.xml + .meta
    eutl.WithMaxAge(24*time.Hour),                  // default
    eutl.WithTerritories("EE", "LV", "LT"),          // default: all XML lists
)
list, err := loader.Load(ctx)
if err != nil {
    return err // the LOTL itself could not be loaded or failed the pin
}
for territory, err := range list.Errors {
    log.Printf("eutl: %s skipped: %v", territory, err) // a national list failed
}
if time.Now().After(list.LOTL.NextUpdate) {
    return errors.New("LOTL is past its NextUpdate; refusing to trust it")
}
```

`Load` fetches the LOTL, then the selected national lists four at a time,
each limited to 32 MiB and required to be `https`. A national list that fails
to download or parse is skipped and recorded in `List.Errors`; only a LOTL
failure fails the call. With a cache directory each list is served from disk
while younger than the max age and revalidated with `If-None-Match` /
`If-Modified-Since` afterwards (ec.europa.eu returns `ETag` and
`Last-Modified`; a `304` refreshes the cache timestamp without a download).
`NextUpdate` is exposed on `List.LOTL` and on every `List.Lists[territory]`
so the caller can refuse stale lists; it is the zero time for a closed list
(the UK list has an empty `NextUpdate`).

Wire the result into the RFC 3161 verifier through the adapter:

```go
check := eutl.Checker(list, func(c *x509.Certificate) []*x509.Certificate {
    return issuersOf(c) // the CA chain the verifier built for the TSA certificate
})
verifier := rfc3161.NewVerifier(roots, rfc3161.WithQualifiedChecker(check))
```

`chainResolver` matters: some lists identify a time-stamping service by the
time-stamp unit's own certificate, others by the CA that issues TSU
certificates. `List.Lookup(cert, chain)` tries the TSA certificate and every
chain element, by exact DER first, then by subject key identifier, then by
subject name. `Match.By` reports which; a `"subject"` match is the weakest
and is only trustworthy because the verifier has already validated the chain
to pinned roots.

## Signature caveat and mitigation

Every trusted list is XAdES-signed, and the certificates allowed to sign the
LOTL are published in the Official Journal of the EU. **This package does not
verify those XML signatures.** Implementing XML-DSig (canonicalisation,
reference digests, XAdES qualifying properties) is out of scope. What the
loader trusts instead is TLS to `ec.europa.eu` and to each national host:
a compromise of one of those hosts or of a certificate authority they use
could feed the loader a forged list.

Mitigations available today:

- `WithPinnedLOTLSHA256(hex)` fails `Load` unless the LOTL bytes hash to the
  pinned digest. Record the digest of the LOTL that was current when a seal
  was anchored and pin it when re-verifying from an evidence bundle.
- `WithOffline()` reads only the cache, so verification can run on an
  air-gapped machine from an archived cache directory.
- Each `Pointer.SigningCertificates` carries the certificates the LOTL names
  for the pointed list, and the LOTL's own self-pointer names the LOTL signing
  certificates (compare with the Official Journal). A future XML-DSig step
  can check each list's `ds:Signature` against these without changing the
  parser.
- The verifier does not depend on the lists for integrity: a forged list can
  only change the `Qualified` flag, never make an invalid token verify.

## Refresh cadence

Lists set a `NextUpdate` about six months ahead but are reissued whenever a
service changes status, typically monthly and sometimes daily. Run `Load` at
least once a day (the default 24 h cache max age encodes this) and alert when
`List.Errors` is non-empty for a territory you depend on or when a list's
`NextUpdate` has passed. The revalidation step is cheap: a current LOTL
answers `304` and no body is transferred.

Publisher quirks observed in October 2026, all recorded in `List.Errors`
rather than failing `Load`:

- `sr.riik.ee` (Estonia) sits behind a Cloudflare JavaScript challenge and
  answers `403` to non-browser clients, including Go's `net/http` and curl.
  Until RIA whitelists automated access, obtain the Estonian list through a
  browser or an institutional mirror, put it in the cache directory under the
  loader's `CachePath(url)` with a matching `.meta`, or use `WithOffline()`.
- `tl.nbu.gov.sk` (Slovakia) is pointed to over plain `http`; the loader
  refuses non-https locations.
- `tsl.gov.cz` answers `406` unless `*/*` is acceptable; the loader sends it.
- The UK list is closed (`<NextUpdate/>`) and carries no QTST services.

## Verifying a ten-year-old seal

Trusted lists are status *histories*, not snapshots. A service withdrawn
today was still qualified for every token it issued while `granted`; a
service granted last year was not qualified for tokens it issued before. The
verifier therefore evaluates `Service.History` at the token's `genTime`
(`Service.StatusAt(t)`, `Service.QualifiedAt(t)`), never the current status.
`List.Qualified(cert, chain, at)` does exactly this.

Worked example. SK ID Solutions AS's qualified time-stamping service appears
on the Estonian list with a history like: `undersupervision` (type `TSA`)
before 1 July 2016, `granted` (type `QTST`) from 1 July 2016, and, if the
service is ever retired, `withdrawn` from that date. A seal anchored in 2026
is `Qualified` because the period in force at its `genTime` is `granted`/
`QTST`; a seal anchored in 2015 is not, although the certificate matches, and
a seal anchored after a withdrawal is not either. The test fixture
`anchor/rfc3161/eutl/testdata/ee-tl.xml` encodes this shape with a synthetic
provider and dates (granted 2016, withdrawn 2030).

Two consequences for long retention:

- Keep the lists. Member states remove providers from their lists years after
  withdrawal, and the LOTL only points to the current national list. Archive
  the cache directory (or at least the LOTL and the relevant national list
  with their SHA-256) next to the seals and proofs they qualify, and pin the
  LOTL digest when re-verifying. This is the "reproducible verification"
  bundle; `WithOffline()` consumes it.
- Keep the chain. Matching by issuing CA requires the CA certificate the TSA
  used at the time, which the RFC 3161 token normally embeds; store the
  token unchanged and let the verifier pass its chain to `Checker`.
