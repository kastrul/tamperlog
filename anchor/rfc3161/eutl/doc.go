// Package eutl loads the EU List of Trusted Lists (ETSI TS 119 612) and
// answers whether a time-stamping authority was listed as a granted
// qualified time-stamping service (eIDAS QTST) at a given time.
//
// The European Commission publishes the List of Trusted Lists (LOTL) at
// https://ec.europa.eu/tools/lotl/eu-lotl.xml. It points to one trusted list
// per member state; each national list enumerates trust service providers,
// their services, the certificates that identify each service and the
// service's status history. [Loader] downloads and caches these lists and
// [List.Qualified] evaluates a certificate against them, feeding
// anchor.Attestation.Qualified.
//
// Matching is per status period: a certificate qualifies only when the
// digital identity listed for the period that contains the time-stamp's time
// authenticates it by key (exact certificate, public key, or an X509SKI equal
// to the SHA-1 of its public key); subject names never suffice. [Checker]
// takes a [Policy] that can refuse lists past their NextUpdate or missing
// territories, and [Loader.LoadWithRefresh] keeps a list current for
// long-running processes.
//
// Trust model: this package verifies TLS to the publishing hosts, not the
// XAdES signature on each list. See docs/anchors/eutl.md for the caveat and
// the available mitigations ([WithPinnedLOTLSHA256], [WithOffline], and the
// signing certificates exposed on each [Pointer]).
package eutl
