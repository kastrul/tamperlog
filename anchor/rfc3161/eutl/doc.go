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
// Trust model: this package verifies TLS to the publishing hosts, not the
// XAdES signature on each list. See docs/anchors/eutl.md for the caveat and
// the available mitigations ([WithPinnedLOTLSHA256], [WithOffline], and the
// signing certificates exposed on each [Pointer]).
package eutl
