# Trust programs plan: X9 Financial PKI, S/MIME roots and client authentication

Author: Dejan Gregor. Date: 2026-11-21. Status: in progress. Decisions T1 to T3 taken as recommended on 2026-11-21.

## Problem

`dcert check` reports one root trust verdict (`src/trust.rs`, `classify`): a chain is
`publicly_trusted` only when it verifies to a root in the embedded `webpki-root-certs` set, and
a chain that ends in any other self-signed root is `private_pki`, described as "not in any
public root program". `webpki-root-certs` holds only the roots Mozilla trusts for websites
(server authentication). Publicly operated roots for other purposes are therefore reported as
private PKI, or as `incomplete` when the server does not send the root:

| Hierarchy | Operator | In the embedded set | Reported today | Correct description |
|---|---|---|---|---|
| X9 Financial PKI (production and UAT roots, two production intermediates) | DigiCert, under the ASC X9 certificate policy | No | `private_pki` or `incomplete` | Industry PKI, not trusted by browsers |
| Sectigo Public Email Protection Root R46 and E46 | Sectigo | No (checked in webpki-root-certs 1.0.12) | `private_pki` or `incomplete` | Mozilla trusted for email (S/MIME) only |
| DigiCert S/MIME roots | DigiCert | No (only DigiCert website roots are present) | `private_pki` or `incomplete` | Mozilla trusted for email only |
| Sectigo Public Server Authentication Root R46 and E46, USERTrust | Sectigo | Yes | `publicly_trusted` | Correct |
| Sectigo QWAC (eIDAS, PSD2) | Sectigo as a qualified trust service provider | The issuing CA "Sectigo Qualified Website Authentication CA R35" is reported as Mozilla included by Cloudflare Radar; the root it chains to is not yet confirmed | Probably `publicly_trusted` for website QWACs | Website trust plus EU trusted list status |

Client authentication is leaving public TLS: Chrome requires new public subordinate CAs to be
serverAuth only since 15 June 2026 and new public TLS certificates from 15 March 2027; Sectigo
already omits the clientAuth EKU by default and stops issuing it on 10 February 2027 and points
mTLS users to a private CA. Sectigo operates no public client authentication root and does not
take part in the X9 PKI (its X9 article calls X9 "a shared private CA, not a publicly trusted
infrastructure"). dcert says nothing about any of this today.

## Principles

1. Never call a chain `publicly_trusted` unless browsers trust it for websites; that boolean
   keeps its meaning.
2. Every other publicly operated root is recognised by the same offline cryptographic check
   against embedded certificates, never by name, so a private root that copies a name cannot
   match.
3. TLS verification (`verify_result`) is unchanged: recognising a root for classification does
   not make dcert trust it for connections.
4. Every embedded certificate has a recorded source URL, retrieval date and SHA-256, checked by a
   test.

## Decisions for Dejan

Decided 2026-11-21 (Dejan: "Proceed"): T1 `publicly_trusted_email`, T2 `industry_pki`, T3 not now.

- **T1.** Email only roots: a new classification `publicly_trusted_email` (recommended), or
  `publicly_trusted` with a purpose field. The new value keeps the existing boolean honest.
- **T2.** Industry PKIs: a new classification `industry_pki` with `trust_program`
  (recommended), or `private_pki` plus a `trust_program` field. Either changes the output for
  X9 chains; record it in the CHANGELOG.
- **T3.** EU trusted lists (QWAC qualification): later and opt in with a network fetch, or not
  at all (recommended until someone needs it).

## Phase P: anchors and sources

- [x] **P.1 Embed the X9 Financial PKI anchors.** `src/trust/anchors/x9/` with the three
  production roots (ECC P-256, RSA 2048, RSA 4096, valid until 12 June 2050), the two
  production intermediates (RSA 4096 ICA, RSA 4096 ICA EU, valid until 17 June 2035) and,
  separately flagged as preproduction, the three UAT roots and the three ML-DSA UAT roots, from
  DigiCert's knowledge base (INFO163). `sources.yaml` records name, URL, retrieval date, serial
  and SHA-256; a unit test recomputes each SHA-256 and compares it with the published value.
  Session notes: 2026-11-21. All 11 files downloaded and matched DigiCert's published SHA-256.
  Production: 3 roots (notBefore 2025-06-13, notAfter 2050-06-12) and 2 intermediates issued
  by the RSA 4096 Root (pathlen 0, to 2035-06-17); UAT: 3 RSA/ECC roots and 3 ML-DSA roots.
  Files in `src/trust_anchors/x9/`, sources in `scripts/trust_anchors.yaml` (the plan's
  `sources.yaml`), fingerprints also in `src/trust_programs.rs`, checked by a Rust test and by
  `gen_trust_anchors.py --check`. The ML-DSA roots need OpenSSL 3.5 to parse; on an older
  OpenSSL (the Linux release binary links the system one) they are skipped.
- [x] **P.2 Embed Mozilla's email trusted roots.** The roots Mozilla trusts for email and not
  for websites (among them Sectigo Public Email Protection Root R46 and E46 and the DigiCert
  S/MIME roots), taken from Mozilla's root data with trust bits at a pinned revision, written by
  a generator script with a `--check` mode like `scripts/gen_typed_tools.py`, so a new Mozilla
  release is a reviewed pull request. Confirm the list against the CCADB Included CA
  Certificate report before the first commit.
  Session notes: 2026-11-21. `scripts/gen_trust_anchors.py` reads NSS `certdata.txt` at
  `NSS_3_134_RTM` (SHA-256 pinned), joins certificates to trust objects by SHA-1 and keeps
  roots with email trust, without website trust and without an email distrust date: 52 roots,
  incl. Sectigo Public Email Protection Root R46/E46, DigiCert SMIME RSA4096/ECC P384 Root G5,
  GlobalSign Secure Mail R45/E45, HARICA, SSL.com and OISTE client roots, and legacy roots now
  trusted for email only (DigiCert Global Root CA, GlobalSign Root CA). NSS 3.134 is three days
  old; it was chosen over 3.133 because it removes the two Buypass roots. The CCADB report was
  not cross-checked separately: certdata.txt is Mozilla's own export of the same trust bits.
- [x] **P.3 Confirm the QWAC chain.** Find the root of "Sectigo Qualified Website
  Authentication CA R35" in CCADB or crt.sh and record whether website QWACs already classify
  as `publicly_trusted`. No code unless a gap is found.
  Session notes: 2026-11-21. crt.sh: "Sectigo Qualified Website Authentication CA R35" is
  issued by "USERTrust RSA Certification Authority" (2020-10-05 to 2035-10-04), which is in
  webpki-root-certs, so website QWACs already classify as `publicly_trusted`. No code.

## Phase C: classification

- [x] **C.1 Trust programs registry.** `src/trust/programs.rs`: each program has an id
  (`mozilla_tls`, `mozilla_email`, `x9_financial`), an operator, a purpose (server auth, email,
  industry mTLS), a browser trusted flag and its anchor set. `classify` tries the programs in
  order and records the first whose store verifies the chain; an embedded intermediate may
  complete the chain, so X9 servers that omit intermediates stop being `incomplete`.
  Session notes: 2026-11-21. `src/trust_programs.rs` (`PROGRAMS`: `mozilla_email`, then
  `x9_financial`); `PublicRoots` builds one `X509Store` per program (expiry ignored, as for the
  Mozilla set) and keeps program intermediates as untrusted helpers. `classify` tries the
  Mozilla website store, then each program, then the private and self-signed fallbacks. The
  X9 RSA 4096 ICA alone now classifies as `industry_pki` anchored on the RSA 4096 Root.
- [x] **C.2 Output.** `root_trust` gains `trust_program`, `operator`, `purpose` and
  `preproduction`; `classification` gains the values decided in T1 and T2; `publicly_trusted`
  stays true only for `mozilla_tls`. Pretty output, for example "X9 Financial PKI (DigiCert):
  industry PKI for mTLS, not trusted by browsers" and "Mozilla email trusted root (Sectigo
  Public Email Protection Root R46): trusted for S/MIME, not for websites".
  Session notes: 2026-11-21. New `classification` values `publicly_trusted_email` and
  `industry_pki` (also in the diagnostics `RootClass` and `kb/diagnostics.schema.json`); new
  fields `trust_program` (`mozilla_tls` for website chains), `operator`, `purpose`,
  `preproduction` (X9 only) and `purpose_note`; pretty output prints the program, operator and
  test-root flag.
- [x] **C.3 Purpose against EKU.** Report the leaf's EKUs next to the anchor's purpose and flag
  mismatches, for example a clientAuth only leaf under a website root, or a serverAuth leaf
  under an email only root.
  Session notes: 2026-11-21. `purpose_note` from the leaf's EKU (x509-parser): clientAuth
  without serverAuth under a website root (cites 15 March 2027 and 10 February 2027),
  serverAuth under an email-only root, clientAuth under an email root. Tests: X9 intermediate,
  X9 UAT root (preproduction), Sectigo Email Protection R46, a website root, impostor roots
  copying the X9 RSA 4096 Root and Sectigo R46 names (private), and the three notes. 717 and
  963 tests pass.

## Phase K: compliance and diagnostics

- [ ] **K.1 clientAuth in public TLS certificates.** A compliance finding when a leaf under a
  `mozilla_tls` root carries the clientAuth EKU: Chrome requires serverAuth only TLS
  certificates from 15 March 2027 and Sectigo stops issuing clientAuth on 10 February 2027.
  Severity info before the issuer's cutoff, warning after it. Suggest a private CA, an industry
  PKI such as X9, or a PSD2 QWAC for EU banking.
  Session notes:
- [ ] **K.2 Rules per program.** CA/Browser Forum checks (398 day validity, SCT presence) apply
  only to `mozilla_tls` chains; X9 chains are checked against the X9 certificate policy, read
  first and cited per finding; email chains against the S/MIME Baseline Requirements where
  dcert already has rules, otherwise skipped with a note. Confirm on a real X9 leaf which
  checks misfire today before changing anything.
  Session notes:
- [ ] **K.3 Knowledge base entries.** `diagnose` entries for "chain anchors to the X9 PKI and
  the client lacks the root" (install the DigiCert X9 bundle, or pass it with `--ca-cert`) and
  "server presents a certificate from an email only root".
  Session notes:

## Phase M: surfaces

- [ ] **M.1 MCP, Python and docs.** The MCP tools return the new fields through `root_trust`;
  regenerate the typed wrappers if a schema changes; README classification table and a trust
  programs section; `scripts/check_docs_commands.py` passes.
  Session notes:

## Phase T: tests

- [ ] **T.1 Tests.** A fake root that copies an X9 root's name and a fake root that copies
  Sectigo Public Email Protection Root R46 must not match; an X9 intermediate fixture; a UAT
  root marked preproduction; `publicly_trusted` unchanged for every existing test chain; the
  `sources.yaml` hash test.
  Session notes:

## Not in scope

- Trusting X9, email or QWAC roots for TLS connections.
- Fetching EU trusted lists (T3) unless decided otherwise.
- Sectigo private CA products: customer private roots stay `private_pki`.

## Sources

- DigiCert community root and authority certificates (X9 section):
  https://knowledge.digicert.com/general-information/community-root-authority-certificates
- DigiCert, issue X9 certificates: https://docs.digicert.com/en/trust-lifecycle-manager/enroll-and-manage-certificates/enrollment-how-to-guides/issue-x9-certificates-via-certcentral.html
- DTCC X9 Financial PKI FAQ: https://dtcclearning.com/documents/cross-product/5597-x9-digicert-faq-v2/file.html
- Sectigo, clarifying X9 PKI: https://www.sectigo.com/blog/clarifying-x9-pki-what-x9-certificates-are-and-are-not
- Sectigo, Chrome Root Program clientAuth and private PKI: https://www.sectigo.com/blog/chrome-root-program-clientauth-private-pki
- Sectigo, TLS client authentication changes: https://www.sectigo.com/blog/tls-client-authentication-public-ca-end-2026
- Sectigo public certificate chain: https://www.sectigo.com/knowledge-base/detail/Access-New-Sectigo-Certificate-Chain
- Sectigo eIDAS products: https://www.sectigo.com/eidas-products
- Cloudflare Radar, Sectigo Qualified Website Authentication CA R35: https://radar.cloudflare.com/certificate-transparency/ca/002393FA0A6825F77EF686E208620B97177791F02F07DB2518480FBE37CE7BD8
- CCADB Included CA Certificate report: https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReport
