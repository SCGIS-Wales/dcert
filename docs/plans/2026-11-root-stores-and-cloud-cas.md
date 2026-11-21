# Root stores and cloud provider CAs plan

Author: Dejan Gregor. Date: 2026-11-21. Status: implemented 2026-11-21; decisions R1 to R4 taken as recommended (Dejan: "You can do all the work on my behalf"). Builds on
`docs/plans/2026-11-trust-programs-x9-sectigo.md` (trust programs registry, pull requests
#172 to #175).

## Question

Which publicly operated TLS CAs does dcert miss because its "publicly trusted" verdict uses only
Mozilla's website roots, with attention to AWS, Azure and Google Cloud?

## Findings (CCADB reports downloaded 2026-11-21)

Source: the CCADB `MozillaTLSServerAuthenticationCSV`, `MicrosoftTLSServerAuthenticationCSV`,
`AppleTLSServerAuthenticationCSV` and `ChromeTLSServerAuthenticationCSV` reports, compared by
SHA-256 and by SPKI SHA-256 with the `webpki-root-certs` 1.0.12 set dcert embeds.

| Store | TLS roots | Not in Mozilla (certificate) | Not in Mozilla (key) |
|---|---|---|---|
| Mozilla | 112 (equal to webpki-root-certs 1.0.12) | | |
| Chrome | 100 | 5 | 5 |
| Apple | 117 | 38 | 37 |
| Microsoft | 181 | 82 | 77 |
| Any of the three | | 95 | **90** |

Five certificates share a key with a Mozilla root (reissues, cross-signs); they already verify.
The 90 others are a real gap: a chain to them is reported as `private_pki`, `incomplete` or
(for DigiCert G1 roots) email only, although Windows, macOS/iOS or Chrome trust it.

By store: 52 Microsoft only (many national and government CAs, for example Australian Defence
Public Root CA, the Finnish, Indian, Korean, Brazilian and Thai government roots, Visa TLS Root
CA, IdenTrust Commercial Root TLS RSA/ECC CA 2, NAVER Cloud, GoDaddy and Starfield TLS Root CA
- R1, DigiCert RSA4096/ECC P384 Root G5, QuoVadis TLS G4); 13 Apple only (the AffirmTrust and
Entrust roots Mozilla and Chrome distrusted, Chunghwa ePKI, COMODO Certification Authority);
20 Apple and Microsoft (DigiCert Global Root CA, Assured ID Root CA and High Assurance EV Root
CA, QuoVadis Root CA 2/3, GlobalSign Root CA, Go Daddy and Starfield Class 2, AAA Certificate
Services, GTS Root R2, Trustwave Global); 5 also in Chrome (Buypass Class 2 and 3, removed by
Mozilla in NSS 3.134, Certigna Root CA, DigiCert Trusted Root G4, QuoVadis Root CA 3 G3).

Partial distrust matters: Microsoft has a "Not Before" date on 35 of the non-Mozilla roots
(certificates issued after it are not trusted), Mozilla has TLS distrust-after dates on three
roots, and Chrome and Apple apply constraints. A verdict that ignores them would overstate trust.

### Cloud providers

| Provider | Public TLS roots (all in Mozilla) | Provider-operated CAs that no root store contains |
|---|---|---|
| AWS | Amazon Root CA 1 to 4 (all four stores), Starfield Services Root CA G2 (Mozilla, Apple, Microsoft; **not Chrome**) | RDS, Aurora, DocumentDB and Neptune database CAs `rds-ca-rsa2048-g1` (default), `rds-ca-rsa4096-g1`, `rds-ca-ecc384-g1`, published as `https://truststore.pki.rds.amazonaws.com/global/global-bundle.pem` (regional roots, valid to about 2061); AWS Private CA (customer roots, private by design) |
| Azure | DigiCert Global Root G2 and G3, Microsoft RSA and ECC Root Certificate Authority 2017, DigiCert TLS G5 roots (all four stores) | None found for public endpoints. Azure PaaS databases still tell clients to keep **DigiCert Global Root CA (G1)**, which Mozilla and Chrome removed for TLS on 2026-04-15 and Apple and Microsoft still trust; one Azure China page lists a "Microsoft TLS RSA Root G2" not in any CCADB TLS report (unconfirmed). |
| Google Cloud | GTS Root R1, R3, R4 and GlobalSign R4 (Mozilla); **GTS Root R2 is in Apple and Microsoft only** (Mozilla trusts it for email only, Chrome not at all) | Cloud SQL per-instance server CA (default; one CA per instance) and the regional shared CA (`GOOGLE_MANAGED_CAS_CA`); Memorystore for Redis per-instance CAs; AlloyDB self-signed certificates by default. None is downloadable as a fixed set. |

What this means for dcert users:
- An RDS or Aurora endpoint is reported as `private_pki` or `incomplete` today, although AWS
  publishes its CA bundle. That is the cloud case worth fixing with embedded anchors.
- A Google Cloud SQL, Memorystore or AlloyDB endpoint is correctly private (per instance), but
  dcert should say which service it is and how to fetch the CA (`gcloud sql instances describe
  --format='value(serverCaCert.cert)'`, the Memorystore `server_ca_certs`), not just "private".
- An Azure database still chaining to DigiCert Global Root CA is reported as email only; the
  verdict should say Microsoft and Apple still trust it for TLS while Mozilla and Chrome do not.
- A GTS Root R2 chain is reported as email only; it is trusted for TLS by Apple and Microsoft.

## Principles

1. `publicly_trusted` keeps its meaning (Mozilla websites) so existing scripts do not change.
2. Every embedded root is matched by signature and SPKI, never by name, and with its store's
   partial distrust dates and constraints.
3. Nothing here changes TLS verification.
4. Each embedded set has a pinned source, a SHA-256 and a `--check` freshness test, as in
   `scripts/gen_trust_anchors.py`.

## Decisions for Dejan

- **R1.** Which other stores to embed: Chrome, Apple and Microsoft (recommended), or Chrome only.
  Recommendation: all three, because Windows and Apple clients are where users meet these roots.
- **R2.** How to report them: a `root_stores` list on every verdict (`["mozilla", "chrome",
  "apple", "microsoft"]`) plus a new classification `publicly_trusted_other` when Mozilla is not
  in the list (recommended), or the list only.
- **R3.** Data source: the CCADB TLS reports, pinned by SHA-256 and refreshed by a reviewed pull
  request (recommended), or the Chromium `root_store.textproto` and Apple's published list for
  those two stores. CCADB's data usage terms apply and must be checked before committing (S.1).
- **R4.** AWS RDS bundle: embed as trust program `aws_rds` (recommended), or detect by name and
  advise only.

## Phase S: root store data

- [x] **S.1 CCADB data terms and pinning.** Read https://www.ccadb.org/rootstores/usage and
  record what redistribution of the reports in a binary allows. Stop and ask if it does not.
  Session notes: 2026-11-21. https://www.ccadb.org/rootstores/usage: CCADB data is under
  CDLA-Permissive-2.0 ("You may use, modify, and redistribute the data freely"), attribution to
  the CCADB is required and its name may not be used to endorse products. Attribution in
  `src/trust_anchors/NOTICE`; the page does not name the TLS reports explicitly.
- [x] **S.2 Generator.** `scripts/gen_root_stores.py`: download the four TLS reports, verify each
  certificate's SHA-256 from its PEM, record per root the stores that include it, Mozilla's
  distrust-after date, Microsoft's Not Before and disabled dates, and Chrome's and Apple's
  constraints; write `src/trust_anchors/root_stores.pem` (roots not in webpki-root-certs) and
  `src/trust_anchors/root_stores.json` (store membership by SPKI for every root). `--check`
  compares with the committed files; the daily audit runs it so a store change opens the
  existing issue.
  Session notes: 2026-11-21. `scripts/gen_root_stores.py` (sources in `scripts/trust_anchors.yaml`):
  207 roots in `root_stores.json` (stores, SPKI, Mozilla distrust-after, Chrome
  `sct_not_after_sec` and permitted DNS names, Apple constraints, Microsoft disabled date) and the
  95 certificates outside Mozilla in `root_stores.pem`, each PEM checked against its SHA-256.
  Microsoft "Not Before" dates are not recorded: their EKU lists never include Server
  Authentication. The reports are live, so `--check` runs in the daily audit (job `root-stores`),
  not in pull request CI.
- [x] **S.3 AWS RDS anchors.** Add `aws_rds` to `scripts/trust_anchors.yaml` from the global
  bundle, each root's SHA-256 pinned; `gen_trust_anchors.py --check` fails when AWS adds a
  region, so the update is a reviewed pull request.
  Session notes: 2026-11-21. Global bundle pinned (SHA-256 90a6f1a7...f21b), 114 self-signed regional
  roots (RSA2048, RSA4096, ECC384 G1), copied to `src/trust_anchors/aws_rds.pem`; checked by the
  same `--check`.

## Phase V: verdict

- [x] **V.1 Store membership.** `root_trust.root_stores` for every chain that anchors on a known
  root (also for `publicly_trusted`, so a Starfield Services G2 chain shows that Chrome lacks it).
  Session notes: 2026-11-21. `src/root_stores.rs` looks a root up by certificate SHA-256, else by SPKI
  (reissues and cross-signs); `root_trust.root_stores` for every verdict with an anchor.
- [x] **V.2 `publicly_trusted_other`.** When the anchor is in Chrome, Apple or Microsoft but not
  Mozilla, with `detail` naming the stores and any date that limits trust; a Microsoft Not
  Before date earlier than the leaf's notBefore means Microsoft does not trust this chain, and
  the verdict says so.
  Session notes: 2026-11-21. Program `other_root_stores` (browser trusted, purpose server_auth) gives
  `publicly_trusted_other`; Mozilla's and Chrome's distrust-after dates are compared with the
  leaf's notBefore and drop the store with a `store_notes` entry (Chrome's limit is on SCT
  times; notBefore is the available proxy). Test: Buypass Class 2 Root CA.
- [x] **V.3 Email-only roots with TLS trust elsewhere.** DigiCert Global Root CA, GTS Root R2 and
  GlobalSign Root CA are email only in Mozilla but TLS trusted by Apple and Microsoft: report
  `publicly_trusted_other` with both facts rather than `publicly_trusted_email`.
  Session notes: 2026-11-21. `other_root_stores` is tried before `mozilla_email`, so DigiCert Global
  Root CA is `publicly_trusted_other` with `root_stores: [apple, microsoft]` (test).
- [x] **V.4 AWS RDS program.** Chains to the RDS roots get a new classification
  `cloud_service_ca` (a provider's service CA, not an industry PKI) with `trust_program: aws_rds`,
  `operator: Amazon Web Services`, and the bundle URL in `detail`.
  Session notes: 2026-11-21. Program `aws_rds` gives `cloud_service_ca`; test with the us-east-1
  RSA2048 G1 root, and `dcert diagnose` names the RDS entry.
- [x] **V.5 Cloud service hints for private chains.** Name based hints only (not a trust verdict)
  for private chains whose issuer matches Google Cloud SQL, Memorystore, AlloyDB or AWS Private
  CA patterns: `root_trust.service_hint` with the provider's command to fetch the CA. Patterns
  verified against real certificates before they ship.
  Session notes: 2026-11-21. Only Google Cloud SQL's per-instance server CA (`O=Google, Inc`, `CN=Google
  Cloud SQL Server CA`, confirmed by a Cloud SQL forum thread and the InSpec resource docs) gets a
  `service_hint`. Memorystore, AlloyDB and AWS Private CA names could not be confirmed on real
  certificates, so they are not matched (the plan required verified patterns).

## Phase K: compliance and diagnostics

- [x] **K.1 Compliance scope.** `publicly_trusted_other` chains get the CA/Browser Forum rules (the
  other stores require the Baseline Requirements too); `cloud_service_ca` chains are advisory,
  like trust programs.
  Session notes: 2026-11-21. `ChainScope::from_trust`: `publicly_trusted_other` is `PublicTls`,
  `cloud_service_ca` is `Program("aws_rds")` (advisory rules).
- [x] **K.2 Diagnose entries.** "Chain trusted by Windows and Apple but not Mozilla or Chrome"
  (with the store list), "AWS RDS endpoint: install the RDS bundle", "Google Cloud SQL or
  Memorystore per-instance CA", "Azure database still on DigiCert Global Root CA".
  Session notes: 2026-11-21. `tls.handshake.root-not-in-mozilla` and `tls.handshake.aws-rds-ca`; the
  DigiCert G1 entry text updated; `kb validate` 88 entries. The Azure G1 case is covered by the
  root-not-in-mozilla and G1 entries; Cloud SQL by the service hint.

## Phase M: docs and tests

- [x] **M.1 Docs.** README classification table, the stores table, the cloud provider table and
  how to pass a provider bundle with `--ca-cert`; MCP descriptions; generated wrappers.
  Session notes: 2026-11-21. README classification and field tables, MCP description; docs check and
  generated wrappers pass.
- [x] **T.1 Tests.** A Microsoft-only root, a root with a Microsoft Not Before date, an Apple-only
  distrusted Entrust root, Starfield Services G2 (Chrome missing), GTS Root R2, an RDS regional
  root, impostor roots copying their names, and the freshness checks.
  Session notes: 2026-11-21. Rust: Buypass (other stores), DigiCert Global Root CA (V.3), a Mozilla
  root's stores, an RDS root, impostors copying Buypass and RDS names, Cloud SQL hint,
  distrust-after evaluation; Python: generator merge, refused mismatching PEM, committed files
  consistent. 731 tests, 977 with mcp. Not tested: Starfield Services G2 and GTS Root R2
  individually (covered by the same lookup).

## Not in scope

- Trusting any of these roots for TLS connections.
- Per-instance Google CAs as anchors (they cannot be enumerated).
- Customer private CAs (AWS Private CA, Google CA Service, Azure private PKI): they stay
  `private_pki`, with a hint where V.5 recognises the service.

## Sources

- CCADB resources and reports: https://www.ccadb.org/resources
- Mozilla, Microsoft, Apple and Chrome TLS reports, for example
  https://ccadb.my.salesforce-sites.com/ccadb/Report?Name=MicrosoftTLSServerAuthenticationCSV
- Chrome Root Store FAQ: https://chromium.googlesource.com/chromium/src/+/main/net/data/ssl/chrome_root_store/faq.md
- Amazon RDS SSL/TLS: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html
- Amazon RDS certificate rotation: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL-certificate-rotation.html
- Amazon DocumentDB certificates: https://docs.aws.amazon.com/documentdb/latest/devguide/ca_cert_rotation.html
- AWS IoT Core server authentication: https://docs.aws.amazon.com/iot/latest/developerguide/server-authentication.html
- Azure Certificate Authority details: https://learn.microsoft.com/en-us/azure/security/fundamentals/azure-certificate-authority-details
- Azure managed TLS changes: https://learn.microsoft.com/en-us/azure/security/fundamentals/managed-tls-changes
- Azure Database for MySQL root rotation: https://learn.microsoft.com/en-us/azure/mysql/flexible-server/security-tls-root-certificate-rotation
- Cloud SQL SSL/TLS: https://docs.cloud.google.com/sql/docs/mysql/authorize-ssl
- Cloud SQL customer-managed CA: https://docs.cloud.google.com/sql/docs/mysql/customer-managed-ca
- Memorystore for Redis Cluster customer-managed CA: https://docs.cloud.google.com/memorystore/docs/cluster/use-customer-managed-ca
