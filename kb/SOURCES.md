# Sources for the diagnostics and reference knowledge bases

Every entry in `kb/diagnostics.yaml` and `kb/reference.yaml` that concerns
Amazon CloudFront or Amazon API Gateway was written from the pages below,
read on 2026-09-20. AWS documentation pages are also available as Markdown
by replacing `.html` with `.md` in the URL, which is how they were captured.

## Amazon CloudFront Developer Guide

| Topic | URL |
|-------|-----|
| Troubleshooting error response status codes (index) | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/troubleshooting-response-errors.html |
| HTTP 400 Bad Request | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/http-400-bad-request.html |
| HTTP 401 Unauthorized | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/http-401-unauthorized.html |
| HTTP 403 Invalid method | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/http-403-invalid-method.html |
| HTTP 403 Permission denied | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/http-403-permission-denied.html |
| HTTP 404 Not Found | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/http-404-not-found.html |
| HTTP 412 Precondition Failed | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/http-412-precondition-failed.html |
| HTTP 500 Internal Server Error | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/http-500-internal-server-error.html |
| HTTP 502 Bad Gateway | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/http-502-bad-gateway.html |
| HTTP 503 Service Unavailable | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/http-503-service-unavailable.html |
| HTTP 504 Gateway Timeout | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/http-504-gateway-timeout.html |
| Troubleshooting distribution issues | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/troubleshooting-distributions.html |
| How CloudFront processes 4xx and 5xx from the origin | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/HTTPStatusCodes.html |
| Generate custom error responses | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/GeneratingCustomErrorResponses.html |
| Request and response behaviour, custom origins | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RequestAndResponseBehaviorCustomOrigin.html |
| Request and response behaviour, S3 origins | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/RequestAndResponseBehaviorS3Origin.html |
| Headers CloudFront adds to origin requests | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/adding-cloudfront-headers.html |
| Viewer mTLS overview | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/mtls-authentication.html |
| Viewer mTLS validation modes (required, optional, passthrough) | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/mtls-validation-modes.html |
| Viewer mTLS headers | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/viewer-mtls-headers.html |
| Enable viewer mTLS | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/enable-mtls-distributions.html |
| Trust stores and certificate management | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/trust-stores-certificate-management.html |
| Certificate revocation (OCSP, KeyValueStore) | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/certificate-revocation.html |
| Additional mTLS settings | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/configuring-additional-settings.html |
| Connection Functions | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/connection-functions.html |
| Connection logs and error codes | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/connection-logs.html |
| Helper methods for mTLS | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/mtls-helper-methods-link.html |
| Origin mTLS overview | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/origin-mtls-authentication.html |
| Enable origin mTLS | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/origin-enable-mtls-distributions.html |
| Viewer protocols and ciphers | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html |
| CloudFront to origin protocols and ciphers | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-ciphers-cloudfront-to-origin.html |
| Certificate requirements | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cnames-and-https-requirements.html |
| Require HTTPS to a custom origin | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/using-https-cloudfront-to-custom-origin.html |
| Load testing | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/load-testing.html |
| Quotas | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/cloudfront-limits.html |
| API common errors | https://docs.aws.amazon.com/cloudfront/latest/APIReference/CommonErrors.html |

## Amazon API Gateway Developer Guide

| Topic | URL |
|-------|-----|
| Important notes (known issues) | https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-known-issues.html |
| Gateway response types | https://docs.aws.amazon.com/apigateway/latest/developerguide/supported-gateway-response-types.html |
| Gateway responses | https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-gatewayResponse-definition.html |
| Mutual TLS for REST APIs | https://docs.aws.amazon.com/apigateway/latest/developerguide/rest-api-mutual-tls.html |
| Mutual TLS for HTTP APIs | https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-mutual-tls.html |
| Security policy for custom domains | https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-custom-domain-tls-version.html |
| Supported security policies | https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-security-policies-list.html |
| Security policy for HTTP APIs | https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-ciphers.html |
| Endpoint types | https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-api-endpoint-types.html |
| Invoke a private API | https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-private-api-test-invoke-url.html |
| Client certificates for backend authentication | https://docs.aws.amazon.com/apigateway/latest/developerguide/getting-started-client-side-ssl-authentication.html |
| Quotas | https://docs.aws.amazon.com/apigateway/latest/developerguide/limits.html |
| Throttling | https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-request-throttling.html |
| Troubleshooting HTTP API Lambda integrations | https://docs.aws.amazon.com/apigateway/latest/developerguide/http-api-troubleshooting-lambda.html |

## AWS Knowledge Center (re:Post)

| Topic | URL |
|-------|-----|
| CloudFront HTTP 403 errors | https://repost.aws/knowledge-center/cloudfront-troubleshoot-403-errors |
| CloudFront 403 "Request Blocked" (WAF) | https://repost.aws/knowledge-center/cloudfront-error-request-blocked |
| CloudFront 403 "Bad Request" | https://repost.aws/knowledge-center/resolve-cloudfront-bad-request-error |
| CloudFront 502 "The request could not be satisfied" | https://repost.aws/knowledge-center/cloudfront-502-errors |
| CloudFront "wasn't able to connect to the origin" | https://repost.aws/knowledge-center/resolve-cloudfront-connection-error |
| CloudFront 503 | https://repost.aws/knowledge-center/cloudfront-503-error |
| CloudFront 504 | https://repost.aws/knowledge-center/cloudfront-troubleshoot-504-errors |
| Lambda@Edge 502 and 503 | https://repost.aws/knowledge-center/lambda-edge-500-errors |
| CloudFront CNAMEs and custom origins | https://repost.aws/knowledge-center/cloudfront-cname-origin |
| CloudFront ERR_SSL_PROTOCOL_ERROR | https://repost.aws/knowledge-center/cloudfront-ssl-connection-errors |
| S3 REST endpoint origin 403 | https://repost.aws/knowledge-center/s3-rest-api-cloudfront-error-403 |
| S3 website endpoint origin 403 | https://repost.aws/knowledge-center/s3-website-cloudfront-error-403 |
| Signed URL and signed cookie 403 | https://repost.aws/knowledge-center/cloudfront-troubleshoot-signed-url-cookies |
| Custom SSL certificate issues | https://repost.aws/knowledge-center/install-ssl-cloudfront |
| Cannot choose a custom certificate | https://repost.aws/knowledge-center/custom-ssl-certificate-cloudfront |
| ACM certificate does not appear or update | https://repost.aws/knowledge-center/acm-certificate-not-appearing-cloudfront |
| API Gateway 403 errors (x-amzn-ErrorType table) | https://repost.aws/knowledge-center/api-gateway-troubleshoot-403-forbidden |
| API Gateway mutual TLS 403 | https://repost.aws/knowledge-center/api-gateway-mutual-tls-403-errors |
| API Gateway Lambda authorizer 403 | https://repost.aws/knowledge-center/api-gateway-403-error-lambda-authorizer |
| API Gateway custom domain "Missing Authentication Token" | https://repost.aws/knowledge-center/api-gateway-403-custom-domain |
| API Gateway public API from a VPC 403 | https://repost.aws/knowledge-center/api-gateway-vpc-connections |
| API Gateway private endpoint connection issues | https://repost.aws/knowledge-center/api-gateway-private-endpoint-connection |
| API Gateway 5xx errors | https://repost.aws/knowledge-center/api-gateway-5xx-error |
| API Gateway 502 with Lambda proxy | https://repost.aws/knowledge-center/malformed-502-api-gateway |
| API Gateway 504 timeouts | https://repost.aws/knowledge-center/api-gateway-504-errors |
| API Gateway 401 with Lambda authorizer | https://repost.aws/knowledge-center/api-gateway-401-error-lambda-authorizer |
| API Gateway 401 with Cognito | https://repost.aws/knowledge-center/api-gateway-cognito-401-unauthorized |
| API Gateway with your own CloudFront distribution | https://repost.aws/knowledge-center/api-gateway-cloudfront-distribution |

## Service models

The control plane exception lists were generated from the botocore service
definitions (`botocore/data/<service>/<version>/service-2.json` on
https://github.com/boto/botocore): cloudfront 2020-05-31 (152 exceptions),
apigateway 2015-07-09 (7) and apigatewayv2 2018-11-29 (5).

## Certificate ecosystem changes (compliance engine, root trust, 2025 to 2026)

The validity schedule, revocation rules, SHA-1 sunset, clientAuth EKU
finding, the distrusted root and retired intermediate entries in
`kb/diagnostics.yaml` and the embedded root set assertions in `src/trust.rs`
were written from the pages below, read on 2026-10-10.

| Topic | URL |
|-------|-----|
| CA/B Forum ballot SC-081v3, schedule of reducing validity periods (398, 200, 100, 47 days) | https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/ |
| CA/B Forum ballot SC-063v4, OCSP optional, CRLs required, short lived certificates | https://cabforum.org/2023/07/14/ballot-sc063v4-make-ocsp-optional-require-crls-and-incentivize-automation/ |
| CA/B Forum ballot SC-097, sunset of all remaining SHA-1 signatures in certificates and CRLs | https://cabforum.org/2026/01/24/ballot-sc097-sunset-all-remaining-use-of-sha-1-signatures-in-certificates-and-crls/ |
| CA/B Forum Baseline Requirements, current text | https://cabforum.org/working-groups/server/baseline-requirements/requirements/ |
| Chrome Root Program policy (serverAuth only leaf certificates, root lifecycle) | https://googlechrome.github.io/chromerootprogram/ |
| Chrome Root Program, Entrust distrust (certificates issued after 2024-11-11) | https://security.googleblog.com/2024/06/sustaining-digital-certificate-security.html |
| Chrome Root Program, Chunghwa Telecom and NetLock distrust (certificates issued after 2025-07-31) | https://security.googleblog.com/2025/05/sustaining-digital-certificate-security-chrome-root-store-changes.html |
| Mozilla CA Root CA Lifecycles (websites trust bit removals, 2026-04-15) | https://wiki.mozilla.org/CA/Root_CA_Lifecycles |
| Mozilla decision on Entrust root CA certificates used for TLS | https://groups.google.com/a/mozilla.org/g/dev-security-policy/c/jCvkhBjg9Yw |
| DigiCert root strategy, G1 root removal and G5 default issuance | https://knowledge.digicert.com/alerts/digicert-root-strategy-aligning-with-industry-standards |
| Let's Encrypt chains of trust (R3, R4, E1, E2 expired 2025-09-15; R10 to R14 and E5 to E9 retired; YR1, YR2, YE1, YE2) | https://letsencrypt.org/certificates/ |
| Let's Encrypt Generation Y hierarchy announcement | https://letsencrypt.org/2025/11/24/gen-y-hierarchy |
| NIST IR 8547 (draft), transition to post quantum cryptography standards | https://csrc.nist.gov/pubs/ir/8547/ipd |
| FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA), FIPS 203 (ML-KEM) | https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization |
| RFC 9881, ML-DSA in X.509 | https://www.rfc-editor.org/rfc/rfc9881 |

The embedded public root set is the `webpki-root-certs` crate (1.0.9 at the
time of writing), which packages the Mozilla/CCADB root store. Verified on
2026-10-10 by iterating the embedded roots: Entrust roots, GTS Root R2 and
the DigiCert G1 roots are absent; the Chunghwa Telecom HiPKI and NetLock
roots are still present because Mozilla still includes them, which is why
the Chrome specific entry explains a chain dcert itself classifies as
publicly trusted.


## mTLS, Apigee, Envoy and nginx (read on 2026-10-24)

The vendor neutral `mtls.server.*` entries, the `tls.handshake.*` entries
rewritten without AWS specifics, and the `mtls.nginx.*`, `envoy.*` and
`apigee.*` entries were written from:

- RFC 8446 (TLS 1.3): https://www.rfc-editor.org/rfc/rfc8446 — section
  4.3.2 (CertificateRequest), 4.4.2 (Certificate, chain order), 6.2 (alerts,
  including `certificate_required`, 116).
- RFC 8996 (deprecating TLS 1.0 and 1.1): https://www.rfc-editor.org/rfc/rfc8996
- RFC 6066 section 3 (Server Name Indication): https://www.rfc-editor.org/rfc/rfc6066
- OpenSSL `SSL_CTX_set_cert_cb(3)` ("called before a certificate will be
  used by a client or server ... always called even if a certificate is
  already set") and `SSL_get_client_CA_list(3)` ("In client mode ...
  returns the list of client CAs sent from the server"). A client only
  prepares a certificate after a CertificateRequest (OpenSSL's client state
  machine, `tls_prepare_client_certificate`), which is what `src/mtls.rs`
  relies on; the loopback tests in `tests/cli_tests.rs` confirm it on TLS
  1.2 and 1.3.
- Apigee hybrid, "Configuring TLS and mTLS on the ingress gateway":
  https://docs.cloud.google.com/apigee/docs/hybrid/v1.16/ingress-tls —
  `virtualhosts[].tlsMode: MUTUAL` with `caCertPath` (or a CA secret);
  `SIMPLE` is the one way TLS default. The configuration property reference
  (https://docs.cloud.google.com/apigee/docs/hybrid/v1.16/config-prop-ref)
  documents `minTLSProtocolVersion` and `cipherSuites`.
- Apigee runtime error catalog:
  https://cloud.google.com/apigee/docs/api-platform/errorcatalog/mp-runtime-errorcatalog
  — the `{"fault": {"faultstring", "detail": {"errorcode"}}}` response
  format, `messaging.adaptors.http.flow.SslHandshakeFailed` (503),
  `ServiceUnavailable` and `NoActiveTargets` (503), `GatewayTimeout` (504),
  `UnexpectedEOFAtTarget` (502) and `flow.APITimedOut` (504).
- nginx `ngx_http_ssl_module`, "Error Processing":
  https://nginx.org/en/docs/http/ngx_http_ssl_module.html#errors — the
  non standard 495 (certificate verification error) and 496 (required
  certificate not presented) codes, which nginx answers as 400 with the
  "The SSL certificate error" and "No required SSL certificate was sent"
  pages.
- Envoy `DownstreamTlsContext.require_client_certificate` and
  `UpstreamTlsContext`:
  https://www.envoyproxy.io/docs/envoy/latest/api-v3/extensions/transport_sockets/tls/v3/tls.proto
  and response code details:
  https://www.envoyproxy.io/docs/envoy/latest/configuration/http/http_conn_man/response_code_details

## TLS security policies (`kb/tls_policies.yaml`, read on 2026-10-26)

`scripts/fetch_aws_tls_policies.py download` reduces these pages to their
tables (and Mozilla's JSON) in `scripts/data/tls_policy_sources.json`;
`generate` writes the catalogue from that snapshot. Facts the ALB page states
only in prose (the ML-KEM hybrid groups of the PQ policies, the console and
CLI defaults) are recorded in `scripts/tls_policies.yaml` under `statements`.
Where the NLB page's two tables disagree about a policy, the catalogue keeps
the ciphers by policy table and says so in the entry's `notes`.

| Provider | URL |
|----------|-----|
| Application Load Balancer security policies | https://docs.aws.amazon.com/elasticloadbalancing/latest/application/describe-ssl-policies.html |
| Network Load Balancer security policies | https://docs.aws.amazon.com/elasticloadbalancing/latest/network/describe-ssl-policies.html |
| CloudFront viewer protocols and ciphers | https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/secure-connections-supported-viewer-protocols-ciphers.html |
| API Gateway security policies | https://docs.aws.amazon.com/apigateway/latest/developerguide/apigateway-security-policies-list.html |
| Mozilla server side TLS guidelines 6.0 | https://ssl-config.mozilla.org/guidelines/6.0.json |

