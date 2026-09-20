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
