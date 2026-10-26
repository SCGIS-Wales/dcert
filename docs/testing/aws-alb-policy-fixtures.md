# Live tests against AWS ALB security policies

The hermetic tests in `tests/policy_alb_pq.rs` check `dcert policy test`
against loopback servers built from the catalogue. The live tests in
`tests/policy_alb_live.rs` check the same verdicts against real Application
Load Balancers, which proves the catalogue matches what AWS actually serves.

They are manual and opt in. Without the two environment variables below the
live tests skip, so `cargo test` never needs AWS.

## What the fixture creates

`infra/test-alb` (Terraform, AWS provider 6) creates one throwaway stack:

| Resource | Purpose |
| --- | --- |
| VPC, two public subnets, internet gateway, route table | Network for an internet facing ALB |
| Security group | HTTPS from `allowed_cidrs` only, on the listener ports |
| Two self signed certificates (RSA 2048 and ECDSA P-256) imported into ACM | Dual certificate listeners, so the ECDSA ciphers are tested too |
| ALB with listener 443 (`ELBSecurityPolicy-TLS13-1-3-PQ-2025-09`) and 8443 (`ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09`) | The two policies under test; each answers with a fixed 200 response |

Every resource carries `Project=dcert-live-tests`, `ManagedBy=terraform` and
`Ephemeral=true`, so anything left behind is easy to find and remove. State
is local; the stack lives only for one run. An ALB costs a few US cents per
hour.

## Running it locally

Requirements: Terraform 1.9 or later, AWS credentials for the test account
in the environment, and a Rust toolchain (the vendored OpenSSL build has
ML-KEM, so the post quantum group checks run for real).

```bash
export AWS_REGION=eu-west-2        # any region with ALB PQ policies
make live-alb                      # apply, test, and always destroy
```

The steps can also run separately: `make live-alb-up`, `make live-alb-test`
and `make live-alb-down`. `ALLOWED_CIDR` defaults to your public address
(`checkip.amazonaws.com`) as a `/32`; set it explicitly behind a NAT or
proxy.

To point the tests at load balancers you manage yourself, skip Terraform
and set the URLs directly:

```bash
DCERT_LIVE_ALB_TLS13_1_3_PQ_URL=https://<alb-dns>:443 \
DCERT_LIVE_ALB_TLS13_1_2_RES_PQ_URL=https://<alb-dns>:8443 \
cargo test --features vendored --test policy_alb_live -- --nocapture
```

## What the tests assert

- Each listener is `conformant` to its policy with no deviations when the
  linked OpenSSL has ML-KEM, and `inconclusive` (group checks not testable,
  nothing failed) otherwise.
- `--identify` against the Res-PQ listener names
  `ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09` as the best fit.

A deviation here means either the catalogue or AWS changed. Regenerate the
catalogue (`scripts/fetch_aws_tls_policies.py download` then `generate`) and
compare before changing any test.

## Running it from GitHub Actions

`.github/workflows/live-alb.yml` runs on manual dispatch only. It assumes an
IAM role through GitHub OIDC (no AWS keys are stored), applies the fixture,
runs the tests and destroys the fixture, even when the tests fail. Tick
`keep` to leave the stack up for debugging, then run `make live-alb-down`.

Set two repository variables (Settings, Secrets and variables, Actions,
Variables):

| Variable | Example |
| --- | --- |
| `DCERT_LIVE_ALB_REGION` | `eu-west-2` |
| `DCERT_LIVE_ALB_ROLE_ARN` | `arn:aws:iam::123456789012:role/dcert-live-alb` |

### IAM role trust policy

The account needs the GitHub OIDC provider
(`token.actions.githubusercontent.com`, audience `sts.amazonaws.com`). The
role trusts only this repository's `main` branch and manual runs:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Federated": "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
      },
      "Action": "sts:AssumeRoleWithWebIdentity",
      "Condition": {
        "StringEquals": {
          "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          "token.actions.githubusercontent.com:sub": "repo:SCGIS-Wales/dcert:ref:refs/heads/main"
        }
      }
    }
  ]
}
```

### IAM role permissions

Limited to the services the fixture uses and to one region:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:CreateVpc", "ec2:DeleteVpc", "ec2:ModifyVpcAttribute",
        "ec2:CreateSubnet", "ec2:DeleteSubnet",
        "ec2:CreateInternetGateway", "ec2:DeleteInternetGateway",
        "ec2:AttachInternetGateway", "ec2:DetachInternetGateway",
        "ec2:CreateRouteTable", "ec2:DeleteRouteTable", "ec2:CreateRoute",
        "ec2:AssociateRouteTable", "ec2:DisassociateRouteTable",
        "ec2:CreateSecurityGroup", "ec2:DeleteSecurityGroup",
        "ec2:AuthorizeSecurityGroupIngress", "ec2:RevokeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupEgress",
        "ec2:CreateTags", "ec2:Describe*",
        "elasticloadbalancing:*",
        "acm:ImportCertificate", "acm:DeleteCertificate",
        "acm:DescribeCertificate", "acm:GetCertificate",
        "acm:AddTagsToCertificate", "acm:ListTagsForCertificate"
      ],
      "Resource": "*",
      "Condition": {
        "StringEquals": { "aws:RequestedRegion": "eu-west-2" }
      }
    }
  ]
}
```

Use a dedicated sandbox account where possible, so the broad
`elasticloadbalancing:*` grant cannot touch anything else.

## Cleaning up after an interrupted run

If a run dies before `destroy`, remove the stack from the same checkout with
`make live-alb-down`. Without the local state, find the resources by tag in
the console or with:

```bash
aws resourcegroupstaggingapi get-resources \
  --tag-filters Key=Project,Values=dcert-live-tests --region "$AWS_REGION"
```
