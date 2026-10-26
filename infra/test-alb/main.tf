# One internet facing Application Load Balancer with an HTTPS listener per
# security policy, a fixed response and self-signed RSA and ECDSA
# certificates imported into ACM (no domain or DNS needed: dcert's policy
# test skips verification). Everything is tagged for cleanup and is meant to
# live only for one test run: `make live-alb` applies, tests and destroys.

locals {
  tags = merge(
    {
      Project   = "dcert-live-tests"
      ManagedBy = "terraform"
      Ephemeral = "true"
    },
    var.extra_tags,
  )
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "this" {
  cidr_block           = "10.98.0.0/16"
  enable_dns_hostnames = true
  tags                 = { Name = "${var.name_prefix}-vpc" }
}

resource "aws_internet_gateway" "this" {
  vpc_id = aws_vpc.this.id
  tags   = { Name = "${var.name_prefix}-igw" }
}

resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.this.id
  cidr_block              = cidrsubnet(aws_vpc.this.cidr_block, 8, count.index)
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = false
  tags                    = { Name = "${var.name_prefix}-public-${count.index}" }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.this.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.this.id
  }

  tags = { Name = "${var.name_prefix}-public" }
}

resource "aws_route_table_association" "public" {
  count          = length(aws_subnet.public)
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

resource "aws_security_group" "alb" {
  name        = "${var.name_prefix}-alb"
  description = "dcert live policy tests: HTTPS from the test client only"
  vpc_id      = aws_vpc.this.id
}

resource "aws_vpc_security_group_ingress_rule" "https" {
  for_each = { for pair in setproduct(keys(var.policies), var.allowed_cidrs) : "${pair[0]}-${pair[1]}" => pair }

  security_group_id = aws_security_group.alb.id
  ip_protocol       = "tcp"
  from_port         = tonumber(each.value[0])
  to_port           = tonumber(each.value[0])
  cidr_ipv4         = each.value[1]
}

# Self-signed identities: one RSA and one ECDSA, so dual certificate
# behaviour (ECDSA suites) is exercised too.
resource "tls_private_key" "rsa" {
  algorithm = "RSA"
  rsa_bits  = 2048
}

resource "tls_private_key" "ecdsa" {
  algorithm   = "ECDSA"
  ecdsa_curve = "P256"
}

resource "tls_self_signed_cert" "rsa" {
  private_key_pem       = tls_private_key.rsa.private_key_pem
  validity_period_hours = 24
  allowed_uses          = ["digital_signature", "key_encipherment", "server_auth"]

  subject {
    common_name = "dcert-live.invalid"
  }
}

resource "tls_self_signed_cert" "ecdsa" {
  private_key_pem       = tls_private_key.ecdsa.private_key_pem
  validity_period_hours = 24
  allowed_uses          = ["digital_signature", "server_auth"]

  subject {
    common_name = "dcert-live.invalid"
  }
}

resource "aws_acm_certificate" "rsa" {
  private_key      = tls_private_key.rsa.private_key_pem
  certificate_body = tls_self_signed_cert.rsa.cert_pem
}

resource "aws_acm_certificate" "ecdsa" {
  private_key      = tls_private_key.ecdsa.private_key_pem
  certificate_body = tls_self_signed_cert.ecdsa.cert_pem
}

resource "aws_lb" "this" {
  name                       = "${var.name_prefix}-alb"
  load_balancer_type         = "application"
  internal                   = false
  security_groups            = [aws_security_group.alb.id]
  subnets                    = aws_subnet.public[*].id
  drop_invalid_header_fields = true
  enable_deletion_protection = false
}

resource "aws_lb_listener" "https" {
  for_each = var.policies

  load_balancer_arn = aws_lb.this.arn
  port              = tonumber(each.key)
  protocol          = "HTTPS"
  ssl_policy        = each.value
  certificate_arn   = aws_acm_certificate.rsa.arn

  default_action {
    type = "fixed-response"

    fixed_response {
      content_type = "text/plain"
      message_body = "dcert live policy test"
      status_code  = "200"
    }
  }
}

resource "aws_lb_listener_certificate" "ecdsa" {
  for_each = aws_lb_listener.https

  listener_arn    = each.value.arn
  certificate_arn = aws_acm_certificate.ecdsa.arn
}
