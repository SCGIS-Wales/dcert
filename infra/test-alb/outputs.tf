output "urls" {
  description = "HTTPS URL of each listener, keyed by its security policy."
  value       = { for port, policy in var.policies : policy => "https://${aws_lb.this.dns_name}:${port}" }
}

output "tls13_1_3_pq_url" {
  description = "Value for DCERT_LIVE_ALB_TLS13_1_3_PQ_URL."
  value       = "https://${aws_lb.this.dns_name}:443"
}

output "tls13_1_2_res_pq_url" {
  description = "Value for DCERT_LIVE_ALB_TLS13_1_2_RES_PQ_URL."
  value       = "https://${aws_lb.this.dns_name}:8443"
}
