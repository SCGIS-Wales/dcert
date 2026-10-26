variable "region" {
  description = "AWS region for the throwaway test load balancer."
  type        = string
}

variable "name_prefix" {
  description = "Prefix for every resource name; keep it short (load balancer names are limited to 32 characters)."
  type        = string
  default     = "dcert-live"

  validation {
    condition     = can(regex("^[a-z0-9-]{1,20}$", var.name_prefix))
    error_message = "name_prefix must be 1 to 20 lower case letters, digits or hyphens."
  }
}

variable "allowed_cidrs" {
  description = "Client CIDRs allowed to reach the listeners, e.g. the CI runner's address as x.x.x.x/32."
  type        = list(string)

  validation {
    condition     = length(var.allowed_cidrs) > 0 && alltrue([for c in var.allowed_cidrs : can(cidrnetmask(c))])
    error_message = "allowed_cidrs must list at least one valid IPv4 CIDR."
  }
}

variable "policies" {
  description = "Listener port to ALB security policy. The live tests expect these two."
  type        = map(string)
  default = {
    "443"  = "ELBSecurityPolicy-TLS13-1-3-PQ-2025-09"
    "8443" = "ELBSecurityPolicy-TLS13-1-2-Res-PQ-2025-09"
  }
}

variable "extra_tags" {
  description = "Tags added to every resource besides the cleanup tags."
  type        = map(string)
  default     = {}
}
