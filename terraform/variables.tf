variable "subscription_id" {
  description = "Azure subscription ID"
  type        = string
}

variable "region" {
  description = "Azure region for all resources"
  type        = string
  default     = "uksouth"
}

variable "environment" {
  description = "Environment name (dev, stage, prod)"
  type        = string
  default     = "prod"
}

variable "vm_size" {
  description = "Azure VM size"
  type        = string
  default     = "Standard_B2ms"
}

variable "admin_username" {
  description = "VM admin username"
  type        = string
  default     = "cybersorted"
}

variable "admin_ssh_public_key" {
  description = "SSH public key for VM access"
  type        = string
}

variable "allowed_ssh_cidr" {
  description = "CIDR block allowed to SSH into the VM (e.g. your office IP)"
  type        = string
}

variable "gcp_project" {
  description = "GCP project ID for Firestore/GCS access"
  type        = string
  default     = "cybersorted-prod"
}

variable "domain" {
  description = "Domain for the MCP server"
  type        = string
  default     = "mcp.cybersorted.io"
}
