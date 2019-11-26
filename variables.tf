# ---------------------------
# Azure Key Vault
# ---------------------------
variable "tenant_id" {
  default = ""
}

variable "key_name" {
  description = "Azure Key Vault key name"
  default     = "generated-key"
}

variable "location" {
  description = "Azure location where the Key Vault resource to be created"
  default     = "westus"
}

variable "environment" {
  default = "hashicorp-poc"
}

variable "tls_cert_file" {
  default = ""
}

variable "tls_key_file" {
  default = ""
}

# ---------------------------
# Virtual Machine
# ---------------------------
variable "public_key" {
  default = ""
}

variable "subscription_id" {
  default = ""
}

variable "client_id" {
  default = ""
}

variable "client_secret" {
  default = ""
}

variable "vm_name" {
  default = "vault-server"
}

variable "vault_download_url" {
  default = "https://releases.hashicorp.com/vault/1.3.0/vault_1.3.0_linux_amd64.zip"
}

variable "resource_group_name" {
  default = "hashicorp-vault-poc"
}
