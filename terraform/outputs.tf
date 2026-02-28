output "vm_public_ip" {
  description = "Public IP address of the MCP server VM"
  value       = azurerm_public_ip.mcp.ip_address
}

output "vm_fqdn" {
  description = "FQDN of the MCP server VM"
  value       = azurerm_public_ip.mcp.fqdn
}

output "ssh_command" {
  description = "SSH command to connect to the VM"
  value       = "ssh ${var.admin_username}@${azurerm_public_ip.mcp.ip_address}"
}

output "resource_group" {
  description = "Resource group name"
  value       = azurerm_resource_group.mcp.name
}

output "dns_record" {
  description = "Create this DNS A record to point your domain to the VM"
  value       = "${var.domain} -> ${azurerm_public_ip.mcp.ip_address}"
}

output "vm_identity_principal_id" {
  description = "System-assigned managed identity principal ID (use to tighten WIF binding)"
  value       = azurerm_linux_virtual_machine.mcp.identity[0].principal_id
}
