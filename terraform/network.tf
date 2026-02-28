# Virtual Network
resource "azurerm_virtual_network" "mcp" {
  name                = "vnet-mcp-${var.environment}"
  location            = azurerm_resource_group.mcp.location
  resource_group_name = azurerm_resource_group.mcp.name
  address_space       = ["10.0.0.0/16"]

  tags = azurerm_resource_group.mcp.tags
}

# Subnet
resource "azurerm_subnet" "mcp" {
  name                 = "snet-mcp-${var.environment}"
  resource_group_name  = azurerm_resource_group.mcp.name
  virtual_network_name = azurerm_virtual_network.mcp.name
  address_prefixes     = ["10.0.1.0/24"]
}

# Network Security Group
resource "azurerm_network_security_group" "mcp" {
  name                = "nsg-mcp-${var.environment}"
  location            = azurerm_resource_group.mcp.location
  resource_group_name = azurerm_resource_group.mcp.name

  # HTTPS — MCP protocol + API
  security_rule {
    name                       = "AllowHTTPS"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # HTTP — Let's Encrypt ACME challenge
  security_rule {
    name                       = "AllowHTTP"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  # SSH — restricted to admin IP
  security_rule {
    name                       = "AllowSSH"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.allowed_ssh_cidr
    destination_address_prefix = "*"
  }

  # Deny all other inbound
  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  tags = azurerm_resource_group.mcp.tags
}

# Associate NSG with subnet
resource "azurerm_subnet_network_security_group_association" "mcp" {
  subnet_id                 = azurerm_subnet.mcp.id
  network_security_group_id = azurerm_network_security_group.mcp.id
}
