# Public IP
resource "azurerm_public_ip" "mcp" {
  name                = "pip-mcp-${var.environment}"
  location            = azurerm_resource_group.mcp.location
  resource_group_name = azurerm_resource_group.mcp.name
  allocation_method   = "Static"
  sku                 = "Standard"
  zones               = ["1"]
  domain_name_label   = "cybersorted-mcp-${var.environment}"

  tags = azurerm_resource_group.mcp.tags
}

# Network Interface
resource "azurerm_network_interface" "mcp" {
  name                = "nic-mcp-${var.environment}"
  location            = azurerm_resource_group.mcp.location
  resource_group_name = azurerm_resource_group.mcp.name

  ip_configuration {
    name                          = "internal"
    subnet_id                     = azurerm_subnet.mcp.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.mcp.id
  }

  tags = azurerm_resource_group.mcp.tags
}

# Virtual Machine
resource "azurerm_linux_virtual_machine" "mcp" {
  name                = "vm-mcp-${var.environment}"
  location            = azurerm_resource_group.mcp.location
  resource_group_name = azurerm_resource_group.mcp.name
  size                = var.vm_size
  zone                = "1"

  admin_username                  = var.admin_username
  disable_password_authentication = true

  admin_ssh_key {
    username   = var.admin_username
    public_key = var.admin_ssh_public_key
  }

  network_interface_ids = [azurerm_network_interface.mcp.id]

  os_disk {
    name                 = "osdisk-mcp-${var.environment}"
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
    disk_size_gb         = 64
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "ubuntu-24_04-lts"
    sku       = "server"
    version   = "latest"
  }

  identity {
    type = "SystemAssigned"
  }

  custom_data = base64encode(file("${path.module}/../scripts/init-vm.sh"))

  tags = azurerm_resource_group.mcp.tags
}
