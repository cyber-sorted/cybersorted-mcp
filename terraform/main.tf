terraform {
  required_version = ">= 1.5"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.0"
    }
  }

  backend "azurerm" {
    resource_group_name  = "cybersorted-tfstate"
    storage_account_name = "csmcptfstate"
    container_name       = "tfstate"
    key                  = "mcp-server.tfstate"
  }
}

provider "azurerm" {
  features {}
  subscription_id = var.subscription_id
}

resource "azurerm_resource_group" "mcp" {
  name     = "cybersorted-mcp-${var.environment}"
  location = var.region

  tags = {
    project     = "cybersorted-mcp"
    environment = var.environment
    managed_by  = "terraform"
  }
}
