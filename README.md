# Vault POC - Auto-unseal using Azure Key Vault

These assets are provided to perform the tasks described in the [Auto-unseal with Azure Key Vault](https://learn.hashicorp.com/vault/operations/autounseal-azure-keyvault) guide.

In addition, a script is provided so that you can enable and test `azure` auth method. (_Optional_)

---

## Prerequisites

- Microsoft Azure account
- [Terraform installed](https://www.terraform.io/downloads.html) and ready to use

<br>

**Terraform Azure Provider Prerequisites**

A ***service principal*** is an application within Azure Active Directory which
can be used to authenticate. Service principals are preferable to running an app
using your own credentials. Follow the instruction in the [Terraform
documentation](https://www.terraform.io/docs/providers/azurerm/auth/service_principal_client_certificate.html)
to create a service principal and then configure in Terraform.

Tips:

- **Subscription ID**: Navigate to the [Subscriptions blade within the Azure
 Portal](https://portal.azure.com/#blade/Microsoft_Azure_Billing/SubscriptionsBlade)
 and copy the **Subscription ID**  

- **Tenant ID**: Navigate to the [Azure Active Directory >
 Properties](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Properties)
 in the Azure Portal, and copy the **Directory ID** which is your tenant ID  

- **Client ID**: Same as the [**Application
 ID**](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ApplicationsListBlade)

- **Client secret**: The [password
 (credential)](https://portal.azure.com/#blade/Microsoft_AAD_IAM/ApplicationsListBlade)
 set on your application

> **IMPORTANT:** Ensure that your Service Principal has appropriate permissions to provision virtual machines, networks, as well as **Azure Key Vault**. Refer to the [Azure documentation](https://docs.microsoft.com/en-us/azure/role-based-access-control/role-assignments-portal).

## Deployment Steps

1. Set this location as your working directory

1. Provide Azure credentials in the `terraform.tfvars.example` and save it as `terraform.tfvars`

    > NOTE: Overwrite the Azure `location` or `environment` name in the `terraform.tfvars` as desired.

1. Run the Terraform commands:

    ```shell
    # Pull necessary plugins
    $ terraform init

    $ terraform plan

    # Output provides the SSH instruction
    $ terraform apply -auto-approve
    ...
    Outputs:

    ip = 13.82.62.56
    key_vault_name = Test-vault-1e5a88de
    ssh-addr =
        Connect to your virtual machine via SSH:

        $ ssh azureuser@13.82.62.562
    ```

1. SSH into the virtual machine:

    ```plaintext
    $ ssh azureuser@13.82.62.562
    ```

1. Check the current Vault status:

    ```text
    $ vault status
    Key                      Value
    ---                      -----
    Recovery Seal Type       azurekeyvault
    Initialized              false
    Sealed                   true
    Total Recovery Shares    0
    Threshold                0
    Unseal Progress          0/0
    Unseal Nonce             n/a
    Version                  n/a
    HA Enabled               false
    ```
    Vault hasn't been initialized, yet.

1. Explorer the Vault configuration file

    ```plaintext
    $ cat /etc/vault.d/config.hcl

    storage "file" {
      path = "/opt/vault"
    }
    listener "tcp" {
      address     = "0.0.0.0:8200"
      tls_disable = 1
    }
    seal "azurekeyvault" {
      client_id      = "YOUR-AZURE-APP-ID"
      client_secret  = "YOUR-AZURE-APP-PASSWORD"
      tenant_id      = "YOUR-AZURE-TENANT-ID"
      vault_name     = "Test-vault-xxxx"
      key_name       = "generated-key"
    }
    ui=true
    disable_mlock = true
    ```

## Clean up

Run `terraform destroy` when you are done exploring:

```plaintext
$ terraform destroy -auto-approve

$ rm -rf .terraform terraform.tfstate*
```
