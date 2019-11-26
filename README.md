# Vault POC using Azure Key Vault

---

## Prerequisites

- Microsoft Azure account
- [Terraform installed](https://www.terraform.io/downloads.html) and ready to use
- *Optional - a [Self Signed SSL Cert](https://github.com/hashicorp/terraform-azurerm-vault/tree/master/modules/private-tls-cert) or a Vaild SSL Cert for the DNS name of your vault server and the localhost ip 127.0.0.1.

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

1. Add the [SSL Certs to the setup.tpl](https://github.com/stoffee/vault-autounseal-azurerm-poc/blob/master/setup.tpl#L59)

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
    $ ssh -i path/to/your/ssh/key azureuser@13.82.62.562
    ```

1. Find your Root Token and Recovery Key

    ```plaintext
    $ cat /opt/vault/setup/vault.unseal.info
    ```





## Clean up

Run `terraform destroy` when you are done exploring:

```plaintext
$ terraform destroy -auto-approve

$ rm -rf .terraform terraform.tfstate*
```
