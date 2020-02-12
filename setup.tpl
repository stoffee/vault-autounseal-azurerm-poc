#!/bin/bash

# sudo apt-get install -y unzip jq
sudo apt update && sudo apt install -y unzip jq

VAULT_ZIP="vault.zip"
VAULT_URL="${vault_download_url}"
curl --silent --output /tmp/$${VAULT_ZIP} $${VAULT_URL}
unzip -o /tmp/$${VAULT_ZIP} -d /usr/local/bin/
chmod 0755 /usr/local/bin/vault
mkdir -pm 0755 /etc/vault.d
mkdir -pm 0755 /opt/vault/tls
mkdir -pm 0755 /opt/vault/setup
chown -R azureuser:azureuser /opt/vault
chown -R azureuser:azureuser /etc/vault.d

export VAULT_ADDR=https://127.0.0.1:8200

cat << EOF > /lib/systemd/system/vault.service
[Unit]
Description=Vault Agent
Requires=network-online.target
After=network-online.target
[Service]
Restart=on-failure
PermissionsStartOnly=true
ExecStartPre=/sbin/setcap 'cap_ipc_lock=+ep' /usr/local/bin/vault
ExecStart=/usr/local/bin/vault server -config /etc/vault.d/config.hcl
ExecReload=/bin/kill -HUP $MAINPID
KillSignal=SIGTERM
User=azureuser
Group=azureuser
[Install]
WantedBy=multi-user.target
EOF


cat << EOF > /etc/vault.d/config.hcl
storage "file" {
  path = "/opt/vault"
}
listener "tcp" {
  address     = "0.0.0.0:8200"
  #tls_disable = 1
  tls_cert_file   = "${tls_cert_file}"
  tls_key_file    = "${tls_key_file}"
}
seal "azurekeyvault" {
  client_id      = "${client_id}"
  client_secret  = "${client_secret}"
  tenant_id      = "${tenant_id}"
  vault_name     = "${vault_name}"
  key_name       = "${key_name}"
}
ui=true
disable_mlock = true
EOF

cat << EOF > /opt/vault/tls/vault.crt.pem
-----BEGIN CERTIFICATE-----
ENTER.YOUR.SSL.CRT
-----END CERTIFICATE-----
EOF

cat << EOF > /opt/vault/tls/vault.key.pem
-----BEGIN RSA PRIVATE KEY-----
ENTER.YOUR.SSL.KEY
-----END RSA PRIVATE KEY-----
EOF

sudo chmod 0664 /lib/systemd/system/vault.service
systemctl daemon-reload

cat << EOF > /etc/profile.d/vault.sh
export VAULT_ADDR=https://127.0.0.1:8200
export VAULT_SKIP_VERIFY=true
EOF

source /etc/profile.d/vault.sh

systemctl enable vault
systemctl start vault
systemctl status vault > /opt/vault/setup/bootstrap_config.log
sleep 12

vault operator init -recovery-shares=1 -recovery-threshold=1 > /opt/vault/setup/vault.unseal.info
systemctl restart vault
vault status >> /opt/vault/setup/bootstrap_config.log
sleep 12

echo "Unsealing..."
`egrep -m3 '^Unseal Key' /opt/vault/setup/vault.unseal.info | cut -f2- -d: | tr -d ' ' | while read key; do   vault operator unseal \$\{key\}; done`

ROOT_TOKEN=`cat /opt/vault/setup/vault.unseal.info |grep Root|awk '{print $4}'`
vault login $ROOT_TOKEN

vault auth enable azure >> /opt/vault/setup/bootstrap_config.log

vault write auth/azure/config tenant_id="${tenant_id}" \
resource="https://management.azure.com/" \
client_id="${client_id}" \
client_secret="${client_secret}" >> /opt/vault/setup/bootstrap_config.log

vault write auth/azure/role/dev-role policies="dev" \
bound_subscription_ids="${subscription_id}" \
bound_resource_groups="${resource_group_name}" \
ttl=24h \
max_ttl=48h >> /opt/vault/setup/bootstrap_config.log

vault write auth/azure/login role="dev-role" \
  jwt="$(curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F'  -H Metadata:true -s | jq -r .access_token)" \
  subscription_id="${subscription_id}" \
  resource_group_name="${resource_group_name}" \
  vm_name="${vm_name}" >> /opt/vault/setup/dev-role-token


export VAULT_TOKEN=$(vault write -field=token auth/azure/login \
 role="dev-role" \
  jwt="$(curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F'  -H Metadata:true -s | jq -r .access_token)" \
 subscription_id="${subscription_id}" \
 resource_group_name="${resource_group_name}" \
 vm_name="${vm_name}")

echo $VAULT_TOKEN >> /opt/vault/setup/dev-role-token-ENV

##
# setup secrets role and pull some fake secret
##

cat << EOF > /opt/vault/setup/dev.hcl
path "secret/db-credentials" {
  capabilities = ["read", "list"]
}
EOF

vault policy write dev /opt/vault/setup/dev.hcl >> /opt/vault/setup/bootstrap_config.log

echo "adding db-credentials as root vault token" >> /opt/vault/setup/bootstrap_config.log 
vault kv put secret/db-credentials DB-Admin=SuperSecurePassword >> /opt/vault/setup/bootstrap_config.log

echo "retrieving db-credentials as root vault token" >> /opt/vault/setup/bootstrap_config.log 
vault kv get secret/db-credentials >> /opt/vault/setup/bootstrap_config.log

echo "Logging in as Azure User" >> /opt/vault/setup/bootstrap_config.log
vault login $VAULT_TOKEN >> /opt/vault/setup/bootstrap_config.log
echo "vault kv get secret/db-credentials" >> /opt/vault/setup/bootstrap_config.log
vault kv get secret/db-credentials >> /opt/vault/setup/bootstrap_config.log
echo "vault kv get secret/linux-credentials" >> /opt/vault/setup/bootstrap_config.log
vault kv get secret/linux-credentials >> /opt/vault/setup/bootstrap_config.log
echo "vault kv put secret/db-credentials DB-Admin=NoBuenoPassword" >> /opt/vault/setup/bootstrap_config.log
vault kv put secret/db-credentials foo=blah >> /opt/vault/setup/bootstrap_config.log

##
# Enable the Azure secrets engine
##

vault login $ROOT_TOKEN  >> /opt/vault/setup/bootstrap_config.log
vault secrets enable azure  >> /opt/vault/setup/bootstrap_config.log
vault write azure/config \
subscription_id=${subscription_id} \
tenant_id=${tenant_id} \
client_id=${client_id} \
client_secret=${client_secret} >> /opt/vault/setup/bootstrap_config.log

vault write azure/roles/my-role ttl=1h azure_roles=-<<EOF
    [
        {
            "role_name": "Contributor",
            "scope":  "/subscriptions/<uuid>/resourceGroups/Website"
        }
    ]
EOF  >> /opt/vault/setup/bootstrap_config.log

vault read azure/creds/my-role >> /opt/vault/setup/my-role-token

#enable transit engine
vault secrets enable transit >>/opt/vault/setup/bootstrap_config.log
vault secrets enable -path=encryption transit >>/opt/vault/setup/bootstrap_config.log
vault write -f transit/keys/orders >>/opt/vault/setup/bootstrap_config.log
vault write transit/encrypt/orders plaintext=$(base64 <<< "4111 1111 1111 1111") >> /opt/vault/setup/plaintext
PLAINTEXT=`sed -n 3p /opt/vault/setup/plaintext |awk '{print $2}'`
vault write transit/decrypt/orders \
        ciphertext="$PLAINTEXT" >> /opt/vault/setup/ciphertext
CIPHERTEXT=`sed -n 3p /opt/vault/setup/ciphertext |awk '{print $2}'`
base64 --decode <<< "$CIPHERTEXT" >>  /opt/vault/setup/creditcard_number

cat << EOF > /tmp/azure_auth.sh
set -v
export VAULT_ADDR="http://127.0.0.1:8200"
vault write auth/azure/login role="dev-role" \
  jwt="$(curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F'  -H Metadata:true -s | jq -r .access_token)" \
  subscription_id="${subscription_id}" \
  resource_group_name="${resource_group_name}" \
  vm_name="${vm_name}"
EOF

sudo chmod +x /tmp/azure_auth.sh
