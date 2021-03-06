#!/bin/bash

export VAULT_ADDR=http://127.0.0.1:8200
export DEBIAN_FRONTEND=noninteractive
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_API_ADDR=http://127.0.0.1:8200
export VAULT_SKIP_VERIFY=true
apt update
apt install -y unzip jq openssl screen vim
apt -y autoremove
apt -y upgrade

VAULT_ZIP="vault.zip"
VAULT_URL="${vault_download_url}"
curl --silent --output /tmp/$${VAULT_ZIP} $${VAULT_URL}
unzip -o /tmp/$${VAULT_ZIP} -d /usr/local/bin/
chmod 0755 /usr/local/bin/vault
mkdir -pm 0755 /etc/vault.d
mkdir -pm 0755 /opt/vault/tls
mkdir -pm 0755 /opt/vault/setup
#create cert
openssl req -x509 -out /opt/vault/tls/vault.crt.pem -keyout /opt/vault/tls/vault.key.pem -newkey rsa:2048 -nodes -sha256 -subj '/CN=localhost' -extensions EXT -config <(printf "[dn]\nCN=localhost\n[req]\ndistinguished_name = dn\n[EXT]\nsubjectAltName=DNS:localhost\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth")
chmod 600 /opt/vault/tls/vault.crt.pem /opt/vault/tls/vault.key.pem
chown -R stoffee:stoffee /opt/vault
chown -R stoffee:stoffee /etc/vault.d
cp /opt/vault/tls/vault.crt.pem /usr/local/share/ca-certificates/vault.crt
update-ca-certificates

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
User=stoffee
Group=stoffee
[Install]
WantedBy=multi-user.target
EOF

cat << EOF > /etc/vault.d/config.hcl
storage "file" {
  path = "/opt/vault"
}
listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_disable = 1
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

sudo chmod 0664 /lib/systemd/system/vault.service
systemctl daemon-reload

systemctl enable vault
systemctl start vault
sleep 12
systemctl status vault

#VAULT_ADDR=http://localhost:8200 vault operator init > /opt/vault/setup/vault.unseal.info
VAULT_ADDR=http://127.0.0.1:8200 vault operator init -recovery-shares=1 -recovery-threshold=1 > /opt/vault/setup/vault.unseal.info
systemctl restart vault
sleep 6
cat << EOF > /etc/profile.d/vault.sh
export VAULT_ADDR=http://127.0.0.1:8200
export VAULT_API_ADDR=http://127.0.0.1:8200
export VAULT_SKIP_VERIFY=true
export ROOT_TOKEN=`cat /opt/vault/setup/vault.unseal.info |grep Root|awk '{print $4}'`
EOF

source /etc/profile.d/vault.sh
VAULT_ADDR=http://127.0.0.1:8200 vault status

#echo "Manually Unsealing vault..."
#VAULT_ADDR=https://localhost:8200 `egrep -m3 '^Unseal Key' /opt/vault/setup/vault.unseal.info | cut -f2- -d: | tr -d ' ' | while read key; do VAULT_ADDR=https://localhost:8200  vault operator unseal \$\{key\}; done`

cat << EOF > /opt/vault/setup/1_azure_auth.sh
#!/bin/sh -x
ROOT_TOKEN=`cat /opt/vault/setup/vault.unseal.info |grep Root|awk '{print $4}'`
VAULT_ADDR=http://127.0.0.1:8200 vault login $ROOT_TOKEN
VAULT_ADDR=http://127.0.0.1:8200 vault audit enable file file_path=/opt/vault/vault_audit.log
VAULT_ADDR=http://127.0.0.1:8200 vault auth enable azure
VAULT_ADDR=http://127.0.0.1:8200 vault write auth/azure/config tenant_id="${tenant_id}" \
resource="https://management.azure.com/" \
client_id="${client_id}" \
client_secret="${client_secret}"

VAULT_ADDR=http://127.0.0.1:8200 vault write auth/azure/role/dev-role policies="dev" \
bound_subscription_ids="${subscription_id}" \
bound_resource_groups="${resource_group_name}" \
ttl=24h \
max_ttl=48h

VAULT_ADDR=http://127.0.0.1:8200 vault write auth/azure/login role="dev-role" \
  jwt="$(curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-11-01&resource=https%3A%2F%2Fmanagement.azure.com%2F'  -H Metadata:true -s | jq -r .access_token)" \
  subscription_id="${subscription_id}" \
  resource_group_name="${resource_group_name}" \
  vm_name="${vm_name}" >> /opt/vault/setup/dev-role-token

VAULT_ADDR=http://127.0.0.1:8200 vault write -field=token auth/azure/login \
 role="dev-role" \
  jwt="$(curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-11-01&resource=https%3A%2F%2Fmanagement.azure.com%2F'  -H Metadata:true -s | jq -r .access_token)" \
 subscription_id="${subscription_id}" \
 resource_group_name="${resource_group_name}" \
 vm_name="${vm_name}" > /opt/vault/setup/VAULT_TOKEN

export VAULT_TOKEN=`cat /opt/vault/setup/VAULT_TOKEN |awk '{print $1}'`

echo $VAULT_TOKEN >> /opt/vault/setup/dev-role-token-ENV
#
# unset this for the rest
#
unset VAULT_TOKEN
EOF
chmod +x /opt/vault/setup/1_azure_auth.sh

##
# setup secrets role and pull some fake secret
##


cat << EOF > /opt/vault/setup/dev.hcl
path "secret/db-credentials" {
  capabilities = ["read", "list"]
}
EOF

cat << EOF > /opt/vault/setup/2_dev_secrets.sh
#!/bin/sh -x
ROOT_TOKEN=`cat /opt/vault/setup/vault.unseal.info |grep Root|awk '{print $4}'`
VAULT_ADDR=http://127.0.0.1:8200 vault login $ROOT_TOKEN
VAULT_ADDR=http://127.0.0.1:8200 vault policy write dev /opt/vault/setup/dev.hcl
VAULT_ADDR=http://127.0.0.1:8200 vault secrets enable -path=secret kv-v2
echo "adding db-credentials as root vault token" 
VAULT_ADDR=http://127.0.0.1:8200 vault kv put secret/db-credentials DB-Admin=SuperSecurePassword
echo "retrieving db-credentials as root vault token" 
VAULT_ADDR=http://127.0.0.1:8200 vault kv get secret/db-credentials
echo "Logging in as Azure User"
export VAULT_TOKEN=`cat /opt/vault/setup/VAULT_TOKEN |awk '{print $1}'`
VAULT_ADDR=http://127.0.0.1:8200 vault login $VAULT_TOKEN
echo "vault kv get secret/db-credentials"
VAULT_ADDR=http://127.0.0.1:8200 vault kv get secret/db-credentials
echo "vault kv get secret/linux-credentials"
VAULT_ADDR=http://127.0.0.1:8200 vault kv get secret/linux-credentials
echo "vault kv put secret/db-credentials DB-Admin=NoBuenoPassword"
VAULT_ADDR=http://127.0.0.1:8200 vault kv put secret/db-credentials foo=blah
unset VAULT_TOKEN
EOF
chmod +x /opt/vault/setup/2_dev_secrets.sh
##
# Enable the Azure secrets engine
##

ROOT_TOKEN=`cat /opt/vault/setup/vault.unseal.info |grep Root|awk '{print $4}'`
VAULT_ADDR=http://127.0.0.1:8200 vault login $ROOT_TOKEN
VAULT_ADDR=http://127.0.0.1:8200 vault secrets enable azure
VAULT_ADDR=http://127.0.0.1:8200 vault write azure/config \
subscription_id=${subscription_id} \
tenant_id=${tenant_id} \
client_id=${client_id} \
client_secret=${client_secret}

VAULT_ADDR=http://127.0.0.1:8200 vault write azure/roles/my-role ttl=1h azure_roles=-<<EOF
    [
        {
            "role_name": "Contributor",
            "scope":  "/subscriptions/<uuid>/resourceGroups/Website"
        }
    ]
EOF

VAULT_ADDR=http://127.0.0.1:8200 vault read azure/creds/my-role >> /opt/vault/setup/my-role-token

#enable transit engine
ROOT_TOKEN=`cat /opt/vault/setup/vault.unseal.info |grep Root|awk '{print $4}'`
VAULT_ADDR=http://127.0.0.1:8200 vault login $ROOT_TOKEN
VAULT_ADDR=http://127.0.0.1:8200 vault secrets enable transit
VAULT_ADDR=http://127.0.0.1:8200 vault secrets enable -path=encryption transit
VAULT_ADDR=http://127.0.0.1:8200 vault write -f transit/keys/orders
VAULT_ADDR=http://127.0.0.1:8200 vault write transit/encrypt/orders plaintext=$(base64 <<< "4111 1111 1111 1111") >> /opt/vault/setup/plaintext
PLAINTEXT=`sed -n 3p /opt/vault/setup/plaintext |awk '{print $2}'`
VAULT_ADDR=http://127.0.0.1:8200 vault write transit/decrypt/orders \
        ciphertext="$PLAINTEXT" >> /opt/vault/setup/ciphertext
CIPHERTEXT=`sed -n 3p /opt/vault/setup/ciphertext |awk '{print $2}'`
base64 --decode <<< "$CIPHERTEXT" >>  /opt/vault/setup/creditcard_number

cat << EOF > /tmp/azure_auth.sh
set -v
export VAULT_ADDR="http://127.0.0.1:8200"
VAULT_ADDR=http://127.0.0.1:8200 vault write auth/azure/login role="dev-role" \
  jwt="$(curl 'http://169.254.169.254/metadata/identity/oauth2/token?api-version=2019-11-01&resource=https%3A%2F%2Fmanagement.azure.com%2F'  -H Metadata:true -s | jq -r .access_token)" \
  subscription_id="${subscription_id}" \
  resource_group_name="${resource_group_name}" \
  vm_name="${vm_name}"
EOF

sudo cp /tmp/azure_auth.sh /opt/vault/setup/azure_auth.sh
sudo chmod +x /tmp/azure_auth.sh /opt/vault/setup/azure_auth.sh
