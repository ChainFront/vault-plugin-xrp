#!/usr/bin/env bash
set -e

#
# Helper script for local development. Automatically builds and registers the
# plugin. Requires `vault` is installed and available on $PATH.
#

# Get the right dir
DIR="$(cd "$(dirname "$(readlink "$0")")" && pwd)"

echo "--> Scratch dir"
SCRATCH="$DIR/tmp"
mkdir -p "$SCRATCH/plugins"

echo "    Authenticating"
export VAULT_ADDR=http://localhost:8200
vault auth root &>/dev/null

echo "--> Creating policies"
vault write sys/policy/user rules=-<<EOF
path "secret/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF
vault write sys/policy/group rules=-<<EOF
path "secret/*" {
  capabilities = ["read"]
}
EOF
vault write sys/policy/usergroup rules=-<<EOF
path "*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}
EOF

echo "--> Building"
go build -o "$SCRATCH/plugins/vault-plugin-ripple"

echo "    Registering plugin"
SHASUM=$(shasum -a 256 "$SCRATCH/plugins/vault-plugin-ripple" | cut -d " " -f1)
vault write sys/plugins/catalog/ripple-plugin \
  sha_256="$SHASUM" \
  command="vault-plugin-ripple"

echo "    Reloading plugin"
vault write sys/plugins/reload/backend \
  plugin="ripple-plugin"

echo "==> Done!"
