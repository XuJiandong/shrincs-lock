#!/usr/bin/env bash
set -euo pipefail

FROM_ADDRESS="ckt1qzda0cr08m85hc8jlnfp3zer7xulejywt49kt2rr0vthywaa50xwsqvuyep8kue7r8mhfe6rzguzj3kmj4yqjwsg8lepn"
CKB_RPC="https://testnet.ckb.dev"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
BINARY="$PROJECT_ROOT/build/release/shrincs-lock"
DEPLOY_CONFIG="$SCRIPT_DIR/deployment.toml"
MIGRATIONS_DIR="$SCRIPT_DIR/migrations"
INFO_FILE="$SCRIPT_DIR/info.json"

if [ ! -f "$BINARY" ]; then
  echo "Error: binary not found at $BINARY" >&2
  exit 1
fi

mkdir -p "$MIGRATIONS_DIR"

cat > "$DEPLOY_CONFIG" <<TOML
[[cells]]
name = "shrincs-lock"
enable_type_id = true
location = { file = "$BINARY" }

[lock]
code_hash = "0x9bd7e06f3ecf4be0f2fcd2188b23f1b9fcc88e5d4b65a8637b17723bbda3cce8"
args = "0xe25a18008e48e10eed71491162932383dddd1fb7"
hash_type = "type"
TOML

echo "==> Generating and signing transactions (you will be prompted for your password)..."
ckb-cli --url "$CKB_RPC" deploy gen-txs \
  --deployment-config "$DEPLOY_CONFIG" \
  --migration-dir "$MIGRATIONS_DIR" \
  --from-address "$FROM_ADDRESS" \
  --sign-now \
  --info-file "$INFO_FILE"

echo "==> Applying transactions..."
ckb-cli --url "$CKB_RPC" deploy apply-txs \
  --migration-dir "$MIGRATIONS_DIR" \
  --info-file "$INFO_FILE"

echo "==> Done. Migration files written to $MIGRATIONS_DIR"

