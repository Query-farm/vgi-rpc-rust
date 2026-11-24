#!/usr/bin/env bash
# Direct-S3 lane: runs vgi-rpc-s3's S3 tests against RustFS over plain http
# (path style) and TLS (private CA), each with static keys and with an STS
# AssumeRole session token (RustFS issues them; a bogus token is refused), plus the credential-rotation test.
#
# Usage: scripts/s3-lane.sh [workdir]
# Needs: docker (RustFS, pinned below; the image vgi-rpc-java and
# vgi-rpc-csharp already use), the aws CLI, openssl, python3, cargo.
set -euo pipefail
RUSTFS_IMAGE=${RUSTFS_IMAGE:-ghcr.io/rustfs/rustfs@sha256:29c02251c085cb04edce556304a9ec0f8fba0c40300266cf4f3d953783fe2450}
WORK=${1:-$(mktemp -d)}
ROOT_USER=vgilane
ROOT_PASS=vgilanesecret123
BUCKET=vgi-lane
rm -rf "$WORK/tls"
mkdir -p "$WORK/tls/certs"
cids=()
cleanup() { for c in "${cids[@]}"; do docker rm -fv "$c" >/dev/null 2>&1 || true; done; }
trap cleanup EXIT

certs=$WORK/tls/certs
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -keyout "$certs/ca.key" -out "$certs/ca.crt" -subj "/CN=vgi-lane-ca" 2>/dev/null
openssl req -newkey rsa:2048 -nodes -keyout "$certs/private.key" -out "$certs/srv.csr" -subj "/CN=127.0.0.1" 2>/dev/null
printf "subjectAltName=IP:127.0.0.1,DNS:localhost\nbasicConstraints=CA:FALSE\n" > "$certs/ext.cnf"
openssl x509 -req -in "$certs/srv.csr" -CA "$certs/ca.crt" -CAkey "$certs/ca.key" -CAcreateserial -days 2 -extfile "$certs/ext.cnf" -out "$certs/public.crt" 2>/dev/null
cp "$certs/public.crt" "$certs/rustfs_cert.pem"; cp "$certs/private.key" "$certs/rustfs_key.pem"; chmod 644 "$certs"/*

start() { # extra docker args...
  docker run -d -p 127.0.0.1::9000 -e RUSTFS_ACCESS_KEY=$ROOT_USER -e RUSTFS_SECRET_KEY=$ROOT_PASS \
    -e RUSTFS_CONSOLE_ENABLE=false -e RUSTFS_OBS_LOGGER_LEVEL=error "$@" "$RUSTFS_IMAGE"
}
HC=$(start); cids+=("$HC")
TC=$(start -v "$certs:/certs:ro" -e RUSTFS_TLS_PATH=/certs); cids+=("$TC")
HP=$(docker port "$HC" 9000/tcp | head -1 | sed 's/.*://')
TP=$(docker port "$TC" 9000/tcp | head -1 | sed 's/.*://')
for i in $(seq 1 120); do
  curl -sf "http://127.0.0.1:$HP/health" >/dev/null && curl -sf --cacert "$certs/ca.crt" "https://127.0.0.1:$TP/health" >/dev/null && break
  sleep 0.5
done

root_aws() { env -u AWS_PROFILE -u AWS_SESSION_TOKEN AWS_CONFIG_FILE=/dev/null AWS_ACCESS_KEY_ID=$ROOT_USER AWS_SECRET_ACCESS_KEY=$ROOT_PASS aws --region us-east-1 "$@"; }
root_aws --endpoint-url "http://127.0.0.1:$HP" s3 mb "s3://$BUCKET" >/dev/null
AWS_CA_BUNDLE=$certs/ca.crt root_aws --endpoint-url "https://127.0.0.1:$TP" s3 mb "s3://$BUCKET" >/dev/null

sts() { # endpoint -> "key secret token"
  AWS_CA_BUNDLE=$certs/ca.crt root_aws --endpoint-url "$1" sts assume-role --role-arn arn:aws:iam::000000000000:role/vgi-lane \
    --role-session-name vgi-lane --duration-seconds 3600 --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text
}

run() { # label endpoint key secret token
  echo "== $1"
  VGI_TEST_S3_ENDPOINT=$2 VGI_TEST_S3_BUCKET=$BUCKET VGI_TEST_S3_ACCESS_KEY_ID=$3 VGI_TEST_S3_SECRET_ACCESS_KEY=$4 \
  VGI_TEST_S3_SESSION_TOKEN=$5 SSL_CERT_FILE=$certs/ca.crt \
    cargo test -p vgi-rpc-s3 --features aws --locked --test s3_minio -- --test-threads=4 --nocapture 2>&1 | tee "$WORK/test.log"
  if grep -q "skipping:" "$WORK/test.log"; then echo "::error::storage tests skipped"; exit 1; fi
}

read -r K S T < <(sts "http://127.0.0.1:$HP")
run "http, path style, static keys" "http://127.0.0.1:$HP" $ROOT_USER $ROOT_PASS ""
run "http, path style, STS session token" "http://127.0.0.1:$HP" "$K" "$S" "$T"
read -r K S T < <(sts "https://127.0.0.1:$TP")
run "https (private CA), static keys" "https://127.0.0.1:$TP" $ROOT_USER $ROOT_PASS ""
run "https (private CA), STS session token" "https://127.0.0.1:$TP" "$K" "$S" "$T"

echo "== credential rotation (credential_process -> STS, refreshed every call)"
VGI_TEST_S3_ENDPOINT="http://127.0.0.1:$HP" VGI_TEST_S3_BUCKET=$BUCKET \
VGI_TEST_S3_ROOT_ACCESS_KEY=$ROOT_USER VGI_TEST_S3_ROOT_SECRET_KEY=$ROOT_PASS \
VGI_TEST_S3_CREDENTIAL_PROCESS="$(cd "$(dirname "$0")" && pwd)/s3-credential-process.sh" \
VGI_TEST_S3_CREDENTIAL_LOG="$WORK/credential.log" \
  cargo test -p vgi-rpc-s3 --features aws --locked --test s3_minio_rotation -- --nocapture 2>&1 | tee "$WORK/test.log"
if grep -q "skipping:" "$WORK/test.log"; then echo "::error::storage tests skipped"; exit 1; fi
echo "credential_process calls: $(wc -l < "$WORK/credential.log")"
echo "S3 LANE OK"
