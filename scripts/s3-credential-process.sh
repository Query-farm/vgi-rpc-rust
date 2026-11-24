#!/bin/sh
# AWS credential_process for the S3 rotation test: mints STS AssumeRole (RustFS)
# credentials (valid 15 minutes) but reports them as expiring in ~5 minutes,
# so the worker refreshes on every call. Appends the key id to
# $VGI_TEST_S3_CREDENTIAL_LOG.
set -eu
creds=$(env -u AWS_PROFILE -u AWS_SESSION_TOKEN AWS_CONFIG_FILE=/dev/null AWS_SHARED_CREDENTIALS_FILE=/dev/null \
  AWS_ACCESS_KEY_ID="$VGI_TEST_S3_ROOT_ACCESS_KEY" AWS_SECRET_ACCESS_KEY="$VGI_TEST_S3_ROOT_SECRET_KEY" \
  aws --region us-east-1 --endpoint-url "$VGI_TEST_S3_ENDPOINT" sts assume-role \
  --role-arn arn:aws:iam::000000000000:role/vgi-rotation --role-session-name vgi-rotation \
  --duration-seconds 900 --output json)
printf '%s' "$creds" | python3 -c '
import json, sys, datetime, os
c = json.load(sys.stdin)["Credentials"]
exp = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(seconds=301)
with open(os.environ["VGI_TEST_S3_CREDENTIAL_LOG"], "a") as log:
    log.write(c["AccessKeyId"] + "\n")
print(json.dumps({"Version": 1, "AccessKeyId": c["AccessKeyId"], "SecretAccessKey": c["SecretAccessKey"],
                  "SessionToken": c["SessionToken"], "Expiration": exp.strftime("%Y-%m-%dT%H:%M:%SZ")}))
'
