# GoBless Runbooks

These runbooks are copy/paste-oriented starting points for operators. Adjust names, regions, table names, and paths to match your environment before running commands.

## Initial deployment

### Prerequisites

- Go 1.22 or newer.
- Terraform 1.5 or newer.
- AWS CLI v2 configured for the target account and region.
- AWS permissions to create Lambda, IAM, KMS, DynamoDB, and CloudWatch Logs resources.
- A KMS asymmetric signing key for the GoBless CA. The Terraform module creates this key from `kms_key_alias`; if your organization manages KMS keys separately, provide the approved key through Terraform variables or module changes.

### Package the Lambda

From the repository root:

```bash
GOOS=linux GOARCH=arm64 go build -tags production -o bootstrap ./cmd/gobless && zip gobless.zip bootstrap
mkdir -p build
mv gobless.zip build/gobless.zip
rm bootstrap
```

Expected: `build/gobless.zip` exists and contains a Lambda bootstrap binary. If your Terraform variable `lambda_zip_path` points somewhere else, move or build the zip at that path instead.

### Configure Terraform

Configure a remote backend before applying shared infrastructure. Either copy `deploy/terraform/backend.tf.example` to ignored `deploy/terraform/backend.tf` and edit it for your AWS account, or pass backend settings through your deployment workflow.

Create an ignored local `terraform.tfvars` file or pass these values through CI/CD secrets:

```bash
cd deploy/terraform
cat > terraform.tfvars <<'EOF'
aws_region          = "us-east-1"
function_name       = "gobless"
kms_key_alias       = "gobless-ca"
allowed_principals  = ["alice", "bob"]
lambda_zip_path     = "../../build/gobless.zip"
allowed_cert_types  = ["user"]
expected_account_id = "123456789012"
enforce_iam_binding = true
kms_admin_principal_arns = [
  "arn:aws:iam::123456789012:role/gobless-deploy",
]
tags = {
  Project = "gobless"
}
EOF
```

Do not commit `terraform.tfvars`, `backend.tf`, Terraform state, or Terraform plan files.

### Deploy

```bash
terraform init
terraform plan -out tfplan
terraform apply tfplan
```

Expected: Terraform reports resources created or changed. Stop if the plan deletes an existing production KMS key, DynamoDB audit table, or Lambda function unexpectedly.

Review the saved plan before applying. After apply, note the Lambda function name, KMS key ID, and DynamoDB audit table name from Terraform outputs or the AWS console. Delete `tfplan` after use if it contains environment-specific data.

### Verify Lambda invocation

Create a minimal request payload for your configured client/compatibility mode, then invoke the function. The exact JSON shape depends on the GoBless client mode in use; this example is a placeholder to verify Lambda reachability and error handling:

```bash
cat > /tmp/gobless-request.json <<'EOF'
{}
EOF

aws lambda invoke \
  --function-name gobless \
  --payload fileb:///tmp/gobless-request.json \
  /tmp/gobless-response.json

cat /tmp/gobless-response.json
```

Expected: the AWS CLI writes status metadata and `response.json` contains either a certificate response or a stable validation/policy error. Stop if the invoke fails with `AccessDeniedException`, `ResourceNotFoundException`, or an unhandled runtime error.

A policy or validation error still proves that IAM invocation and Lambda startup are working. A successful certificate response requires a valid signing request, a caller principal that policy allows, and a trusted client request shape.

## Rotating the CA

Rotation is not automatic for asymmetric KMS keys. Plan a distribution window because every SSH server that trusts GoBless must receive the new CA public key.

1. Create a new asymmetric KMS key for the CA, or update the Terraform `kms_key_alias` so the module creates the replacement key:

   ```bash
   cd deploy/terraform
   terraform plan -out tfplan -var 'kms_key_alias=gobless-ca-2026-q2'
   terraform apply tfplan
   ```

   Expected: Terraform creates or selects the replacement CA key and updates the Lambda configuration. Stop if the plan removes the old key before the deprecation window is complete.

2. Deploy GoBless with the new KMS key configured. Confirm the Lambda environment points at the new key:

   ```bash
   aws lambda get-function-configuration \
     --function-name gobless \
     --query 'Environment.Variables.GOBLESS_CA_KMS_KEY_ID'
   ```

3. Export or otherwise obtain the new CA public key through your approved GoBless public-key distribution path.

4. Add the new CA public key to `TrustedUserCAKeys` on every host while keeping the old CA public key present during the deprecation window:

   ```bash
   sudo install -m 0644 gobless_user_ca_keys /etc/ssh/gobless_user_ca_keys
   sudo sshd -t
   sudo systemctl restart sshd
   ```

5. Announce the deprecation window. Keep the old CA trusted until all certificates issued by the old key have expired and all hosts have received the new trust file.

6. After the window, remove the old CA public key from `TrustedUserCAKeys` on every host and restart `sshd` again:

   ```bash
   sudo sshd -t
   sudo systemctl restart sshd
   ```

7. Disable or schedule deletion of the old KMS key only after confirming that no hosts still trust or require it.

## Responding to a compromised CA key

Treat a compromised CA key as an emergency. SSH user certificates do not have a CRL mechanism that OpenSSH servers consult for GoBless-issued user certificates. Revocation is operational: remove trust for the compromised CA from every host.

### Immediate containment

1. Disable the compromised KMS key:

   ```bash
   aws kms disable-key --key-id COMPROMISED_KEY_ID
   ```

   This is intentionally disruptive: signing with the compromised key stops immediately. Expected: subsequent KMS signing attempts with that key fail.

2. Create or select a replacement asymmetric KMS key and redeploy GoBless with that key:

   ```bash
   cd deploy/terraform
   terraform plan -out tfplan -var 'kms_key_alias=gobless-ca-recovery'
   terraform apply tfplan
   ```

3. Replace `TrustedUserCAKeys` on every host so it contains only the new CA public key. Do not leave the compromised CA public key trusted:

   ```bash
   sudo install -m 0644 gobless_user_ca_keys /etc/ssh/gobless_user_ca_keys
   sudo sshd -t
   sudo systemctl restart sshd
   ```

4. Revoke all outstanding certificates issued under the compromised key by rotating `TrustedUserCAKeys` everywhere. There is no central CRL to update; every host must stop trusting the compromised CA public key.

5. Watch authentication logs for continued use of certificates signed by the old CA:

   ```bash
   sudo journalctl -u sshd --since '1 hour ago'
   ```

### Post-incident audit

Audit DynamoDB for all certificates issued under the compromised key and during the suspected compromise window. Use the fields available in your audit records, such as `Timestamp`, `KeyID`, `CertSerial`, `IAMCallerARN`, `Principals`, `Approved`, and `LambdaFnName`.

```bash
START_ISO="2026-05-06T00:00:00Z"  # replace with incident-window start
END_ISO="2026-05-07T00:00:00Z"    # replace with incident-window end

aws dynamodb scan \
  --table-name gobless-audit \
  --filter-expression '#ts BETWEEN :start AND :end' \
  --expression-attribute-names '{"#ts":"Timestamp"}' \
  --expression-attribute-values "{\":start\":{\"S\":\"${START_ISO}\"},\":end\":{\"S\":\"${END_ISO}\"}}"
```

If audit records include a signer key identifier in your deployed version, filter on that value as well. Preserve CloudTrail KMS `Sign` events and Lambda logs for the same window.

## Checking audit logs

The Terraform module creates a DynamoDB table named `gobless-audit` by default. The table uses `EventID` as the partition key, so `get-item` and `scan` are always available. Add secondary indexes before relying on high-volume operational queries.

### Fetch one audit event by EventID

```bash
aws dynamodb get-item \
  --table-name gobless-audit \
  --key '{"EventID":{"S":"11111111-2222-4333-8444-555555555555"}}'
```

### Scan recent approved or denied decisions

```bash
aws dynamodb scan \
  --table-name gobless-audit \
  --filter-expression '#approved = :approved' \
  --expression-attribute-names '{"#approved":"Approved"}' \
  --expression-attribute-values '{":approved":{"BOOL":true}}'
```

```bash
aws dynamodb scan \
  --table-name gobless-audit \
  --filter-expression '#event_type = :denied' \
  --expression-attribute-names '{"#event_type":"EventType"}' \
  --expression-attribute-values '{":denied":{"S":"signing_denied"}}'
```

### Query with an operator-created index

If you add a GSI such as `KeyIDIndex` with `KeyID` as the partition key, use `query` for direct certificate correlation:

```bash
aws dynamodb query \
  --table-name gobless-audit \
  --index-name KeyIDIndex \
  --key-condition-expression 'KeyID = :key_id' \
  --expression-attribute-values '{":key_id":{"S":"gobless-user-alice-1778080000-deadbeef"}}'
```

If you add a GSI such as `CallerIndex` with `IAMCallerARN` as the partition key, query by caller:

```bash
aws dynamodb query \
  --table-name gobless-audit \
  --index-name CallerIndex \
  --key-condition-expression 'IAMCallerARN = :caller' \
  --expression-attribute-values '{":caller":{"S":"arn:aws:iam::111122223333:user/alice"}}'
```

## Debugging a failed cert auth

Start from the client and then check server-side trust.

1. Run SSH with verbose logging:

   ```bash
   ssh -vvv -i ~/.ssh/id_ed25519 -o CertificateFile=~/.ssh/id_ed25519-cert.pub alice@host.example.com
   ```

2. Look for these client-side clues:

   - `Offering public key` followed by the certificate path.
   - Certificate type: user certificates must be offered for user login; host certificates are not accepted for user auth.
   - `Server accepts key` means SSH accepted the certificate and any later failure is likely account, shell, PAM, or command policy.
   - `Permission denied (publickey)` means the cert was not accepted or no acceptable key was offered.

3. Inspect the certificate locally:

   ```bash
   ssh-keygen -L -f ~/.ssh/id_ed25519-cert.pub
   ```

4. Common causes:

   - Principal mismatch: the certificate principals do not include the target Unix username, or `AuthorizedPrincipalsFile` / `AuthorizedPrincipalsCommand` does not allow that principal.
   - Expired certificate: `Valid: from ... to ...` is outside the current time on the client or server.
   - CA not trusted: the GoBless CA public key is missing from the server's `TrustedUserCAKeys` file.
   - Wrong cert type: a host certificate was issued where a user certificate is required, or the client is trying to use a plain public key without the matching `-cert.pub` file.
   - Source-address restriction: the certificate includes a source-address critical option that does not match the client's observed address.
   - Force-command or extension policy: the certificate was issued with critical options or extensions that conflict with the server's account policy.

5. Check server-side SSH logs:

   ```bash
   sudo journalctl -u sshd --since '15 minutes ago'
   ```

6. Confirm trust configuration and reload safely:

   ```bash
   sudo sshd -T | grep -i trustedusercakeys
   sudo sshd -t
   sudo systemctl restart sshd
   ```
