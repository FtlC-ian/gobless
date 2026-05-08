# GoBless Cleanup Guide

> ⚠️ **Read carefully before running any destroy commands.**
> These steps are **irreversible**. Destroying the KMS CA key means all previously issued certificates become unverifiable — your SSH servers will no longer accept them.

---

## 1. Revoke or Expire Outstanding Certificates

GoBless issues short-lived certificates (default 1 hour for users, 24 hours for hosts). In most cases, waiting for them to expire is sufficient and safest.

If you need to invalidate certs immediately:

- **Remove the CA public key** from all SSH servers' `TrustedUserCAKeys` / `HostCertificate` config, then reload sshd:
  ```bash
  sudo systemctl reload sshd
  ```
  Once the CA is no longer trusted, all previously issued certs are rejected regardless of validity window.

---

## 2. Destroy Terraform Resources

```bash
cd your-terraform-directory/
terraform destroy
```

Review the plan carefully before confirming. This will destroy:
- The Lambda function
- The KMS CA key (scheduled for deletion per `kms_deletion_window_days`)
- The DynamoDB audit table
- IAM roles and policies

> **Note:** KMS keys are not immediately deleted. AWS schedules deletion with a minimum 7-day waiting period. During this window, the key is disabled but recoverable. After the window expires, it is permanently gone.

To cancel a pending KMS key deletion (if you change your mind):
```bash
aws kms cancel-key-deletion --key-id <key-id>
aws kms enable-key --key-id <key-id>
```

---

## 3. Audit That No Certs Remain Valid

After teardown, confirm no active certs remain:

1. **Check your DynamoDB audit table** (before destroying it) for any certs with `ValidBefore` in the future:
   ```bash
   aws dynamodb scan \
     --table-name gobless-audit-example \
     --filter-expression "ValidBefore > :now" \
     --expression-attribute-values '{":now": {"N": "$(date +%s)"}}'
   ```

2. **Check SSH servers** — inspect `sshd_config` to confirm `TrustedUserCAKeys` no longer references the GoBless CA:
   ```bash
   grep -r TrustedUserCAKeys /etc/ssh/
   ```

3. **Verify the CA key is gone** (or pending deletion):
   ```bash
   aws kms describe-key --key-id <your-kms-key-id>
   # KeyState should be "PendingDeletion" or "Deleted"
   ```

---

## 4. Clean Up S3 Deployment Artifacts

If you uploaded a `gobless.zip` to S3 for the Lambda deploy:
```bash
aws s3 rm s3://my-example-deploy-bucket-replace-me/gobless/gobless.zip
```

---

## 5. Final Check

- [ ] KMS CA key is pending deletion or deleted
- [ ] Lambda function is destroyed
- [ ] DynamoDB audit table is destroyed (or archived/exported if needed for compliance)
- [ ] `TrustedUserCAKeys` removed from all SSH server configs
- [ ] sshd reloaded on all servers
- [ ] S3 artifacts removed
