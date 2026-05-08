# GoBless Examples

> ⚠️ **EXAMPLE ONLY — NOT FOR PRODUCTION**
>
> All values in this directory are **fake, placeholder, and safe to share publicly.**
> Do NOT copy any ARN, key, credential, or identifier from these files into a real environment.
> Replace every value with your own real configuration before deploying.

---

## What This Example Shows

This directory contains a complete, self-contained worked example of deploying and using GoBless — a Lambda-based SSH certificate authority backed by AWS KMS.

### What you'll find here

| Path | Description |
|------|-------------|
| `config/gobless.ini` | Example GoBless configuration file with all options documented |
| `lambda-events/` | Sample Lambda invocation payloads (user cert, host cert, invalid request) |
| `terraform/` | Example Terraform variable files and expected output |
| `verify/` | Scripts and reference output for inspecting issued certificates |
| `cleanup.md` | Teardown instructions for destroying resources safely |

---

## How to Use This Example

1. **Read the config** — `config/gobless.ini` shows every supported option with inline comments.
2. **Understand the event shape** — the JSON files in `lambda-events/` show what callers send to the Lambda function.
3. **Deploy with Terraform** — copy `terraform/terraform.tfvars.example` to `terraform.tfvars`, fill in real values, then run `terraform apply`.
4. **Verify issued certs** — use `verify/inspect-cert.sh` to inspect any certificate issued by GoBless.
5. **Clean up** — follow `cleanup.md` when you're done.

---

## Security Notes

- The RSA public key in `lambda-events/` is a **throwaway key generated for this example**. It has no associated private key in production and must never be trusted.
- The KMS key ARN (`arn:aws:kms:us-east-1:123456789012:key/example-key-id-replace-me`) is structurally valid but points to a nonexistent account/key.
- All AWS account IDs use `123456789012` — a well-known example account that AWS itself uses in documentation.
