# opa-cds-aws-tf

Vulnetix-compatible OPA/Rego rules for AWS Terraform source files, adapted from the intent of the [CDS-SNC `opa_checks`](https://github.com/cds-snc/opa_checks) ruleset.

Load from the Vulnetix CLI:

```bash
vulnetix scan --rule Vulnetix/opa-cds-aws-tf
```

## Clean-room approach

These rules were produced using a **clean-room** methodology:

1. The **intent** of each upstream CDS-SNC rule was studied — what misconfiguration it flags, why it matters at deploy time or at runtime, and what it expects the remediated Terraform to look like.
2. Detection logic was then **written from scratch** against the Vulnetix CLI's `input.file_contents` schema.
3. **No upstream Rego code was copied.** The CDS-SNC rules operate on `terraform show -json` plan output — a completely different input shape — so they cannot be used verbatim with Vulnetix in any case. The helper library (`rules/_lib/tf.rego`) and the PostgreSQL reserved-word list (`rules/_lib/pg_reserved.rego`) are original implementations: the library parses raw HCL with regex under `terraform fmt` conventions; the reserved-word list is compiled from the public PostgreSQL 16 Appendix C documentation (facts, not copyrightable).
4. The upstream is MIT-licensed; this repository is **Apache-2.0** (see `LICENSE`). Because nothing is derived from the upstream source, the licenses do not interact.

The result is a set of rules that match the **security and correctness intent** of the upstream checks while being natively compatible with the Vulnetix CLI `--rule` mechanism and with raw `.tf` source files — no Terraform plan generation required.

## Coverage

All rules target Terraform source files (`*.tf`) and AWS resource blocks. Rule IDs use the `CDS-AWS-TF-*` prefix.

| Category | Rule | ID | Severity |
|----------|------|-----|----------|
| API Gateway | Integration URI must match integration type | `CDS-AWS-TF-APIGW-001` | medium |
| CloudFront | Custom error response path must start with `/` | `CDS-AWS-TF-CF-001` | low |
| CloudWatch | Log metric filter pattern must be valid | `CDS-AWS-TF-CW-001` | low |
| ECS | Container definition name must not contain whitespace | `CDS-AWS-TF-ECS-001` | low |
| ECS | Container definitions JSON must not have trailing commas | `CDS-AWS-TF-ECS-002` | low |
| IAM | Policy statement effect must be `Allow` or `Deny` | `CDS-AWS-TF-IAM-001` | high |
| IAM | Service-principal grant must scope `AWS:SourceAccount` | `CDS-AWS-TF-IAM-002` | high |
| Lambda | Runtime must be currently supported by AWS | `CDS-AWS-TF-LAMBDA-001` | medium |
| Lambda | VPC-attached function must attach `AWSLambdaVPCAccessExecutionRole` | `CDS-AWS-TF-LAMBDA-002` | medium |
| RDS | Master password must satisfy AWS + PostgreSQL constraints | `CDS-AWS-TF-RDS-001` | high |
| RDS | Master username must satisfy PostgreSQL identifier rules | `CDS-AWS-TF-RDS-002` | medium |
| RDS | Database name must not be a PostgreSQL reserved keyword | `CDS-AWS-TF-RDS-003` | medium |
| Security Group | Rule with `protocol = "-1"` must set `from_port`/`to_port` to 0 | `CDS-AWS-TF-SG-001` | medium |
| SSM | Parameter name must not start with `aws`/`ssm` | `CDS-AWS-TF-SSM-001` | medium |
| Tagging | `tags` blocks must include `CostCentre` and `Terraform` keys | `CDS-AWS-TF-TAG-001` | low |
| WAF | `aws_wafv2_web_acl` rules must have unique priorities | `CDS-AWS-TF-WAF-001` | low |

**Total: 16 rules.**

## Layout

```
opa-cds-aws-tf/
├── LICENSE                                   ← Apache 2.0
├── README.md
└── rules/
    ├── _lib/
    │   ├── tf.rego                           # package vulnetix.cds_aws_tf.tf
    │   └── pg_reserved.rego                  # package vulnetix.cds_aws_tf.pg_reserved
    ├── api_gateway/integration_uri.rego
    ├── cloudfront/error_response_path.rego
    ├── cloudwatch/metric_filter_pattern.rego
    ├── ecs/container_name_whitespace.rego
    ├── ecs/container_definition_trailing_comma.rego
    ├── iam/invalid_effect.rego
    ├── iam/unscoped_service_principal.rego
    ├── lambda/unsupported_runtime.rego
    ├── lambda/vpc_missing_eni_policy.rego
    ├── rds/master_password.rego
    ├── rds/master_username.rego
    ├── rds/database_name.rego
    ├── security_group/invalid_ports.rego
    ├── ssm/parameter_name_reserved_prefix.rego
    ├── tagging/required_tags.rego
    └── waf/duplicate_priority.rego
```

The Vulnetix CLI walks every `.rego` file under `rules/` recursively, so the per-service sub-directories are loaded automatically.

## Usage

Load alongside the built-in Vulnetix ruleset:

```bash
vulnetix scan --rule Vulnetix/opa-cds-aws-tf
```

Use only these rules (skip the built-ins):

```bash
vulnetix scan --disable-default-rules --rule Vulnetix/opa-cds-aws-tf
```

Gate CI by severity:

```bash
vulnetix scan --rule Vulnetix/opa-cds-aws-tf --severity high
```

Pair with the other clean-room opa-* rule sets in the Vulnetix org:

```bash
vulnetix scan \
  --rule Vulnetix/opa-cds-aws-tf \
  --rule Vulnetix/opa-aquasecurity-trivy \
  --rule Vulnetix/opa-snyk-labs-iac \
  --severity high
```

## Design notes

### HCL parsing

Vulnetix delivers file contents as raw text, not parsed AST. `rules/_lib/tf.rego` provides regex-based helpers that:

- Discover `resource "TYPE" "NAME"` / `data "TYPE" "NAME"` blocks and nested sub-blocks using `terraform fmt` conventions (top-level `}` at column 0; nested `}` at matching indentation).
- Extract string, numeric, and reference attribute values (`attr_string`, `attr_raw`).
- Return accurate 1-based line numbers for findings so that editors, SARIF consumers, and the Vulnetix UI can point to the offending line.

The helpers do not attempt full HCL parsing — unusual formatting (e.g. `}` not at column 0) may produce false negatives. In exchange, there is zero dependency on an HCL parser or a Terraform plan. Run `terraform fmt` before scanning for the most accurate results.

### Local customisation

The `tagging/required_tags.rego` rule enforces two governance keys (`CostCentre`, `Terraform`) that reflect the CDS-SNC convention. Replace these in the `_required` set to match your organisation's tagging policy.

The `lambda/unsupported_runtime.rego` `_supported` set is a snapshot of AWS-supported runtimes as of April 2026. Runtime EOLs happen quarterly; update this list when AWS retires or adds runtimes.

### Testing rules locally

```bash
# Parse/compile the whole rule set
opa check rules/

# Evaluate a single rule against a test fixture
echo '{"file_contents": {"main.tf": "..."}}' | \
  opa eval -I -d rules/ 'data.vulnetix.rules.cds_aws_tf_iam_invalid_effect.findings'
```

## Not included

The upstream repository has evolved alongside CDS-SNC's internal Terraform modules. The following upstream rules were considered but not ported because they are too organisation-specific to be useful in a general-purpose rule set:

- Module-path assertions (e.g. "all S3 buckets must use the `cds-snc/s3-bucket` module") — these encode a specific module catalogue rather than a portable security intent.
- CDS-SNC-internal naming prefixes for resources.

If you want those checks for your organisation, fork this repository and extend the rule set.

## Attribution

- Upstream intent reference: [cds-snc/opa_checks](https://github.com/cds-snc/opa_checks) (MIT).
- PostgreSQL reserved-keyword list: [PostgreSQL 16 Appendix C](https://www.postgresql.org/docs/16/sql-keywords-appendix.html) (facts).
- Implementation: original clean-room work, Apache-2.0.
