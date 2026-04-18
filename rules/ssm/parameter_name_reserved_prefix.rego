# Intent derived from https://github.com/cds-snc/opa_checks (MIT).
# Clean-room implementation — no upstream Rego copied.

package vulnetix.rules.cds_aws_tf_ssm_parameter_name_reserved_prefix

import rego.v1

import data.vulnetix.cds_aws_tf.tf

metadata := {
	"id": "CDS-AWS-TF-SSM-001",
	"name": "SSM parameter name must not start with a reserved prefix",
	"description": "AWS reserves the `aws` and `ssm` prefixes (case-insensitive, with or without a leading `/`) in Systems Manager Parameter Store. Creation succeeds in some edge cases but cross-region replication and KMS lookups misbehave; stick to an application-specific prefix instead.",
	"help_uri": "https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-su-create.html",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "ssm", "terraform"],
}

findings contains finding if {
	some block in tf.resource_blocks("aws_ssm_parameter")
	name := tf.attr_string(block, "name")
	_starts_with_reserved(name)
	line := tf.attr_line(block, "name")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("SSM parameter name %q starts with a reserved prefix (aws/ssm)", [name]),
		"artifact_uri": block.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": tf.snippet(block, line),
	}
}

_starts_with_reserved(name) if {
	trimmed := trim_prefix(name, "/")
	lower_trimmed := lower(trimmed)
	some prefix in {"aws", "ssm"}
	startswith(lower_trimmed, prefix)
}
