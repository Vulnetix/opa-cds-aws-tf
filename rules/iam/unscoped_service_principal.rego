# Intent derived from https://github.com/cds-snc/opa_checks (MIT).
# Clean-room implementation — no upstream Rego copied.

package vulnetix.rules.cds_aws_tf_iam_unscoped_service_principal

import rego.v1

import data.vulnetix.cds_aws_tf.tf

metadata := {
	"id": "CDS-AWS-TF-IAM-002",
	"name": "IAM statement granting a service principal must scope AWS:SourceAccount",
	"description": "When an IAM policy document grants a `Principal.Service` (other than `sts:AssumeRole`) without a `StringEquals` / `StringLike` condition on `AWS:SourceAccount`, the resource is vulnerable to the AWS confused-deputy pattern — any other AWS account whose service calls into yours can trigger the action. Scope the grant to your own account explicitly.",
	"help_uri": "https://docs.aws.amazon.com/IAM/latest/UserGuide/confused-deputy.html",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [441],
	"capec": [],
	"attack_technique": ["T1078.004"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "iam", "terraform", "confused-deputy"],
}

findings contains finding if {
	some block in tf.data_blocks("aws_iam_policy_document")
	some stmt in tf.sub_blocks(block, "statement")
	_has_service_principal(stmt)
	not _has_source_account_condition(stmt)
	not _is_only_assume_role(stmt)
	finding := {
		"rule_id": metadata.id,
		"message": "IAM statement grants a service principal without an AWS:SourceAccount condition",
		"artifact_uri": block.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": stmt.header_line,
		"snippet": stmt.header_text,
	}
}

_has_service_principal(stmt) if {
	some principals in tf.sub_blocks(stmt, "principals")
	t := tf.attr_string(principals, "type")
	t == "Service"
}

_has_source_account_condition(stmt) if {
	some cond in tf.sub_blocks(stmt, "condition")
	variable := tf.attr_string(cond, "variable")
	lower(variable) == "aws:sourceaccount"
}

# If the only action is sts:AssumeRole (assume-role trust policy), the
# confused-deputy pattern does not apply the same way and AWS does not
# require SourceAccount there.
_is_only_assume_role(stmt) if {
	actions := tf.attr_raw(stmt, "actions")
	contains(actions, "sts:AssumeRole")
	not contains(actions, ",")
}
