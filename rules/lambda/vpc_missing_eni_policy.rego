# Intent derived from https://github.com/cds-snc/opa_checks (MIT).
# Clean-room implementation — no upstream Rego copied.

package vulnetix.rules.cds_aws_tf_lambda_vpc_missing_eni_policy

import rego.v1

import data.vulnetix.cds_aws_tf.tf

metadata := {
	"id": "CDS-AWS-TF-LAMBDA-002",
	"name": "VPC-attached Lambda must have the VPC-execution managed policy attached to its role",
	"description": "Lambdas with a `vpc_config` block need to create and delete ENIs at cold-start. Without the AWS-managed policy `AWSLambdaVPCAccessExecutionRole` (or equivalent inline permissions) attached to the function's execution role, cold-starts fail with an obscure `EC2ThrottledException` message after production traffic has already shifted. Catching this statically avoids a painful pager.",
	"help_uri": "https://docs.aws.amazon.com/lambda/latest/dg/configuration-vpc.html",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "lambda", "terraform", "iam"],
}

# A VPC-attached Lambda function is one whose aws_lambda_function block has
# a vpc_config sub-block.
_vpc_lambdas := [b |
	some b in tf.resource_blocks("aws_lambda_function")
	count(tf.sub_blocks(b, "vpc_config")) > 0
]

# The set of role attributes referenced across all VPC-attached lambdas.
# We emit one finding per function whose role doesn't appear in a
# role_policy_attachment referencing the AWS-managed ENI policy.
findings contains finding if {
	some lambda in _vpc_lambdas
	role_ref := tf.attr_raw(lambda, "role")
	not _has_eni_attachment(role_ref)
	line := tf.attr_line(lambda, "role")
	finding := {
		"rule_id": metadata.id,
		"message": "VPC-attached Lambda execution role is missing the AWSLambdaVPCAccessExecutionRole managed policy attachment",
		"artifact_uri": lambda.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": tf.snippet(lambda, line),
	}
}

_has_eni_attachment(role_ref) if {
	some attach in tf.resource_blocks("aws_iam_role_policy_attachment")
	_refers_same_role(tf.attr_raw(attach, "role"), role_ref)
	policy_arn := tf.attr_raw(attach, "policy_arn")
	contains(policy_arn, "AWSLambdaVPCAccessExecutionRole")
}

# Match role references loosely — strip whitespace and punctuation so that
# `aws_iam_role.foo.arn` and `aws_iam_role.foo.name` both compare equal.
_refers_same_role(a, b) if {
	_normalise_role(a) == _normalise_role(b)
}

_normalise_role(ref) := out if {
	trimmed := trim_space(ref)
	without_tail := regex.replace(trimmed, `\.(arn|name|id)\s*$`, "")
	out := without_tail
}
