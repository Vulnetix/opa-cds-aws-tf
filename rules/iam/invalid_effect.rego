# Intent derived from https://github.com/cds-snc/opa_checks (MIT).
# This file is an original clean-room implementation — no upstream Rego was
# copied. The behaviour matches the security intent: an IAM policy
# statement's `effect` attribute must be "Allow" or "Deny".

package vulnetix.rules.cds_aws_tf_iam_invalid_effect

import rego.v1

import data.vulnetix.cds_aws_tf.tf

metadata := {
	"id": "CDS-AWS-TF-IAM-001",
	"name": "IAM policy statement effect must be Allow or Deny",
	"description": "AWS IAM policy statements support exactly two Effect values: `Allow` and `Deny`. Any other value is rejected at deploy time and usually signals a typo — for example `allow` or `Permit` — that silently weakens the intended authorization model.",
	"help_uri": "https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_effect.html",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [732],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "iam", "terraform", "policy"],
}

_valid := {"Allow", "Deny"}

findings contains finding if {
	some block in tf.data_blocks("aws_iam_policy_document")
	some stmt in tf.sub_blocks(block, "statement")
	effect := tf.attr_string(stmt, "effect")
	not _valid[effect]
	line := tf.attr_line(stmt, "effect")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("IAM statement effect must be \"Allow\" or \"Deny\"; found %q", [effect]),
		"artifact_uri": block.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": tf.snippet(stmt, line),
	}
}
