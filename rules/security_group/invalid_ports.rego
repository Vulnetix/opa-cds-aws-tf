# Intent derived from https://github.com/cds-snc/opa_checks (MIT).
# Clean-room implementation — no upstream Rego copied.

package vulnetix.rules.cds_aws_tf_sg_invalid_ports

import rego.v1

import data.vulnetix.cds_aws_tf.tf

metadata := {
	"id": "CDS-AWS-TF-SG-001",
	"name": "Security group ingress/egress with protocol \"-1\" must set ports to 0",
	"description": "When a security group rule sets `protocol = \"-1\"` (all protocols), AWS requires both `from_port` and `to_port` to be `0`. Any other value is accepted by Terraform's local validation but then rejected at apply time with a generic `InvalidParameterValue` error. Flagging this at scan time also forces an explicit conversation about whether an all-protocols rule is actually intended.",
	"help_uri": "https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_IpPermission.html",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "security-group", "terraform", "network"],
}

findings contains finding if {
	some block in tf.resource_blocks("aws_security_group")
	some rule in _rule_blocks(block)
	tf.attr_string(rule, "protocol") == "-1"
	some attr in {"from_port", "to_port"}
	tf.attr_raw(rule, attr) != "0"
	line := tf.attr_line(rule, attr)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("%s block with protocol = \"-1\" must have %s set to 0", [rule.name, attr]),
		"artifact_uri": block.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": tf.snippet(rule, line),
	}
}

_rule_blocks(block) := out if {
	ingress := tf.sub_blocks(block, "ingress")
	egress := tf.sub_blocks(block, "egress")
	out := array.concat(ingress, egress)
}
