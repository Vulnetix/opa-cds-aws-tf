# Intent derived from https://github.com/cds-snc/opa_checks (MIT).
# Clean-room implementation — no upstream Rego copied.

package vulnetix.rules.cds_aws_tf_waf_duplicate_priority

import rego.v1

import data.vulnetix.cds_aws_tf.tf

metadata := {
	"id": "CDS-AWS-TF-WAF-001",
	"name": "WAFv2 web ACL rules must have unique priorities",
	"description": "`aws_wafv2_web_acl` rules are evaluated in ascending `priority` order. Duplicate priorities are rejected by the WAFv2 API with a generic `WAFInvalidParameterException`, and the error message does not identify which two rules collided — catching this statically short-circuits a painful debugging loop.",
	"help_uri": "https://docs.aws.amazon.com/waf/latest/developerguide/classic-web-acl-priority.html",
	"languages": ["terraform"],
	"severity": "low",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "waf", "terraform"],
}

findings contains finding if {
	some block in tf.resource_blocks("aws_wafv2_web_acl")
	rules := tf.sub_blocks(block, "rule")
	some dup in _duplicate_priorities(rules)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Multiple rules in aws_wafv2_web_acl %q share priority %q", [block.name, dup.priority]),
		"artifact_uri": block.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": dup.line,
		"snippet": tf.snippet(block, dup.line),
	}
}

_duplicate_priorities(rules) := [{"priority": p, "line": line} |
	priorities := [tf.attr_raw(r, "priority") | some r in rules]
	some p in priorities
	count([x | some x in priorities; x == p]) > 1
	some r in rules
	tf.attr_raw(r, "priority") == p
	line := tf.attr_line(r, "priority")
]
