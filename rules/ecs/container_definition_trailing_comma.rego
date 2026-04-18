# Intent derived from https://github.com/cds-snc/opa_checks (MIT).
# Clean-room implementation — no upstream Rego copied.

package vulnetix.rules.cds_aws_tf_ecs_container_definition_trailing_comma

import rego.v1

import data.vulnetix.cds_aws_tf.tf

metadata := {
	"id": "CDS-AWS-TF-ECS-002",
	"name": "ECS container_definitions JSON must not contain trailing commas",
	"description": "`aws_ecs_task_definition.container_definitions` takes a JSON string, and strict JSON parsers reject trailing commas before `]` or `}`. The error surfaces at apply time with no line number; catching it statically saves a full plan/apply cycle.",
	"help_uri": "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definitions.html",
	"languages": ["terraform"],
	"severity": "low",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "ecs", "terraform", "json"],
}

findings contains finding if {
	some block in tf.resource_blocks("aws_ecs_task_definition")
	some i, text in block.body_lines
	regex.match(`,\s*[\]\}]`, text)
	line := block.body_start_line + i
	finding := {
		"rule_id": metadata.id,
		"message": "container_definitions contains a trailing comma before a closing bracket or brace",
		"artifact_uri": block.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": text,
	}
}
