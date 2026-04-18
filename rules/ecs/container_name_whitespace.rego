# Intent derived from https://github.com/cds-snc/opa_checks (MIT).
# Clean-room implementation — no upstream Rego copied.

package vulnetix.rules.cds_aws_tf_ecs_container_name_whitespace

import rego.v1

import data.vulnetix.cds_aws_tf.tf

metadata := {
	"id": "CDS-AWS-TF-ECS-001",
	"name": "ECS container definition name must not contain whitespace",
	"description": "ECS container names are used in CloudWatch log stream paths, ECS Exec targets, sidecar `dependsOn` references, and service-discovery hostnames. Whitespace in the name breaks all of these downstream consumers even though the task definition itself will register successfully.",
	"help_uri": "https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task_definition_parameters.html",
	"languages": ["terraform"],
	"severity": "low",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "ecs", "terraform"],
}

findings contains finding if {
	some block in tf.resource_blocks("aws_ecs_task_definition")
	some m in regex.find_all_string_submatch_n(`"name"\s*:\s*"([^"]*\s[^"]*)"`, block.body, -1)
	name := m[1]
	line := _line_containing(block, m[0])
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Container name %q contains whitespace", [name]),
		"artifact_uri": block.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": tf.snippet(block, line),
	}
}

_line_containing(block, needle) := line if {
	some i, text in block.body_lines
	contains(text, needle)
	line := block.body_start_line + i
} else := block.header_line
