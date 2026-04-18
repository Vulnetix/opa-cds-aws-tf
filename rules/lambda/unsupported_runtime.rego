# Intent derived from https://github.com/cds-snc/opa_checks (MIT).
# Clean-room implementation — no upstream Rego copied.

package vulnetix.rules.cds_aws_tf_lambda_unsupported_runtime

import rego.v1

import data.vulnetix.cds_aws_tf.tf

metadata := {
	"id": "CDS-AWS-TF-LAMBDA-001",
	"name": "Lambda runtime must be supported by AWS",
	"description": "AWS retires Lambda runtimes on a rolling schedule; deprecated runtimes stop receiving security patches and eventually refuse to execute. Keep the runtime within the currently supported list, or use a container image / custom `provided.*` runtime.",
	"help_uri": "https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [1104],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "lambda", "terraform", "eol"],
}

# Clean-room list from the AWS Lambda runtimes documentation as of 2026-04.
# Review periodically; retired runtimes should be pruned.
_supported := {
	"nodejs18.x", "nodejs20.x", "nodejs22.x",
	"python3.9", "python3.10", "python3.11", "python3.12", "python3.13",
	"java8.al2", "java11", "java17", "java21",
	"dotnet6", "dotnet8",
	"ruby3.2", "ruby3.3",
	"go1.x",
	"provided.al2", "provided.al2023",
}

findings contains finding if {
	some block in tf.resource_blocks("aws_lambda_function")
	runtime := tf.attr_string(block, "runtime")
	not _supported[runtime]
	line := tf.attr_line(block, "runtime")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Lambda runtime %q is not in the supported set; check AWS EOL schedule", [runtime]),
		"artifact_uri": block.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": tf.snippet(block, line),
	}
}
