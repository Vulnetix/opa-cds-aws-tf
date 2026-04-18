# Intent derived from https://github.com/cds-snc/opa_checks (MIT).
# Clean-room implementation — no upstream Rego copied.

package vulnetix.rules.cds_aws_tf_cloudwatch_metric_filter_pattern

import rego.v1

import data.vulnetix.cds_aws_tf.tf

metadata := {
	"id": "CDS-AWS-TF-CW-001",
	"name": "CloudWatch log metric filter pattern must be a valid filter expression",
	"description": "A `pattern` must be one of: a JSON filter expression starting with `{` and ending with `}`; a space-delimited field sequence starting with `[` and ending with `]`; or a plain text term whose quotes balance. Invalid patterns validate at apply time but then silently never match log events, leaving the alarm permanently unarmed.",
	"help_uri": "https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html",
	"languages": ["terraform"],
	"severity": "low",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "cloudwatch", "terraform", "logging"],
}

findings contains finding if {
	some block in tf.resource_blocks("aws_cloudwatch_log_metric_filter")
	pattern := tf.attr_string(block, "pattern")
	not _looks_valid(pattern)
	line := tf.attr_line(block, "pattern")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Metric filter pattern %q does not look like a valid filter expression", [pattern]),
		"artifact_uri": block.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": tf.snippet(block, line),
	}
}

_looks_valid(pat) if {
	trimmed := trim_space(pat)
	startswith(trimmed, "{")
	endswith(trimmed, "}")
}

_looks_valid(pat) if {
	trimmed := trim_space(pat)
	startswith(trimmed, "[")
	endswith(trimmed, "]")
}

_looks_valid(pat) if {
	not contains(pat, "{")
	not contains(pat, "}")
	not contains(pat, "[")
	not contains(pat, "]")
	count(regex.find_all_string_submatch_n(`"`, pat, -1)) % 2 == 0
}
