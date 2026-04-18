# Intent derived from https://github.com/cds-snc/opa_checks (MIT).
# Clean-room implementation — no upstream Rego copied.

package vulnetix.rules.cds_aws_tf_cloudfront_error_response_path

import rego.v1

import data.vulnetix.cds_aws_tf.tf

metadata := {
	"id": "CDS-AWS-TF-CF-001",
	"name": "CloudFront custom error response path must start with /",
	"description": "`aws_cloudfront_distribution.custom_error_response.response_page_path` must be an absolute path beginning with `/` — CloudFront silently ignores paths without the leading slash and the custom error page never renders, leaving users with a generic 403/404.",
	"help_uri": "https://docs.aws.amazon.com/cloudfront/latest/APIReference/API_CustomErrorResponse.html",
	"languages": ["terraform"],
	"severity": "low",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "cloudfront", "terraform"],
}

findings contains finding if {
	some block in tf.resource_blocks("aws_cloudfront_distribution")
	some err in tf.sub_blocks(block, "custom_error_response")
	path := tf.attr_string(err, "response_page_path")
	not startswith(path, "/")
	line := tf.attr_line(err, "response_page_path")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("response_page_path %q must start with '/'", [path]),
		"artifact_uri": block.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": tf.snippet(err, line),
	}
}
