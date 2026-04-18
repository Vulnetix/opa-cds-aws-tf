# Intent derived from https://github.com/cds-snc/opa_checks (MIT).
# Clean-room implementation — no upstream Rego copied.

package vulnetix.rules.cds_aws_tf_api_gateway_integration_uri

import rego.v1

import data.vulnetix.cds_aws_tf.tf

metadata := {
	"id": "CDS-AWS-TF-APIGW-001",
	"name": "API Gateway integration URI must match the integration type",
	"description": "AWS API Gateway validates `aws_api_gateway_integration.uri` against the integration `type`. For `AWS` and `AWS_PROXY` the URI must be an ARN that starts with `arn:aws:apigateway:`; for `HTTP` and `HTTP_PROXY` it must be an http:// or https:// URL. Mismatches fail at apply with a vague error.",
	"help_uri": "https://docs.aws.amazon.com/apigateway/latest/api/API_Integration.html",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "api-gateway", "terraform"],
}

_aws_types := {"AWS", "AWS_PROXY"}

_http_types := {"HTTP", "HTTP_PROXY"}

findings contains finding if {
	some block in tf.resource_blocks("aws_api_gateway_integration")
	kind := tf.attr_string(block, "type")
	_aws_types[kind]
	uri := tf.attr_string(block, "uri")
	not startswith(uri, "arn:aws:apigateway:")
	finding := _make(block, kind, uri, "arn:aws:apigateway:…")
}

findings contains finding if {
	some block in tf.resource_blocks("aws_api_gateway_integration")
	kind := tf.attr_string(block, "type")
	_http_types[kind]
	uri := tf.attr_string(block, "uri")
	not startswith(uri, "http://")
	not startswith(uri, "https://")
	finding := _make(block, kind, uri, "http(s)://…")
}

_make(block, kind, uri, expected) := finding if {
	line := tf.attr_line(block, "uri")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("Integration type %q requires uri to start with %s, got %q", [kind, expected, uri]),
		"artifact_uri": block.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": tf.snippet(block, line),
	}
}
