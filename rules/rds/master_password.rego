# Intent derived from https://github.com/cds-snc/opa_checks (MIT).
# Clean-room implementation — no upstream Rego copied.

package vulnetix.rules.cds_aws_tf_rds_master_password

import rego.v1

import data.vulnetix.cds_aws_tf.pg_reserved
import data.vulnetix.cds_aws_tf.tf

metadata := {
	"id": "CDS-AWS-TF-RDS-001",
	"name": "RDS cluster master password must satisfy AWS and PostgreSQL constraints",
	"description": "AWS RDS for PostgreSQL rejects master passwords shorter than 8 characters, passwords containing `/`, `@`, or `\"`, and passwords that are PostgreSQL reserved keywords. Deploys fail late and the error message points at the API, not the Terraform line — catching this at scan time saves rollbacks.",
	"help_uri": "https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_CreateDBCluster.html",
	"languages": ["terraform"],
	"severity": "high",
	"level": "error",
	"kind": "iac",
	"cwe": [521],
	"capec": ["CAPEC-49"],
	"attack_technique": ["T1110"],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "rds", "terraform", "credentials"],
}

findings contains finding if {
	some block in tf.resource_blocks("aws_rds_cluster")
	password := tf.attr_string(block, "master_password")
	count(password) < 8
	finding := _make(block, "must be at least 8 characters")
}

findings contains finding if {
	some block in tf.resource_blocks("aws_rds_cluster")
	password := tf.attr_string(block, "master_password")
	some c in ["/", "@", "\""]
	contains(password, c)
	finding := _make(block, sprintf("must not contain the character %q", [c]))
}

findings contains finding if {
	some block in tf.resource_blocks("aws_rds_cluster")
	password := tf.attr_string(block, "master_password")
	pg_reserved.is_reserved(password)
	finding := _make(block, "must not be a PostgreSQL reserved keyword")
}

_make(block, reason) := finding if {
	line := tf.attr_line(block, "master_password")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_rds_cluster.master_password is invalid: %s", [reason]),
		"artifact_uri": block.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": tf.snippet(block, line),
	}
}
