# Intent derived from https://github.com/cds-snc/opa_checks (MIT).
# Clean-room implementation — no upstream Rego copied.

package vulnetix.rules.cds_aws_tf_rds_master_username

import rego.v1

import data.vulnetix.cds_aws_tf.pg_reserved
import data.vulnetix.cds_aws_tf.tf

metadata := {
	"id": "CDS-AWS-TF-RDS-002",
	"name": "RDS cluster master username must satisfy PostgreSQL identifier rules",
	"description": "PostgreSQL identifiers must start with a letter, be shorter than 64 characters, and must not collide with a reserved keyword. RDS will reject the cluster creation otherwise. Violations tend to hide in auto-generated module inputs.",
	"help_uri": "https://www.postgresql.org/docs/current/sql-syntax-lexical.html",
	"languages": ["terraform"],
	"severity": "medium",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "rds", "terraform", "postgres"],
}

findings contains finding if {
	some block in tf.resource_blocks("aws_rds_cluster")
	username := tf.attr_string(block, "master_username")
	not regex.match(`^[A-Za-z]`, username)
	finding := _make(block, "must start with a letter (a-z, A-Z)")
}

findings contains finding if {
	some block in tf.resource_blocks("aws_rds_cluster")
	username := tf.attr_string(block, "master_username")
	count(username) >= 64
	finding := _make(block, "must be shorter than 64 characters")
}

findings contains finding if {
	some block in tf.resource_blocks("aws_rds_cluster")
	username := tf.attr_string(block, "master_username")
	pg_reserved.is_reserved(username)
	finding := _make(block, "must not be a PostgreSQL reserved keyword")
}

_make(block, reason) := finding if {
	line := tf.attr_line(block, "master_username")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("aws_rds_cluster.master_username is invalid: %s", [reason]),
		"artifact_uri": block.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": tf.snippet(block, line),
	}
}
