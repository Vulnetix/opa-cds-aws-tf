# Intent derived from https://github.com/cds-snc/opa_checks (MIT).
# Clean-room implementation — no upstream Rego copied.

package vulnetix.rules.cds_aws_tf_rds_database_name

import rego.v1

import data.vulnetix.cds_aws_tf.pg_reserved
import data.vulnetix.cds_aws_tf.tf

metadata := {
	"id": "CDS-AWS-TF-RDS-003",
	"name": "RDS cluster database_name must not be a PostgreSQL reserved keyword",
	"description": "The initial database created inside an RDS cluster cannot be named after a PostgreSQL reserved keyword — the cluster provisions but every subsequent unquoted reference to the database breaks.",
	"help_uri": "https://www.postgresql.org/docs/current/sql-keywords-appendix.html",
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
	db_name := tf.attr_string(block, "database_name")
	pg_reserved.is_reserved(db_name)
	line := tf.attr_line(block, "database_name")
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("database_name %q is a PostgreSQL reserved keyword", [db_name]),
		"artifact_uri": block.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": line,
		"snippet": tf.snippet(block, line),
	}
}
