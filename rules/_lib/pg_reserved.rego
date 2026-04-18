# PostgreSQL reserved SQL keywords.
# Clean-room compilation from the PostgreSQL 16 documentation
# (Appendix C — "SQL Key Words"). Keywords listed as "reserved" or
# "reserved (can be function or type)" in the SQL:2023 / PostgreSQL columns
# are included. These keywords cannot be used as identifiers without
# quoting in PostgreSQL, and therefore are unsafe choices for RDS master
# usernames, database names, or unquoted identifiers passed through
# Terraform.
#
# Source: https://www.postgresql.org/docs/16/sql-keywords-appendix.html
# (facts, not copyrightable)

package vulnetix.cds_aws_tf.pg_reserved

import rego.v1

# Lower-case set for case-insensitive membership checks.
keywords := {
	"all", "analyse", "analyze", "and", "any", "array", "as", "asc",
	"asymmetric", "authorization", "binary", "both", "case", "cast",
	"check", "collate", "collation", "column", "concurrently",
	"constraint", "create", "cross", "current_catalog", "current_date",
	"current_role", "current_schema", "current_time", "current_timestamp",
	"current_user", "default", "deferrable", "desc", "distinct", "do",
	"else", "end", "except", "false", "fetch", "for", "foreign",
	"freeze", "from", "full", "grant", "group", "having", "ilike", "in",
	"initially", "inner", "intersect", "into", "is", "isnull", "join",
	"lateral", "leading", "left", "like", "limit", "localtime",
	"localtimestamp", "natural", "not", "notnull", "null", "offset",
	"on", "only", "or", "order", "outer", "overlaps", "placing",
	"primary", "references", "returning", "right", "select",
	"session_user", "similar", "some", "symmetric", "system_user",
	"table", "tablesample", "then", "to", "trailing", "true", "union",
	"unique", "user", "using", "variadic", "verbose", "when", "where",
	"window", "with",
}

is_reserved(word) if {
	lower_word := lower(word)
	keywords[lower_word]
}
