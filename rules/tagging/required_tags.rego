# Intent derived from https://github.com/cds-snc/opa_checks (MIT).
# Clean-room implementation — no upstream Rego copied.

package vulnetix.rules.cds_aws_tf_required_tags

import rego.v1

import data.vulnetix.cds_aws_tf.tf

metadata := {
	"id": "CDS-AWS-TF-TAG-001",
	"name": "AWS resource tags must include governance keys",
	"description": "Any resource that declares a `tags = { ... }` map must include the governance keys `CostCentre` (for finance chargeback) and `Terraform` (to identify infrastructure-as-code-managed resources during incident response). The exact key names are organisation-specific; edit the rule to match your team's policy.",
	"help_uri": "https://docs.aws.amazon.com/whitepapers/latest/tagging-best-practices/tagging-best-practices.html",
	"languages": ["terraform"],
	"severity": "low",
	"level": "warning",
	"kind": "iac",
	"cwe": [],
	"capec": [],
	"attack_technique": [],
	"cvssv4": "",
	"cwss": "",
	"tags": ["aws", "tagging", "terraform", "governance"],
}

_required := {"CostCentre", "Terraform"}

findings contains finding if {
	some f in tf.tf_files
	some block_match in _tags_blocks(f)
	some key in _missing(block_match.body)
	finding := {
		"rule_id": metadata.id,
		"message": sprintf("tags block is missing required key %q", [key]),
		"artifact_uri": f.path,
		"severity": metadata.severity,
		"level": metadata.level,
		"start_line": block_match.line,
		"snippet": f.lines[block_match.line - 1],
	}
}

# Find inline `tags = { ... }` maps per file. This is a pragmatic scan —
# we locate the opening `tags = {` line, then consume up to the matching
# `}` line at the same indentation.
_tags_blocks(f) := out if {
	starts := [i |
		some i, line in f.lines
		regex.match(`^\s*tags\s*=\s*\{`, line)
	]
	out := [m |
		some s in starts
		indent := _leading_ws(f.lines[s])
		close_pattern := sprintf(`^%s\}\s*$`, [indent])
		candidates := [j |
			some j in numbers.range(s + 1, count(f.lines) - 1)
			regex.match(close_pattern, f.lines[j])
		]
		count(candidates) > 0
		m := {"line": s + 1, "body": concat("\n", array.slice(f.lines, s + 1, candidates[0]))}
	]
}

_leading_ws(line) := ws if {
	m := regex.find_all_string_submatch_n(`^(\s*)`, line, 1)
	ws := m[0][1]
}

_missing(body) := {key |
	some key in _required
	not _has_key(body, key)
}

_has_key(body, key) if {
	pattern := sprintf(`(?m)^\s*(?:"%s"|%s)\s*=`, [key, key])
	regex.match(pattern, body)
}
