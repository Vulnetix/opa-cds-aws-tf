# Clean-room Terraform (.tf) source scanning helpers.
# Not a rule. Not derived from any upstream OPA library.
#
# Design notes:
# - Operates on raw .tf text via input.file_contents, not on Terraform plan JSON.
# - Block boundaries are inferred from `terraform fmt` conventions: each
#   top-level block's closing `}` sits at column 0 on its own line.
# - Regex patterns intentionally tolerate extra whitespace but do not attempt
#   full HCL parsing. Unusual formatting may produce false negatives — that is
#   an accepted trade-off for a dependency-free scanner.

package vulnetix.cds_aws_tf.tf

import rego.v1

# ---------- file discovery ----------

is_tf_file(path) if {
	lower_path := lower(path)
	endswith(lower_path, ".tf")
	not contains(lower_path, "/.terraform/")
}

tf_files := [{"path": path, "content": content, "lines": split(content, "\n")} |
	some path, content in input.file_contents
	is_tf_file(path)
]

# ---------- block discovery ----------

# resource_blocks(type): list of resource "TYPE" "NAME" { ... } blocks.
# type is a regex-safe string (e.g. "aws_iam_policy_document").
resource_blocks(type) := [b |
	some f in tf_files
	some b in _blocks(f.path, f.lines, "resource", type)
]

# data_blocks(type): list of data "TYPE" "NAME" { ... } blocks.
data_blocks(type) := [b |
	some f in tf_files
	some b in _blocks(f.path, f.lines, "data", type)
]

# any_blocks([types]): resource blocks whose type is in the given set.
any_resource_blocks(types) := [b |
	some t in types
	some b in resource_blocks(t)
]

_blocks(path, lines, kind, type) := out if {
	header_pattern := sprintf(`^\s*%s\s+"%s"\s+"[^"]+"\s*\{`, [kind, type])
	name_pattern := sprintf(`^\s*%s\s+"%s"\s+"([^"]+)"`, [kind, type])
	headers := [{"idx": i, "name": _first_submatch(name_pattern, line)} |
		some i, line in lines
		regex.match(header_pattern, line)
	]
	out := [b |
		some h in headers
		close_idx := _matching_close(lines, h.idx)
		body_lines := array.slice(lines, h.idx + 1, close_idx)
		b := {
			"path": path,
			"kind": kind,
			"type": type,
			"name": h.name,
			"header_line": h.idx + 1,
			"close_line": close_idx + 1,
			"body_start_line": h.idx + 2,
			"body": concat("\n", body_lines),
			"body_lines": body_lines,
			"header_text": lines[h.idx],
		}
	]
}

# First line after `start` whose only content is `}`.
# Works for `terraform fmt` output: top-level blocks terminate with `}` at
# column 0. Inner `}` characters are indented.
_matching_close(lines, start) := idx if {
	candidates := [i |
		some i in numbers.range(start + 1, count(lines) - 1)
		regex.match(`^\}\s*$`, lines[i])
	]
	idx := candidates[0]
}

# ---------- attribute inspection ----------

# attr_string(block, name): the string literal value of attribute `name`.
# Returns the literal contents (without quotes). Undefined if not a string
# attribute or not present. `name` must match [A-Za-z0-9_], which is true for
# all valid HCL identifiers.
attr_string(block, name) := value if {
	pattern := sprintf(`(?m)^\s*%s\s*=\s*"([^"]*)"\s*$`, [name])
	value := _first_submatch(pattern, block.body)
}

# attr_line(block, name): the 1-based line number within the file where
# attribute `name = ...` is declared inside the block's body.
attr_line(block, name) := line if {
	pattern := sprintf(`^\s*%s\s*=`, [name])
	some i, text in block.body_lines
	regex.match(pattern, text)
	line := block.body_start_line + i
}

# attr_raw(block, name): the raw right-hand side of `name = <RHS>` up to end
# of the line (useful for numeric, reference, or quoted values).
attr_raw(block, name) := value if {
	pattern := sprintf(`(?m)^\s*%s\s*=\s*(.+?)\s*$`, [name])
	value := _first_submatch(pattern, block.body)
}

# has_attr(block, name): true if the block's body defines the attribute.
has_attr(block, name) if {
	pattern := sprintf(`(?m)^\s*%s\s*=`, [name])
	regex.match(pattern, block.body)
}

# ---------- sub-block inspection ----------

# sub_blocks(block, name): nested blocks of the form `NAME { ... }` at any
# indentation inside the parent body. Uses the same `terraform fmt`
# closing-brace convention: the closing `}` of each sub-block must be on its
# own line with matching indentation or less.
sub_blocks(block, name) := out if {
	header_pattern := sprintf(`^(\s*)%s\s*\{\s*$`, [name])
	header_indices := [i |
		some i, line in block.body_lines
		regex.match(header_pattern, line)
	]
	out := [sb |
		some hi in header_indices
		indent := _leading_ws(block.body_lines[hi])
		close_i := _matching_sub_close(block.body_lines, hi, indent)
		sub_body_lines := array.slice(block.body_lines, hi + 1, close_i)
		sb := {
			"path": block.path,
			"name": name,
			"header_line": block.body_start_line + hi,
			"close_line": block.body_start_line + close_i,
			"body_start_line": block.body_start_line + hi + 1,
			"body": concat("\n", sub_body_lines),
			"body_lines": sub_body_lines,
			"header_text": block.body_lines[hi],
		}
	]
}

_leading_ws(line) := ws if {
	m := regex.find_all_string_submatch_n(`^(\s*)`, line, 1)
	ws := m[0][1]
}

_matching_sub_close(lines, start, indent) := idx if {
	pattern := sprintf(`^%s\}\s*$`, [indent])
	candidates := [i |
		some i in numbers.range(start + 1, count(lines) - 1)
		regex.match(pattern, lines[i])
	]
	idx := candidates[0]
}

# ---------- utility ----------

# Find the 1-based line within a block body where `needle_pattern` matches.
# Useful when a specific sub-line triggers a finding.
line_matching(block, needle_pattern) := line if {
	some i, text in block.body_lines
	regex.match(needle_pattern, text)
	line := block.body_start_line + i
}

snippet(block, line_num) := text if {
	rel := line_num - block.body_start_line
	rel >= 0
	rel < count(block.body_lines)
	text := block.body_lines[rel]
} else := block.header_text

# Internal: first capture group of first match, or undefined.
_first_submatch(pattern, text) := value if {
	m := regex.find_all_string_submatch_n(pattern, text, 1)
	count(m) > 0
	value := m[0][1]
}
