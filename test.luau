--!strict

-- Tests for the Seashell module.
-- Run with: luau test.luau
--
-- Each test calls `assert` with a descriptive message.  A failing assertion
-- will raise an error and print the message, making the broken test easy to
-- spot.  A passing run prints "All tests passed." at the end.

local Seashell = require("init")

-- ─── Helpers ──────────────────────────────────────────────────────────────────

--- Runs `fn` and returns `true` when it raises an error whose message contains
--- `expected_fragment`.  Returns `false` if no error is raised, and re-raises
--- the original error if it does not contain the expected fragment.
local function expect_error(fn: () -> (), expected_fragment: string): boolean
	local ok: boolean, err: unknown = pcall(fn)
	if ok then
		return false
	end
	-- err is the error object – coerce to string for the substring check.
	local msg: string = tostring(err)
	if not string.find(msg, expected_fragment, 1, true) then
		error(`Expected error containing '{expected_fragment}' but got: {msg}`)
	end
	return true
end

-- ─── hash_string ──────────────────────────────────────────────────────────────

-- SHA-1("") = da39a3ee5e6b4b0d3255bfef95601890afd80709  (RFC 3174)
assert(
	Seashell.hash_string("") == "da39a3ee5e6b4b0d3255bfef95601890afd80709",
	"hash_string: empty string must match RFC 3174 test vector"
)

-- SHA-1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d  (RFC 3174)
assert(
	Seashell.hash_string("abc") == "a9993e364706816aba3e25717850c26c9cd0d89d",
	"hash_string: 'abc' must match RFC 3174 test vector"
)

-- Same input always yields the same output.
assert(
	Seashell.hash_string("hello") == Seashell.hash_string("hello"),
	"hash_string: same input must produce the same digest"
)

-- Different inputs must produce different digests.
assert(
	Seashell.hash_string("hello") ~= Seashell.hash_string("world"),
	"hash_string: different inputs must produce different digests"
)

-- Digest is always 40 hex characters.
assert(
	#Seashell.hash_string("test") == 40,
	"hash_string: digest must be exactly 40 characters"
)

-- ─── signature_of ─────────────────────────────────────────────────────────────

-- Empty table produces an empty signature.
assert(
	Seashell.signature_of({}) == "",
	"signature_of: empty table must produce an empty string"
)

-- Flat table: keys must be sorted lexicographically.
assert(
	Seashell.signature_of({ z = 1, a = 2, m = 3 }) == "a,m,z",
	"signature_of: flat keys must be sorted lexicographically"
)

-- Number keys are converted via tostring and sorted accordingly.
assert(
	Seashell.signature_of({ [3] = true, [1] = true, [2] = true }) == "1,2,3",
	"signature_of: number keys must be sorted lexicographically by tostring"
)

-- Mixed string/number keys are sorted together as strings.
assert(
	Seashell.signature_of({ b = 1, [1] = 2, a = 3 }) == "1,a,b",
	"signature_of: mixed string/number keys must sort as strings"
)

-- Nested table: the value being a table triggers the brace notation.
assert(
	Seashell.signature_of({ outer = { inner = 1 } }) == "outer{inner}",
	"signature_of: nested table must use brace notation"
)

-- Nested table with multiple children, sorted correctly.
assert(
	Seashell.signature_of({ root = { z = 1, a = 2 } }) == "root{a,z}",
	"signature_of: nested keys must be sorted"
)

-- Multiple top-level keys, one of which is a nested table.
assert(
	Seashell.signature_of({ name = "x", addr = { city = "y", zip = "z" } })
		== "addr{city,zip},name",
	"signature_of: mixed flat and nested keys must be ordered correctly"
)

-- Deeply nested tables (three levels).
local deep: Seashell.TableLike = { level1 = { level2 = { level3 = 0 } } }
assert(
	Seashell.signature_of(deep) == "level1{level2{level3}}",
	"signature_of: deeply nested tables must produce correct brace notation"
)

-- ─── hash_table ───────────────────────────────────────────────────────────────

-- Same structure, different values → same hash.
local tbl_a: Seashell.TableLike = { name = "Alice", age = 30 }
local tbl_b: Seashell.TableLike = { name = "Bob",   age = 99 }
assert(
	Seashell.hash_table(tbl_a) == Seashell.hash_table(tbl_b),
	"hash_table: same key structure with different values must produce the same hash"
)

-- Nested tables with same structure, different values → same hash.
local nested_a: Seashell.TableLike = { user = { id = 1,  name = "Alice" } }
local nested_b: Seashell.TableLike = { user = { id = 99, name = "Bob"   } }
assert(
	Seashell.hash_table(nested_a) == Seashell.hash_table(nested_b),
	"hash_table: same nested key structure with different values must produce the same hash"
)

-- Multiple levels of nesting with same structure → same hash.
local multi_a: Seashell.TableLike = { a = { b = { c = 1 } } }
local multi_b: Seashell.TableLike = { a = { b = { c = 2 } } }
assert(
	Seashell.hash_table(multi_a) == Seashell.hash_table(multi_b),
	"hash_table: multiple levels of nesting — same structure must hash equally"
)

-- Different structures → different hashes.
local diff_a: Seashell.TableLike = { x = 1, y = 2 }
local diff_b: Seashell.TableLike = { x = 1, z = 2 }
assert(
	Seashell.hash_table(diff_a) ~= Seashell.hash_table(diff_b),
	"hash_table: different key structures must produce different hashes"
)

-- A nested value that is not a table is treated the same regardless of value.
local leaf_a: Seashell.TableLike = { k = 42 }
local leaf_b: Seashell.TableLike = { k = "hello" }
assert(
	Seashell.hash_table(leaf_a) == Seashell.hash_table(leaf_b),
	"hash_table: non-table values under the same key must not affect the hash"
)

-- Extra key in one table → different hash.
local extra_a: Seashell.TableLike = { x = 1 }
local extra_b: Seashell.TableLike = { x = 1, y = 2 }
assert(
	Seashell.hash_table(extra_a) ~= Seashell.hash_table(extra_b),
	"hash_table: a table with an extra key must produce a different hash"
)

-- Empty tables hash equally.
assert(
	Seashell.hash_table({}) == Seashell.hash_table({}),
	"hash_table: two empty tables must produce the same hash"
)

-- ─── Cyclic reference detection ───────────────────────────────────────────────

-- Direct self-reference (t.self = t).
local cyclic_direct: Seashell.TableLike = {}
cyclic_direct["self"] = cyclic_direct
assert(
	expect_error(function()
		Seashell.hash_table(cyclic_direct)
	end, "Cyclic"),
	"hash_table: direct cyclic reference must raise an error"
)

-- Indirect cycle (A.child = B, B.parent = A).
local cycle_a: Seashell.TableLike = {}
local cycle_b: Seashell.TableLike = {}
cycle_a["child"] = cycle_b
cycle_b["parent"] = cycle_a
assert(
	expect_error(function()
		Seashell.hash_table(cycle_a)
	end, "Cyclic"),
	"hash_table: indirect cyclic reference must raise an error"
)

-- Diamond (shared sub-table, NOT a cycle) must NOT raise.
local shared: Seashell.TableLike = { val = 1 }
local diamond: Seashell.TableLike = { left = shared, right = shared }
assert(
	pcall(Seashell.hash_table, diamond),
	"hash_table: diamond-shaped (shared) reference must not raise an error"
)

-- ─── Invalid key type detection ───────────────────────────────────────────────

-- Boolean key must be rejected.
local bad_bool: Seashell.TableLike = { [true] = 1 } :: Seashell.TableLike
assert(
	expect_error(function()
		Seashell.hash_table(bad_bool)
	end, "Invalid key type"),
	"hash_table: boolean key must raise an error"
)

-- Table key must be rejected.
local bad_tbl_key: Seashell.TableLike = { [{}] = 1 } :: Seashell.TableLike
assert(
	expect_error(function()
		Seashell.hash_table(bad_tbl_key)
	end, "Invalid key type"),
	"hash_table: table key must raise an error"
)

-- ─── Done ─────────────────────────────────────────────────────────────────────

print("All tests passed.")
