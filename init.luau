--!strict

-- Seashell: deterministic table-key hashing for Luau.
-- Two tables that share identical key structures (including nested tables)
-- will always produce the same hash, regardless of their values.

-- ─── Public types ─────────────────────────────────────────────────────────────

--- A key type that is accepted by the serialiser.
export type KeyType = string | number

--- The hex-encoded SHA-1 digest returned by the hashing functions.
export type HashResult = string

--- Any table whose keys and values are not yet known.
export type TableLike = { [unknown]: unknown }

-- ─── Internal types ───────────────────────────────────────────────────────────

-- Tracks tables that are on the current call stack to detect cyclic references.
type VisitedSet = { [TableLike]: boolean }

-- ─── SHA-1 constants ──────────────────────────────────────────────────────────

-- Initial hash word values (FIPS 180-4 §5.3.1).
local H0_INIT: number = 0x67452301
local H1_INIT: number = 0xEFCDAB89
local H2_INIT: number = 0x98BADCFE
local H3_INIT: number = 0x10325476
local H4_INIT: number = 0xC3D2E1F0

-- Round constants (FIPS 180-4 §4.2.1).
-- K_R1: floor(sqrt(2) × 2^30), rounds 1-20
local K_R1: number = 0x5A827999
-- K_R2: floor(sqrt(3) × 2^30), rounds 21-40
local K_R2: number = 0x6ED9EBA1
-- K_R3: floor(sqrt(5) × 2^30), rounds 41-60
local K_R3: number = 0x8F1BBCDC
-- K_R4: floor(sqrt(10) × 2^30), rounds 61-80
local K_R4: number = 0xCA62C1D6

-- Wrap-around modulus for 32-bit unsigned arithmetic.
local UINT32_MOD: number = 0x100000000

-- ─── SHA-1 implementation ─────────────────────────────────────────────────────

--- Converts a byte-value `n` at bit-shift `shift` into a single character.
local function extract_byte(n: number, shift: number): string
	return string.char(bit32.band(bit32.rshift(n, shift), 0xFF))
end

--- Pads `input` according to the SHA-1 specification and returns the full
--- padded message as a byte string.
local function pad_message(input: string): string
	local msg_len: number = #input
	local bit_len: number = msg_len * 8

	-- Append mandatory 0x80 byte then zero bytes until length ≡ 56 (mod 64).
	local msg: string = input .. "\x80"
	while #msg % 64 ~= 56 do
		msg = msg .. "\x00"
	end

	-- Append the original bit-length as a 64-bit big-endian integer.
	local high_bits: number = math.floor(bit_len / UINT32_MOD)
	local low_bits: number = bit_len % UINT32_MOD

	msg = msg
		.. extract_byte(high_bits, 24)
		.. extract_byte(high_bits, 16)
		.. extract_byte(high_bits, 8)
		.. extract_byte(high_bits, 0)
		.. extract_byte(low_bits, 24)
		.. extract_byte(low_bits, 16)
		.. extract_byte(low_bits, 8)
		.. extract_byte(low_bits, 0)

	return msg
end

--- Hashes `input` with SHA-1 and returns the 40-character hex digest.
local function hash_string(input: string): HashResult
	local h0: number = H0_INIT
	local h1: number = H1_INIT
	local h2: number = H2_INIT
	local h3: number = H3_INIT
	local h4: number = H4_INIT

	local msg: string = pad_message(input)

	-- Process every 64-byte (512-bit) chunk.
	for chunk_start: number = 1, #msg, 64 do
		local w: { number } = {}

		-- Load the first 16 big-endian 32-bit words from this chunk.
		for i: number = 0, 15 do
			local offset: number = chunk_start + i * 4
			w[i + 1] = bit32.bor(
				bit32.lshift(string.byte(msg, offset), 24),
				bit32.lshift(string.byte(msg, offset + 1), 16),
				bit32.lshift(string.byte(msg, offset + 2), 8),
				string.byte(msg, offset + 3)
			)
		end

		-- Extend to 80 words.
		for i: number = 17, 80 do
			w[i] = bit32.lrotate(bit32.bxor(w[i - 3], w[i - 8], w[i - 14], w[i - 16]), 1)
		end

		local a: number = h0
		local b: number = h1
		local c: number = h2
		local d: number = h3
		local e: number = h4

		-- 80 rounds split into four groups of 20.
		for i: number = 1, 80 do
			local f: number
			local k: number

			if i <= 20 then
				-- Rounds 1–20: Ch(b,c,d) = (b AND c) OR (NOT b AND d)
				f = bit32.bor(bit32.band(b, c), bit32.band(bit32.bnot(b), d))
				k = K_R1
			elseif i <= 40 then
				-- Rounds 21–40: Parity(b,c,d) = b XOR c XOR d
				f = bit32.bxor(b, c, d)
				k = K_R2
			elseif i <= 60 then
				-- Rounds 41–60: Maj(b,c,d) = (b AND c) OR (b AND d) OR (c AND d)
				f = bit32.bor(bit32.band(b, c), bit32.band(b, d), bit32.band(c, d))
				k = K_R3
			else
				-- Rounds 61–80: Parity(b,c,d) = b XOR c XOR d
				f = bit32.bxor(b, c, d)
				k = K_R4
			end

			-- All arithmetic kept within 32 bits via modulo.
			local temp: number = (bit32.lrotate(a, 5) + f + e + k + w[i]) % UINT32_MOD
			e = d
			d = c
			c = bit32.lrotate(b, 30)
			b = a
			a = temp
		end

		h0 = (h0 + a) % UINT32_MOD
		h1 = (h1 + b) % UINT32_MOD
		h2 = (h2 + c) % UINT32_MOD
		h3 = (h3 + d) % UINT32_MOD
		h4 = (h4 + e) % UINT32_MOD
	end

	return string.format("%08x%08x%08x%08x%08x", h0, h1, h2, h3, h4)
end

-- ─── Key serialisation ────────────────────────────────────────────────────────

--- Recursively serialises the *key structure* of `tbl` into a canonical string.
---
--- Format rules
--- * Keys at the same level are sorted lexicographically (by `tostring`) and
---   joined with `,`.
--- * A key whose value is itself a table is written as `key{<nested keys>}`.
--- * Only `string` and `number` keys are accepted; anything else is an error.
--- * `visited` tracks tables on the current call path so that cyclic
---   references are detected and reported before a stack overflow can occur.
local function serialize_keys(tbl: TableLike, visited: VisitedSet): string
	-- Cycle detection: if this table is already on the current call stack it
	-- means we have a cyclic reference and must stop immediately.
	if visited[tbl] then
		error("Cyclic reference detected in table structure")
	end

	-- Mark this table as part of the current path.
	visited[tbl] = true

	-- Collect keys, validating that each one is a string or number.
	local keys: { KeyType } = {}
	local typed_tbl: { [KeyType]: unknown } = tbl :: { [KeyType]: unknown }
	for k: unknown, _: unknown in tbl do
		local key_type: string = typeof(k)
		if key_type ~= "string" and key_type ~= "number" then
			-- Unmark before raising so the error is clean.
			visited[tbl] = nil
			error(`Invalid key type '{key_type}': only string and number keys are supported`)
		end
		table.insert(keys, k :: KeyType)
	end

	-- Sort keys lexicographically using their string representations so that
	-- the output is always in a deterministic order.
	table.sort(keys, function(a: KeyType, b: KeyType): boolean
		return tostring(a) < tostring(b)
	end)

	-- Build serialised parts for each key.
	local parts: { string } = {}
	for _, key: KeyType in keys do
		local value: unknown = typed_tbl[key]
		local key_str: string = tostring(key)

		if typeof(value) == "table" then
			-- Recurse into nested tables and wrap their keys in braces.
			local nested: string = serialize_keys(value :: TableLike, visited)
			table.insert(parts, key_str .. "{" .. nested .. "}")
		else
			table.insert(parts, key_str)
		end
	end

	-- Unmark this table so it can legitimately appear in other branches of the
	-- same top-level table (diamond-shaped references are not cycles).
	visited[tbl] = nil

	return table.concat(parts, ",")
end

-- ─── Public API ───────────────────────────────────────────────────────────────

--- Returns the canonical key-structure string for `tbl`.
---
--- The string is suitable for direct inspection or for passing to `hash_string`.
--- Raises an error on cyclic references or unsupported key types.
local function signature_of(tbl: TableLike): string
	local visited: VisitedSet = {}
	return serialize_keys(tbl, visited)
end

--- Returns the SHA-1 hash of the *key structure* of `tbl`.
---
--- Two tables that contain exactly the same keys (and the same nested-table
--- key structures) always produce the same hash, regardless of their values.
--- Raises an error on cyclic references or unsupported key types.
local function hash_table(tbl: TableLike): HashResult
	return hash_string(signature_of(tbl))
end

return {
	hash_string = hash_string,
	hash_table = hash_table,
	signature_of = signature_of,
}
