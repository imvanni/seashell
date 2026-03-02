--!strict

-- Seashell: deterministic table-key hashing for Luau.
-- Two tables that share identical key structures (including nested tables)
-- will always produce the same hash, regardless of their values.

-- ─── Public types ─────────────────────────────────────────────────────────────

--- A key type that is accepted by the serialiser.
export type KeyType = string | number

--- The hex-encoded SHA-1 digest returned by the hashing functions.
export type HashResult = string

--- Any table whose keys may be strings or numbers.
export type TableLike = { [any]: any }

-- ─── Internal types ───────────────────────────────────────────────────────────

-- Tracks tables that are on the current call stack to detect cyclic references.
type VisitedSet = { [TableLike]: boolean }

-- ─── SHA-1 implementation ─────────────────────────────────────────────────────

--- Converts a byte-value `n` at bit-shift `shift` into a single character.
local function extractByte(n: number, shift: number): string
	return string.char(bit32.band(bit32.rshift(n, shift), 0xFF))
end

--- Pads `input` according to the SHA-1 specification and returns the full
--- padded message as a byte string.
local function padMessage(input: string): string
	local msgLen: number = #input
	local bitLen: number = msgLen * 8

	-- Append mandatory 0x80 byte then zero bytes until length ≡ 56 (mod 64).
	local msg: string = input .. "\x80"
	while #msg % 64 ~= 56 do
		msg = msg .. "\x00"
	end

	-- Append the original bit-length as a 64-bit big-endian integer.
	local highBits: number = math.floor(bitLen / 0x100000000)
	local lowBits: number = bitLen % 0x100000000

	msg = msg
		.. extractByte(highBits, 24)
		.. extractByte(highBits, 16)
		.. extractByte(highBits, 8)
		.. extractByte(highBits, 0)
		.. extractByte(lowBits, 24)
		.. extractByte(lowBits, 16)
		.. extractByte(lowBits, 8)
		.. extractByte(lowBits, 0)

	return msg
end

--- Hashes `input` with SHA-1 and returns the 40-character hex digest.
local function hashString(input: string): HashResult
	-- Initial hash values.
	local h0: number = 0x67452301
	local h1: number = 0xEFCDAB89
	local h2: number = 0x98BADCFE
	local h3: number = 0x10325476
	local h4: number = 0xC3D2E1F0

	local msg: string = padMessage(input)

	-- Process every 64-byte (512-bit) chunk.
	for chunkStart: number = 1, #msg, 64 do
		local w: { number } = {}

		-- Load the first 16 big-endian 32-bit words from this chunk.
		for i: number = 0, 15 do
			local offset: number = chunkStart + i * 4
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
				-- K = floor(sqrt(2) × 2^30)
				f = bit32.bor(bit32.band(b, c), bit32.band(bit32.bnot(b), d))
				k = 0x5A827999
			elseif i <= 40 then
				-- Rounds 21–40: Parity(b,c,d) = b XOR c XOR d
				-- K = floor(sqrt(3) × 2^30)
				f = bit32.bxor(b, c, d)
				k = 0x6ED9EBA1
			elseif i <= 60 then
				-- Rounds 41–60: Maj(b,c,d) = (b AND c) OR (b AND d) OR (c AND d)
				-- K = floor(sqrt(5) × 2^30)
				f = bit32.bor(bit32.band(b, c), bit32.band(b, d), bit32.band(c, d))
				k = 0x8F1BBCDC
			else
				-- Rounds 61–80: Parity(b,c,d) = b XOR c XOR d
				-- K = floor(sqrt(10) × 2^30)
				f = bit32.bxor(b, c, d)
				k = 0xCA62C1D6
			end

			-- All arithmetic kept within 32 bits via modulo.
			local temp: number = (bit32.lrotate(a, 5) + f + e + k + w[i]) % 0x100000000
			e = d
			d = c
			c = bit32.lrotate(b, 30)
			b = a
			a = temp
		end

		h0 = (h0 + a) % 0x100000000
		h1 = (h1 + b) % 0x100000000
		h2 = (h2 + c) % 0x100000000
		h3 = (h3 + d) % 0x100000000
		h4 = (h4 + e) % 0x100000000
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
local function serializeKeys(tbl: TableLike, visited: VisitedSet): string
	-- Cycle detection: if this table is already on the current call stack it
	-- means we have a cyclic reference and must stop immediately.
	if visited[tbl] then
		error("Cyclic reference detected in table structure")
	end

	-- Mark this table as part of the current path.
	visited[tbl] = true

	-- Collect keys, validating that each one is a string or number.
	local keys: { KeyType } = {}
	local typedTbl: { [KeyType]: any } = tbl :: { [KeyType]: any }
	for k: any, _: any in pairs(tbl) do
		local keyType: string = typeof(k)
		if keyType ~= "string" and keyType ~= "number" then
			-- Unmark before raising so the error is clean.
			visited[tbl] = nil
			error(`Invalid key type '{keyType}': only string and number keys are supported`)
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
	for _, key: KeyType in ipairs(keys) do
		local value: any = typedTbl[key]
		local keyStr: string = tostring(key)

		if typeof(value) == "table" then
			-- Recurse into nested tables and wrap their keys in braces.
			local nested: string = serializeKeys(value :: TableLike, visited)
			table.insert(parts, keyStr .. "{" .. nested .. "}")
		else
			table.insert(parts, keyStr)
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
--- The string is suitable for direct inspection or for passing to `hashString`.
--- Raises an error on cyclic references or unsupported key types.
local function signatureOf(tbl: TableLike): string
	local visited: VisitedSet = {}
	return serializeKeys(tbl, visited)
end

--- Returns the SHA-1 hash of the *key structure* of `tbl`.
---
--- Two tables that contain exactly the same keys (and the same nested-table
--- key structures) always produce the same hash, regardless of their values.
--- Raises an error on cyclic references or unsupported key types.
local function hashTable(tbl: TableLike): HashResult
	return hashString(signatureOf(tbl))
end

return {
	hashString = hashString,
	hashTable = hashTable,
	signatureOf = signatureOf,
}
