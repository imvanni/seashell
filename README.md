# seashell

A Luau module that produces a deterministic **SHA-1 hash of a table's key structure**.

Two tables that share identical keys — including nested table keys — always produce
the same hash, regardless of their values.

---

## API

```luau
local Seashell = require(path.to.seashell)

-- Hash a plain string.
local digest: string = Seashell.hashString("hello world")
-- → "2aae6c69..."

-- Get the canonical key-structure string of a table.
local sig: string = Seashell.signatureOf({ name = "Ann", age = 30 })
-- → "age,name"

-- Hash a table's key structure.
local hash: string = Seashell.hashTable({
    name   = "Ann",
    age    = 30,
    address = {
        city = "New York",
        zip  = "10001",
    },
})
-- → SHA-1 of "address{city,zip},age,name"
```

### Exported types

| Type | Description |
|---|---|
| `KeyType` | `string \| number` — the only accepted key types |
| `HashResult` | `string` — a 40-character lowercase hex SHA-1 digest |
| `TableLike` | `{ [any]: any }` — any table passed to the module |

---

## Behaviour

| Feature | Detail |
|---|---|
| **Key ordering** | Keys are sorted lexicographically (`tostring`) so the result is always deterministic |
| **Nested tables** | Represented as `key{nested,keys}` in the canonical string |
| **Values ignored** | Only keys (and whether a value is itself a table) affect the hash |
| **Cyclic references** | Detected and raised as an error before a stack overflow can occur |
| **Invalid key types** | Any key that is not a `string` or `number` raises an error |
| **Hash algorithm** | Pure-Luau SHA-1 via the `bit32` library |

---

## Serialisation format

Given the table

```luau
{
    name    = "Ann",
    age     = 30,
    address = { city = "New York", zip = "10001" },
}
```

the canonical string is:

```
address{city,zip},age,name
```

Keys at the same level are separated by `,`; nested table keys are wrapped in `{…}`.
This string is then SHA-1 hashed to produce the final digest.
