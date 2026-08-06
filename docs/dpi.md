# DPI Engine — how secrets and personal data are detected

## Architecture

```
Request body (string)
    |
    +-- Stage 1: scan_secrets()  --> SECRET
    |
    +-- Stage 2: scan_pii()      --> FIO, COMPANY, EMAIL, PHONE
    |
    +-- deduplicate() -> sort -> result
```

## Stage 1: Secret detection (3 methods)

### Method A — Aho-Corasick prefix dictionary

Fastest. O(n) over text length. Looks for key prefixes followed by a value.

```rust
static SECRET_PREFIXES: Lazy<AhoCorasick> = Lazy::new(|| {
    AhoCorasickBuilder::new().ascii_case_insensitive(true).build([
        "sk-",           // OpenAI/DeepSeek API keys
        "api_key",       // parameter names
        "token",         // JWT and access tokens
        "bearer",        // Authorization: Bearer xxx
        "password",      // passwords
        "access_token",  // OAuth tokens
    ])
});
```

How it works: finds `sk-` -> captures characters after until whitespace/quote/comma
(up to 64 chars) -> forms full match `sk-abc123...`. Minimum value length is 4 chars
(filters false positives).

### Method B — Regex key-value pairs

Catches patterns like `api_key=...` or `token: "..."`:

```rust
Regex::new(r#"(?i)(api_key|apikey|api-key|token|secret|password|bearer)
              \s*[:=]\s*["']?([a-zA-Z0-9_\-\.]{8,})"#)
```

How it works: finds key name -> optional whitespace -> `:` or `=` -> optional quotes
-> value >= 8 chars.

### Method C — Regex API keys

Catches keys in `sk-...` / `pk-...` format even without a prefix at the start:

```rust
Regex::new(r#"(?i)\b(sk|pk|api)-
              (?:[a-zA-Z0-9]{4,}-)?
              [a-zA-Z0-9_-]{8,}\b"#)
```

Word boundary -> prefix `sk-`/`pk-`/`api-` -> optional mid segment -> key body >= 8 chars.

## Stage 2: Personal data detection (4 types)

All 4 use compiled `Lazy<Regex>` — compiled once at startup, search-only afterwards.

### Full name (Russian) — `PII_FIO_REGEX`

```rust
Regex::new(r#"(?:[А-ЯЁ][а-яё]+        # Capitalized word    (Иван)
                \s+[А-ЯЁ][а-яё]+      # Second word         (Иванов)
                (?:\s+[А-ЯЁ][а-яё]+)?)"#)  # Patronymic (optional)
```

`[А-ЯЁ][а-яё]+` — uppercase letter + lowercase. Russian letters are 2 bytes in UTF-8
but regex handles them as regular characters.

### Company names — `PII_COMPANY_REGEX`

```rust
Regex::new(r#"(?i)\b(?:ООО|ЗАО|ОАО|АО|ИП|ПАО|НКО)  # Legal form
                \s+["«]?[А-ЯЁA-Z]                    # Space -> first letter of name
                [\w\s\-\.]{1,40}"#)                   # Rest of name (1-40 chars)
```

### Email — `PII_EMAIL_REGEX`

```rust
Regex::new(r#"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"#)
```

Standard email pattern. No Cyrillic — email is always ASCII.

### Phone (Russian) — `PII_PHONE_REGEX`

```rust
Regex::new(r#"(?:\+7|8)                     # +7 or 8
                \s*[\(]?\d{3}[\)]?          # carrier code (999)
                \s*\d{3}[\s-]?\d{2}[\s-]?\d{2}"#)  # number (123-45-67)
```

## Deduplication

After both stages, detections may overlap (e.g., `sk-abc` found by both
Aho-Corasick and API_KEY_REGEX). Deduplicator removes nested matches, keeping
the outer one:

```rust
fn deduplicate(detections: &mut Vec<Detection>) {
    // For each pair: if intervals overlap, remove the second
    // Simple O(n^2) — sufficient for n < 20
}
```

## What happens to detected data

### Masking mode (legacy, no Redis)

```
sk-1234567890abcdef -> sk-1234***-cdef     (first 4 + *** + last 4)
Иван Иванов         -> Иван И***            (first word + first letter + ***)
ООО Ромашка         -> ООО Р***             (legal form + first letter + ***)
user@company.com    -> u***@c***.com        (anonymized)
+7 999 123-45-67    -> +7 ***-**-4567       (last 4 preserved)
```

Rules:
- Secrets: preserve first 4 and last 4 chars of the value part
- FIO: keep first word fully, others — first letter + ***
- Company: keep legal form, name — first letter + ***
- Email: keep first letter of local part and domain
- Phone: keep prefix and last 4 digits

### Tokenization mode (new, deterministic token)

```
sk-1234567890abcdef -> [KEY_a3f2b1]   (SHA256(value + session_id)[:6])
Иван Иванов         -> [FIO_9b2c7d]
ООО Ромашка         -> [ORG_1c4e8a]
user@company.com    -> [EML_d5f7b3]
+7 999 123-45-67    -> [PHN_e8a1c5]
```

Tokens are deterministic: same value + same session = always same token.
This guarantees consistency — if a user sends `sk-abc` twice in one session,
the AI sees `[KEY_a3f2b1]` both times.

Token format: `[PREFIX_hash6]` where hash6 = first 6 chars of SHA256 hex.
Prefix mapping:
- KEY = Secret (API keys, tokens, passwords)
- FIO = Full name
- ORG = Company/organization
- EML = Email
- PHN = Phone

## Performance

| Method | Complexity | Throughput |
|:-------|:-----------|:-----------|
| Aho-Corasick | O(n) | ~500 MB/s |
| Regex (5 patterns) | O(n) each | ~100 MB/s total |
| SHA256 (tokenization) | O(n) | ~200 MB/s |
| **Total** | **O(n)** | **~50 MB/s** |

On a typical JSON request of 1-10 KB — detection time < 1 ms.
