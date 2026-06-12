---
name: business-logic
description: >-
  Business logic vulnerability playbook. Use when reasoning about workflows, race conditions, price manipulation, coupon abuse, state machines, and multi-step authorization gaps.
---

# SKILL: Business Logic Vulnerabilities — Expert Attack Playbook

> **AI LOAD INSTRUCTION**: Business logic flaws are scanner-invisible and high-reward on bug bounty. This skill covers race conditions, price manipulation, workflow bypass, coupon/referral abuse, negative values, and state machine attacks. These require human reasoning, not automation. For specific exploitation techniques (payment precision/overflow, captcha bypass, password reset flaws, user enumeration), load the companion [SCENARIOS.md](./SCENARIOS.md).

### Extended Scenarios

Also load [SCENARIOS.md](./SCENARIOS.md) when you need:
- Payment precision & integer overflow attacks — 32-bit overflow to negative, decimal rounding exploitation, negative shipping fees
- Payment parameter tampering checklist — price, discount, currency, gateway, return_url fields
- Condition race practical patterns — parallel coupon application, gift card double-spend with Burp group send
- Captcha bypass techniques — drop verification request, remove parameter, clear cookies to reset counter, OCR with tesseract
- Arbitrary password reset — predictable tokens (`md5(username)`), session replacement attack, registration overwrite
- User information enumeration — login error message difference, masked data reconstruction across endpoints, base64 uid cookie manipulation
- Frontend restriction bypass — array parameters for multiple coupons (`couponid[0]`/`couponid[1]`), remove `disabled`/`readonly` attributes
- Application-layer DoS patterns — regex backtracking, WebSocket abuse

## QUICK START

### First-pass probes

| Signal | Probe | Why |
|---|---|---|
| Checkout / payment flow | Set price=0 or quantity=-1 | Negative/zero value bypass |
| Coupon / promo code | Reuse code, stack multiple codes | One-time-use enforcement gap |
| Multi-step form | Skip steps via direct URL access | Workflow state not validated |
| File / resource access | Modify ID in URL parameter | IDOR on business objects |
| Rate-limited action | Send 10 concurrent requests | Race condition on one-time ops |
| Profile / settings | Add role=admin to request body | Mass assignment |
| Referral / invite | Use own referral code | Self-referral loop |

---

## 1. PRICE AND VALUE MANIPULATION

### Negative Quantity / Price
Many applications validate "amount > 0" but not for currency:
```
Add to cart with quantity: -1
Update quantity to: -100
{
  "quantity": -5,
  "price": -99.99     ← may be accepted
}
```
**Impact**: Receive credit to account, items for free, bank transfers in reverse.

### Integer Overflow
```
quantity: 2147483648   ← INT_MAX + 1 overflows to negative in 32-bit
price: 9999999999999   ← exceeds float precision → rounds to 0
```

### Rounding Manipulation
```
Item price: $0.001
Order 1000 items → each rounds down → total = $0.00
```

### Currency Exchange Rate Lag
```
1. Deposit using currency A at rate X
2. Rate changes
3. Withdraw using currency A at new rate → profit from rate difference
```

### Free Upgrade via Promo Stacking
Test combining discount codes, referral credits, welcome bonuses:
```
Apply promo: FREE50  → 50% off
Apply promo: REFER10 → additional 10%
Apply loyalty points → additional discount
Total: -$5 (free + credit)
```

---

## 2. RACE CONDITIONS

**Concept**: Two operations run simultaneously before the first completes its check-update cycle.

### Double-Spend / Double-Redeem
```bash
# Send same request simultaneously (~millisecond apart):
# Use Burp Repeater "Send to Group" or Race Conditions tool:

POST /api/use-coupon    ← send 20 parallel requests
POST /api/redeem-gift   ← same coupon code, parallel
POST /api/withdraw-funds ← same balance, parallel

# If check and update are non-atomic:
# Thread 1: check(balance >= 100) → TRUE
# Thread 2: check(balance >= 100) → TRUE (before Thread 1 deducted)
# Thread 1: balance -= 100
# Thread 2: balance -= 100 → BOTH succeed → double-spend
```

### Race Condition Test with Burp Suite
```
1. Capture request
2. Send to Repeater → duplicate 20+ times
3. "Send group in parallel" (Burp 2023+)
4. Check: did any duplicate succeed?
```

### Account Registration Race
```
Register with same email simultaneously → two accounts created → data isolation broken
Password reset token race → reuse same token twice
Email verification race → verify multiple email addresses
```

### Limit Bypass via Race
```
"Claim once" discounts, freebies, "first order" bonus:
→ Send 10 parallel POST /claim requests
→ Race window: all pass the "already claimed?" check before any write
```

---

## 3. WORKFLOW / STEP SKIP BYPASS

### Payment Flow Bypass
```
Normal flow:
  1. Add to cart
  2. Enter shipping info
  3. Enter payment (card/wallet)
  4. Click confirm → payment charged
  5. Order confirmed

Attack: Skip to step 5 directly
POST /api/orders/confirm {"cart_id": "1234", "payment_status": "paid"}
→ Does server trust client-sent payment_status?
```

### Multi-Step Verification Skip
```
Password reset flow:
  1. Enter email
  2. Receive token
  3. Enter token
  4. Set new password (requires valid token from step 3)

Attack: Try going to step 4 without completing step 3:
POST /reset/password {"email": "victim@x.com", "token": "invalid", "new_pass": "hacked"}
→ Does server check that token was properly validated?

Or: Try token from old/expired flow → still accepted?
```

### 2FA Bypass
```
Normal flow:
  1. Enter username + password → success
  2. Enter 2FA code → logged in

Attack: After step 1 success, go directly to /dashboard
→ Is session created before 2FA completes?
→ Does /dashboard require 2FA-complete check or just "authenticated" flag?
```

### Shipping Without Payment
```
  1. Add item to cart
  2. Enter shipping address
  3. Select payment method (credit card)
  4. Apply promo code (100% discount or gift card)  
  5. Final amount: $0
  6. Order placed

Attack: Apply 100% discount code → no actual payment processed → item ships
```

---

## 4. COUPON AND REFERRAL ABUSE

### Coupon Stacking
```
Test: Can you apply multiple coupon codes?
Test: Does "SAVE20" + promo stack to >100%?
Test: Apply coupon, remove item, keep discount applied, add different item
```

### Referral Loop
```
1. Create Account_A
2. Register Account_B with Account_A's referral code → both get credit
3. Create Account_C with Account_B's referral code
4. Ad infinitum with throwaway emails
→ Infinite credit generation
```

### Coupon = Fixed Dollar Amount on Variable-Price Item
```
Coupon: -$5 off any order
Buy item worth $3, use -$5 coupon → net -$2 (credit balance)
```

---

## 5. ACCOUNT / PRIVILEGE LOGIC FLAWS

### Email Verification Bypass
```
1. Register with email A (legitimate, verified)
2. Change email to B (attacker's email, unverified)
3. Use account as verified — does server enforce re-verification?

Or: Change email to victim's email → no verification → account claim
```

### Password Reset Token Binding
```
1. Request password reset for your account → get token
2. Change your email address (account settings)
3. Reuse old password reset token → does it still work for old email?

Or: Request reset for victim@target.com
    Token sent to victim but check: does URL reveal predictable token pattern?
```

### OAuth Account Linking Abuse
```
1. Have victim's email (but not their password)
2. Register with victim's email → get account with same email
3. Link OAuth (Google/GitHub) to your account
4. Victim logs in with Google → server finds email match → merges with YOUR account
```

---

## 6. API BUSINESS LOGIC FLAWS

### Object State Manipulation
```
order.status = "pending"
→ PUT /api/orders/1234 {"status": "refunded"}   ← self-trigger refund
→ PUT /api/orders/1234 {"status": "shipped"}    ← mark as shipped without shipping
```

### Transaction Reuse
```
1. Initiate payment → get transaction_id
2. Complete purchase
3. Reuse same transaction_id for second purchase:
   POST /api/checkout {"transaction_id": "USED_TX", "cart": "new_cart"}
```

### Limit Count Manipulation
```
Daily transfer limit = $1000
→ Transfer $999, cancel, transfer $999 (limit not updated on cancel)
→ Parallel transfers (race condition on limit check)
→ Different payment types not sharing limit counter
```

---

## 7. SUBSCRIPTION / TIER CONFUSION

```
Free tier: cannot access feature X
Paid tier: can access feature X

Attack: 
- Sign up for paid trial → enable feature X → downgrade to free
  → Does feature X get disabled on downgrade? 
  → Can you continue using feature X?

Or:
- Inspect premium endpoint list from JS bundle
- Directly call premium endpoints with free account token
→ Server checks subscription for UI but not API?
```

---

## 8. FILE UPLOAD BUSINESS LOGIC

For the full upload attack workflow beyond pure logic flaws, also load:

- [upload insecure files](../file-upload/SKILL.md)

```
Upload size limit: 10MB
→ Upload 10MB → compress client-side → server decompresses → bomb?
(Zip bomb: 1KB zip → 1GB file = denial of service)

Upload type restriction:
→ Upload .csv for "data import" → inject formulas: =SYSTEM("calc")
  (CSV injection in Excel macro context)
→ Upload avatar → server converts → attack converter (ImageMagick, FFmpeg CVEs)

Storage path prediction:
→ /uploads/USER_ID/filename
→ Can you overwrite other user's file by knowing their ID + filename?
```

---

## DECISION TREE

```
Business flow mapped (happy path documented)?
├── Price / value manipulation?
│   ├── Negative quantity or price → receive credit or free items
│   ├── Integer overflow (2147483648) → wraps to negative
│   ├── Rounding exploitation → fractional amounts round to zero
│   └── Currency exchange lag → profit from rate differences
├── Quantity / limit abuse?
│   ├── Multiple coupon stacking → exceeds 100% discount
│   ├── Referral loop → infinite credit generation
│   ├── Rate limit bypass via parallel requests
│   └── Limit not updated on cancellation
├── Race condition?
│   ├── Double-spend (coupon, gift card, withdrawal) → send parallel
│   ├── Account registration race → duplicate accounts
│   └── Limit bypass (claim once) → all pass check before write
├── Privilege escalation?
│   ├── Modify status field directly (order.status = "refunded")
│   ├── Premium features accessible after downgrade
│   ├── Direct API call bypasses subscription check
│   └── Email change without re-verification → account claim
└── Workflow bypass?
    ├── Skip payment step → go to order confirmation directly
    ├── Skip 2FA step → access dashboard after password only
    ├── Skip token validation in password reset
    └── Transaction ID reuse for second purchase
```

## 10. TESTING APPROACH

```
For each business process:
1. Map the INTENDED flow (happy path)
2. Ask: "What if I skip step N?"
3. Ask: "What if I send negative/zero/MAX values?"
4. Ask: "What if I repeat this step twice?" (idempotency)
5. Ask: "What happens if I do A then B instead of B then A?"
6. Ask: "What if two users do this simultaneously?"
7. Ask: "Can I modify the 'trusted' status fields?"
8. Think from financial/resource impact angle → highest bounty
```

---

## 11. HIGH-IMPACT CHECKLISTS

### E-commerce / Payment
```
□ Negative quantity in cart
□ Apply multiple conflicting coupons
□ Race condition: double-spend gift card
□ Skip payment step directly to order confirmation  
□ Refund without return (trigger refund on delivered item via state change)
□ Currency rounding exploitation
```

### Authentication / Account
```
□ 2FA bypass by direct URL access after password step
□ Password reset token reuse after email change
□ Email verification bypass (change email after verification)
□ OAuth account takeover via email match
□ Register with existing unverified email
```

### Subscriptions / Limits
```
□ Access premium features after downgrade
□ Exceed rate/usage limits via parallel requests
□ Referral loop for infinite credits
□ Free trial ≠ time-limited (no enforcement after trial)
□ Direct API call to premium endpoint without subscription check
```

---

## TESTING CHECKLIST

- [ ] Identify all business-critical workflows (checkout, transfer, refund, discount)
- [ ] Test price/quantity/currency manipulation on each workflow
- [ ] Test race conditions on one-time-use operations (coupon, transfer, vote)
- [ ] Test state machine transitions (skip steps, replay steps, reverse flows)
- [ ] Test privilege escalation through workflow parameter tampering
- [ ] Test multi-step authorization gaps (step A authorized but step B isn't rechecked)
- [ ] Test negative quantities, zero-value items, floating-point rounding
- [ ] Test referral/promo code abuse (self-referral, reuse, stacking)
- [ ] Test account-level logic (tier bypass, subscription skip, trial extension)
- [ ] Test data validation consistency between client and server

## MCP TOOLS

| Tool | Use Case |
|------|----------|
| `http_framework_test` | Send crafted requests to test price manipulation, negative values, and workflow bypass |
| `http_repeater` | Replay and modify business logic requests to test race conditions and step skipping |
| `browser_agent_inspect` | Browser inspection to observe client-side state changes and business flow enforcement |
| `burpsuite_alternative_scan` | Comprehensive web scanning to discover business logic endpoints and API surfaces |
| `api_fuzzer` | Fuzz API parameters to find hidden business logic flaws and undocumented endpoints |

## RELATED ROUTING

- [race-condition](../race-condition/SKILL.md) — Race conditions are core to many business logic exploits
- [idor](../idor/SKILL.md) — IDOR often found in business object access flows
- [authbypass](../authentication-bypass/SKILL.md) — Auth bypass in multi-step workflows
- [sqli](../sqli/SKILL.md) — SQLi can manipulate business data and prices
- [recon](../recon-and-methodology/SKILL.md) — Recon uncovers business endpoints and API surfaces
