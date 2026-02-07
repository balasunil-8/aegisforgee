# A04: Insecure Design

## 🎯 Overview

### What is Insecure Design?

Insecure Design represents a broad category of security weaknesses where missing or ineffective control design creates vulnerabilities. This is different from insecure implementation - even perfect code cannot fix a fundamentally flawed design.

**Key Distinction:**
- **Insecure Design**: The blueprint itself is flawed (missing security controls in the architecture)
- **Insecure Implementation**: The blueprint is good, but the code has bugs

### Why Does It Matter?

Insecure design flaws are particularly dangerous because:

1. **Cannot be patched easily**: You can't fix a design flaw with a code patch - you need architectural changes
2. **Business logic exploitation**: Attackers exploit the intended functionality, not bugs
3. **Hard to detect**: Security scanners won't find design flaws - they're "working as designed"
4. **Wide impact**: One design flaw can affect multiple features

### Real-World Impact Examples

**1. Knight Capital Group (2012) - $440 Million Loss**
- **Flaw**: Missing deployment controls and rollback mechanism
- **Impact**: Faulty trading algorithm deployed to production, caused 45-minute chaos
- **Root Cause**: Insecure design - no staged rollout, no kill switch, no anomaly detection
- **Result**: Company lost $440M and was acquired

**2. British Airways (2018) - 380,000 Customers Affected**
- **Flaw**: Payment card data sent to attacker's server
- **Impact**: £20 million GDPR fine, major reputation damage
- **Root Cause**: Lack of subresource integrity checks (insecure design in third-party script loading)

**3. Robinhood SMS Bypass (2020)**
- **Flaw**: Account recovery didn't verify ownership beyond SMS
- **Impact**: Accounts takeover, unauthorized trading
- **Root Cause**: Insecure authentication workflow design

### OWASP Ranking and Severity

- **OWASP Top 10 2021**: #4 (NEW ENTRY)
- **OWASP Top 10 2025**: #4 (MAINTAINED)
- **Severity**: HIGH to CRITICAL
- **Likelihood**: COMMON
- **CWEs Mapped**: 73 CWEs including:
  - CWE-209: Generation of Error Message Containing Sensitive Information
  - CWE-256: Plaintext Storage of Password
  - CWE-501: Trust Boundary Violation
  - CWE-522: Insufficiently Protected Credentials

---

## 🔧 Technical Details

### How Does Insecure Design Work?

Insecure design vulnerabilities occur when security requirements are not properly considered during the design phase. Common patterns include:

#### 1. Race Conditions

**What is it?**
When multiple operations compete to access/modify shared resources without proper synchronization.

**Technical Explanation:**
```python
# VULNERABLE CODE
balance = get_balance(user_id)  # Step 1: Check
if balance >= price:             # Step 2: Verify
    # ⚠️ RACE WINDOW: Another request can execute here!
    time.sleep(0.1)              # Processing delay
    balance -= price             # Step 3: Update
    update_balance(user_id, balance)
```

**The Problem:**
- Thread A checks balance: $100 ≥ $60 ✓
- Thread B checks balance: $100 ≥ $60 ✓
- Thread A deducts: $100 - $60 = $40
- Thread B deducts: $100 - $60 = $40 (should be $40 - $60 = overdraft!)
- Result: User made $120 in purchases with only $100

#### 2. Workflow Bypass

**What is it?**
Missing validation of business process state transitions.

**Technical Explanation:**
```python
# VULNERABLE: No workflow state validation
def confirm_order(order_id):
    order = get_order(order_id)
    # ⚠️ Never checks if payment completed!
    order.status = 'confirmed'
    ship_items(order)
```

**The Problem:**
Expected workflow: Create → Pay → Confirm
Actual workflow: Create → Confirm (payment skipped!)

#### 3. Trust Boundary Violations

**What is it?**
Trusting data from untrusted sources (usually the client).

**Technical Explanation:**
```python
# VULNERABLE: Trust client-provided price
def purchase(request):
    price = request.json['price']  # ⚠️ Client controls price!
    is_premium = request.json['is_premium']  # ⚠️ Client claims premium!
    
    if is_premium:
        price *= 0.5  # Premium discount
    
    charge_user(price)  # Charge manipulated price
```

**The Problem:**
Client sends: `{"price": 0.01, "is_premium": true}`
Server charges: $0.01 * 0.5 = $0.005 for a $1000 laptop!

#### 4. Missing Resource Limits

**What is it?**
No rate limiting, size limits, or resource quotas.

**Technical Explanation:**
```python
# VULNERABLE: No limits
def process_data(request):
    data = request.json['data']  # ⚠️ Could be 10GB array!
    
    results = []
    for item in data:  # ⚠️ Could be millions of items!
        for i in range(1000000):  # ⚠️ Expensive operation!
            results.append(compute(item))
    
    return results
```

**The Problem:**
- Attacker sends array with 10,000 items
- Each item triggers 1 million operations
- Total: 10 billion operations
- Result: Server CPU at 100%, legitimate users locked out (DoS)

---

## 🎯 Attack Vectors

### 1. Race Condition Exploitation

**Attack Method: Simultaneous Requests**

```bash
# Send 10 simultaneous purchase requests
for i in {1..10}; do
    curl -X POST http://target/api/red/insecure-design/race-condition \
         -H "Content-Type: application/json" \
         -d '{"user_id": 1, "item_id": 101, "price": 999.99}' &
done
wait

# Result: All 10 requests succeed even if balance is only $1000
# User gets $10,000 worth of items for $1000
```

**Why It Works:**
Each request checks the balance before others deduct it.

### 2. Workflow Bypass

**Attack Method: Skip Payment Step**

```bash
# Step 1: Create order
ORDER_ID=$(curl -X POST http://target/api/red/insecure-design/workflow-bypass \
           -H "Content-Type: application/json" \
           -d '{"action": "create", "user_id": 1, "items": ["laptop"], "total": 999.99}' \
           | jq -r '.order.order_id')

# Step 2: Skip payment! Go directly to confirm
curl -X POST http://target/api/red/insecure-design/workflow-bypass \
     -H "Content-Type: application/json" \
     -d "{\"action\": \"confirm\", \"order_id\": \"$ORDER_ID\"}"

# Result: Order confirmed without payment!
```

### 3. Price Manipulation

**Attack Method: Client-Side Price Control**

```bash
# Normal price: $999.99
# Attacker's price: $0.01
curl -X POST http://target/api/red/insecure-design/trust-boundary \
     -H "Content-Type: application/json" \
     -d '{
           "user_id": 2,
           "item_name": "Laptop",
           "price": 0.01,
           "is_premium": true,
           "discount": 99
         }'

# Result: Laptop purchased for $0.01 * (1 - 0.99) * 0.5 = $0.00005
```

### 4. Resource Exhaustion

**Attack Method: Denial of Service**

```bash
# Send huge payload
python3 << 'EOF'
import requests
import json

huge_array = ['x' * 1000] * 100000  # 100MB payload

response = requests.post(
    'http://target/api/red/insecure-design/missing-limits',
    json={
        'operation': 'expensive_compute',
        'data': huge_array
    }
)
print(response.json())
EOF

# Result: Server CPU/memory exhausted, legitimate users blocked
```

---

## 🛡️ Defense Mechanisms

### 1. Race Condition Prevention

**Secure Design Patterns:**

```python
# SECURE: Idempotency + Atomic Operations
import threading

account_lock = threading.Lock()
processed_requests = {}

def secure_purchase(request):
    idempotency_key = request.json['idempotency_key']
    
    # Check if already processed
    if idempotency_key in processed_requests:
        return processed_requests[idempotency_key]
    
    # Atomic operation with lock
    with account_lock:
        balance = get_balance(user_id)
        if balance < price:
            return {'error': 'Insufficient balance'}
        
        # Update happens inside the same lock
        new_balance = balance - price
        update_balance(user_id, new_balance)
        
        result = {'order_id': create_order(), 'balance': new_balance}
        processed_requests[idempotency_key] = result
        return result
```

**Key Controls:**
1. **Idempotency Keys**: Prevent duplicate processing
2. **Locks/Mutexes**: Ensure atomic check-and-update
3. **Database Transactions**: Use `BEGIN TRANSACTION ... COMMIT`
4. **Optimistic Locking**: Version numbers to detect concurrent modifications

### 2. Workflow State Validation

**Secure Design Patterns:**

```python
# SECURE: State Machine with Validation
class OrderStateMachine:
    STATES = ['created', 'paid', 'confirmed', 'shipped']
    ALLOWED_TRANSITIONS = {
        'created': ['paid', 'cancelled'],
        'paid': ['confirmed', 'refunded'],
        'confirmed': ['shipped'],
        'shipped': []
    }
    
    def transition(self, order, new_state):
        current_state = order.workflow_state
        
        # Validate transition is allowed
        if new_state not in self.ALLOWED_TRANSITIONS.get(current_state, []):
            raise InvalidStateTransition(
                f"Cannot transition from {current_state} to {new_state}"
            )
        
        # Additional validation for specific transitions
        if new_state == 'confirmed':
            if order.payment_status != 'paid':
                raise PaymentRequired("Order must be paid before confirmation")
        
        order.workflow_state = new_state
        order.save()
```

**Key Controls:**
1. **State Machine**: Define valid states and transitions
2. **Validation Rules**: Check prerequisites for each transition
3. **Immutability**: Once confirmed, order cannot be modified
4. **Audit Trail**: Log all state transitions

### 3. Server-Side Validation

**Secure Design Patterns:**

```python
# SECURE: Never Trust Client Data
PRODUCT_CATALOG = {
    101: {'name': 'Laptop', 'price': 999.99},
    102: {'name': 'Mouse', 'price': 29.99}
}

USER_PREMIUM_STATUS = {
    1: True,
    2: False
}

def secure_purchase(request):
    user_id = request.json['user_id']
    product_id = request.json['product_id']
    
    # ✓ Get price from server-side catalog
    if product_id not in PRODUCT_CATALOG:
        return {'error': 'Invalid product'}
    
    product = PRODUCT_CATALOG[product_id]
    base_price = product['price']  # Server decides price
    
    # ✓ Check premium status server-side
    is_premium = USER_PREMIUM_STATUS.get(user_id, False)
    
    # ✓ Calculate discount server-side
    discount = 0.15 if is_premium else 0
    final_price = base_price * (1 - discount)
    
    # ✓ Apply business rules (max discount cap)
    final_price = max(final_price, base_price * 0.5)  # At most 50% off
    
    return charge_user(user_id, final_price)
```

**Key Controls:**
1. **Server-Side Catalog**: Price, inventory from database
2. **Server-Side Authorization**: Check user permissions server-side
3. **Server-Side Calculation**: Compute totals, discounts, taxes server-side
4. **Business Rule Enforcement**: Apply constraints (min/max values)

### 4. Resource Limits and Rate Limiting

**Secure Design Patterns:**

```python
# SECURE: Comprehensive Resource Limits
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

limiter = Limiter(
    app,
    key_func=get_remote_address,
    default_limits=["100 per hour"]
)

@app.route('/api/process')
@limiter.limit("10 per minute")  # Rate limit
def process_data():
    data = request.get_json()
    
    # ✓ Input size validation
    if len(data.get('items', [])) > 1000:
        return {'error': 'Too many items (max 1000)'}, 400
    
    # ✓ Timeout for operations
    import signal
    signal.alarm(5)  # 5 second timeout
    
    try:
        result = expensive_operation(data)
    except TimeoutError:
        return {'error': 'Operation timeout'}, 408
    
    # ✓ Output size limit
    if len(result) > 10000:
        result = result[:10000]
    
    return {'result': result}
```

**Key Controls:**
1. **Rate Limiting**: Requests per minute/hour per user/IP
2. **Input Validation**: Max size, max count, data type checks
3. **Operation Timeouts**: Prevent long-running operations
4. **Resource Quotas**: Memory limits, CPU time limits
5. **Pagination**: Break large datasets into chunks

---

## 🧪 AegisForge Labs

### Red Team Endpoints (Vulnerable)

#### 1. Race Condition

```bash
# Test race condition with parallel requests
endpoint="http://localhost:5000/api/red/insecure-design/race-condition"

# Send 5 parallel purchase requests
for i in {1..5}; do
    curl -X POST $endpoint \
         -H "Content-Type: application/json" \
         -d '{"user_id": 1, "item_id": 101, "price": 300.00, "action": "purchase"}' &
done
wait

# Check balance - should be negative or incorrectly calculated
```

#### 2. Workflow Bypass

```bash
# Skip payment and confirm order
endpoint="http://localhost:5000/api/red/insecure-design/workflow-bypass"

# Create order
order=$(curl -X POST $endpoint \
        -H "Content-Type: application/json" \
        -d '{"action": "create", "user_id": 1, "items": ["laptop"], "total": 999.99}')

order_id=$(echo $order | jq -r '.order.order_id')

# Skip payment step!
# Directly confirm
curl -X POST $endpoint \
     -H "Content-Type: application/json" \
     -d "{\"action\": \"confirm\", \"order_id\": \"$order_id\"}"
```

#### 3. Price Manipulation

```bash
# Set your own price
curl -X POST http://localhost:5000/api/red/insecure-design/trust-boundary \
     -H "Content-Type: application/json" \
     -d '{
           "user_id": 1,
           "item_name": "Expensive Laptop",
           "price": 0.01,
           "is_premium": true,
           "discount": 99
         }'
```

#### 4. Resource Exhaustion

```bash
# Send huge payload
python3 << 'EOF'
import requests

response = requests.post(
    'http://localhost:5000/api/red/insecure-design/missing-limits',
    json={
        'operation': 'expensive_compute',
        'data': ['x'] * 50000  # Large array
    },
    timeout=30
)
print(response.json())
EOF
```

### Blue Team Endpoints (Secure)

#### 1. Race Condition Prevention

```bash
# Idempotency prevents duplicate processing
endpoint="http://localhost:5000/api/blue/insecure-design/race-condition"
key=$(uuidgen)

# Send multiple requests with same idempotency key
for i in {1..5}; do
    curl -X POST $endpoint \
         -H "Content-Type: application/json" \
         -d "{\"user_id\": 1, \"item_id\": 101, \"idempotency_key\": \"$key\"}" &
done
wait

# Only first request processes, others return cached result
```

#### 2. Workflow Enforcement

```bash
# Try to skip payment - will fail
endpoint="http://localhost:5000/api/blue/insecure-design/workflow-bypass"

order=$(curl -X POST $endpoint \
        -H "Content-Type: application/json" \
        -d '{"action": "create", "user_id": 1, "items": ["laptop"], "total": 999.99}')

order_id=$(echo $order | jq -r '.order.order_id')

# Try to confirm without payment
curl -X POST $endpoint \
     -H "Content-Type: application/json" \
     -d "{\"action\": \"confirm\", \"order_id\": \"$order_id\"}"

# Result: Error - payment required
```

#### 3. Server-Side Validation

```bash
# Server decides price, not client
curl -X POST http://localhost:5000/api/blue/insecure-design/trust-boundary \
     -H "Content-Type: application/json" \
     -d '{
           "user_id": 1,
           "item_id": 101,
           "coupon_code": "SAVE10"
         }'

# Server looks up price from catalog, verifies premium status, calculates discount
```

#### 4. Resource Limits

```bash
# Rate limiting enforced
endpoint="http://localhost:5000/api/blue/insecure-design/missing-limits"

# Send 15 requests (limit is 10/min)
for i in {1..15}; do
    curl -X POST $endpoint \
         -H "Content-Type: application/json" \
         -d '{"user_id": 1, "operation": "default", "data": ["x"]}' \
         -w "\nStatus: %{http_code}\n"
    sleep 0.1
done

# First 10 succeed, next 5 get HTTP 429 (Too Many Requests)
```

---

## 🌍 Real-World Examples

### 1. Uber's Race Condition in Referral System (2016)

**Vulnerability:**
- Referral credits applied without proper locking
- Multiple simultaneous referrals from same code could be redeemed

**Exploitation:**
1. User A creates referral code
2. User B starts signup with User A's code
3. User B submits form multiple times simultaneously
4. Each request credits User A due to race condition
5. User A gets multiple bonuses from single referral

**Impact:**
- Financial loss from fraudulent credits
- Legitimate users exploited system

**Fix:**
- Idempotency keys for referral redemption
- Atomic database transactions
- One-time use tokens

### 2. Starbucks Gift Card Race Condition (2015)

**Vulnerability:**
- Gift card balance check and deduction not atomic
- Multiple purchases could succeed with single card

**Exploitation:**
1. Load $50 on gift card
2. Use same card on multiple payment terminals simultaneously
3. All terminals check balance: $50 ≥ $5 ✓
4. All terminals deduct $5
5. Made $25 in purchases with $50 card, but only $5 deducted

**Impact:**
- Estimated millions in losses
- Required complete redesign of payment system

**Fix:**
- Server-side synchronization
- Database row locking
- Transaction isolation

### 3. Ethereum DAO Hack (2016) - $60 Million

**Vulnerability:**
- Reentrancy attack: balance updated AFTER external call
- Workflow: Check balance → Transfer funds → Update balance

**Exploitation:**
```solidity
// Vulnerable smart contract
function withdraw(uint amount) {
    require(balances[msg.sender] >= amount);
    // ⚠️ External call before state update
    msg.sender.call.value(amount)();  // Attacker can call withdraw() again here!
    balances[msg.sender] -= amount;   // Balance updated too late
}
```

**Impact:**
- $60 million stolen
- Ethereum hard fork required
- Led to Ethereum Classic split

**Fix:**
- Update state before external calls
- Reentrancy guards
- Check-Effects-Interactions pattern

### 4. Twitter OAuth Workflow Bypass (2020)

**Vulnerability:**
- OAuth callback didn't verify authorization code was actually issued
- Could skip approval step

**Exploitation:**
1. Start OAuth flow
2. Intercept callback URL
3. Modify or fabricate authorization code
4. Skip user consent screen
5. Gain access without user approval

**Impact:**
- Unauthorized account access
- Privacy violations

**Fix:**
- PKCE (Proof Key for Code Exchange)
- State parameter validation
- Authorization code verification

---

## ✅ Testing Checklist

### Manual Testing Steps

#### Race Condition Testing

- [ ] Identify endpoints that modify shared resources (balance, inventory, etc.)
- [ ] Send simultaneous requests using tools like Apache Bench or custom scripts
- [ ] Check if resource constraints are violated (negative balance, oversold items)
- [ ] Test with different timing delays to find race windows
- [ ] Verify idempotency keys are required and enforced

#### Workflow Bypass Testing

- [ ] Map out the intended business workflow (Create → Pay → Confirm)
- [ ] Identify state transition points
- [ ] Try to skip steps (go from Create directly to Confirm)
- [ ] Try to reverse steps (Confirm then try to change price)
- [ ] Verify each step validates previous steps completed
- [ ] Test with expired or invalid state tokens

#### Trust Boundary Testing

- [ ] Identify fields that should be server-controlled (price, role, permissions)
- [ ] Try to manipulate these fields in requests
- [ ] Set prices to $0.00 or negative values
- [ ] Set is_admin=true or role=admin
- [ ] Set premium=true or discount=100
- [ ] Verify server recalculates from authoritative source

#### Resource Limit Testing

- [ ] Send requests with increasingly large payloads
- [ ] Test rate limiting with burst of requests
- [ ] Try to trigger expensive operations repeatedly
- [ ] Test with extreme values (iterations=999999999)
- [ ] Verify timeouts are enforced
- [ ] Check pagination is required for large datasets

### Automated Testing Approaches

#### Burp Suite

```
1. Use Burp Repeater to send simultaneous requests
   - Repeater → New group → Add requests
   - Send in parallel to test race conditions

2. Use Intruder for workflow testing
   - Payload: Different workflow actions
   - Grep: Error messages about missing steps

3. Use Collaborator for SSRF in workflow callbacks
```

#### Custom Python Script

```python
import requests
import concurrent.futures

def test_race_condition(session_id):
    """Test race condition with parallel requests"""
    url = "http://target/api/purchase"
    
    def make_purchase():
        return requests.post(url, 
            json={"item_id": 101, "price": 999.99},
            cookies={"session": session_id}
        )
    
    # Send 10 parallel requests
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(make_purchase) for _ in range(10)]
        results = [f.result() for f in futures]
    
    # Check if multiple succeeded
    successes = [r for r in results if r.status_code == 200]
    if len(successes) > 1:
        print(f"⚠️ Race condition found: {len(successes)} purchases succeeded")
```

### Common Pitfalls

1. **False Negatives from Timing**
   - Race conditions require precise timing
   - May need to send hundreds of requests to trigger
   - Try different network conditions

2. **Caching Interference**
   - CDN or application cache may hide race conditions
   - Test with cache-busting parameters
   - Use unique idempotency keys

3. **Load Balancer Effects**
   - Multiple app servers may prevent race conditions
   - Sticky sessions can help reach same server
   - Test in development environment with single server

4. **Transaction Isolation Levels**
   - Database transactions may prevent races
   - Check isolation level (READ COMMITTED, SERIALIZABLE, etc.)
   - Even with transactions, application-level logic can be flawed

---

## 📚 References and Further Reading

### OWASP Resources
- [OWASP Top 10 2021 - A04](https://owasp.org/Top10/A04_2021-Insecure_Design/)
- [OWASP Secure Design Principles](https://owasp.org/www-project-secure-design-principles/)
- [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/)

### Books
- "Threat Modeling: Designing for Security" by Adam Shostack
- "Secure by Design" by Dan Bergh Johnsson, Daniel Deogun, Daniel Sawano
- "Security Engineering" by Ross Anderson

### Research Papers
- "An Empirical Study of Race Conditions in Web Applications" - SIGSOFT 2014
- "Breaking and Fixing Origin-Based Access Control in Hybrid Web/Mobile Frameworks" - NDSS 2014

### Bug Bounty Reports
- [HackerOne: Race condition in coupon redemption](https://hackerone.com/reports/145745)
- [Bugcrowd: Workflow bypass in payment processing](https://bugcrowd.com/disclosures)

### Tools
- **Burp Suite**: Race condition testing with Turbo Intruder
- **Apache Bench**: Load testing for race conditions
- **Locust**: Distributed load testing
- **Race The Web**: Purpose-built for race condition testing

---

## 🎓 Key Takeaways

1. **Design Security Early**: Can't patch design flaws - need architectural changes
2. **Use State Machines**: Enforce valid transitions, prevent workflow bypass
3. **Never Trust Client**: Server decides prices, permissions, calculations
4. **Apply Resource Limits**: Rate limiting, timeouts, size limits on everything
5. **Atomic Operations**: Use locks, transactions, idempotency keys
6. **Threat Model First**: Identify abuse cases during design phase
7. **Peer Review Designs**: Security review before coding starts

**Remember**: A secure implementation of an insecure design is still insecure. Security must be designed in from the start.

---

**Next Steps:**
- Test the AegisForge endpoints to see these vulnerabilities in action
- Try to exploit the Red Team endpoints
- Study the Blue Team implementations to understand secure patterns
- Apply these principles to your own applications

**⚠️ Disclaimer**: These examples are for educational purposes only. Only test on systems you own or have explicit permission to test.
