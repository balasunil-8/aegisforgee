"""
OWASP Web Top 10 2021 - A04: Insecure Design
RED TEAM (Vulnerable) Endpoints

This module demonstrates insecure design vulnerabilities including:
- Race conditions in order processing
- Workflow bypass allowing payment skipping
- Trust boundary violations (trusting client-side data)
- Missing resource limits and rate limiting

Author: AegisForge Security Team
Version: 1.0
WARNING: These endpoints are intentionally insecure for educational purposes only
"""

from flask import Blueprint, request, jsonify
import time
import threading
import uuid
from datetime import datetime

# Create blueprint
a04_insecure_design_red = Blueprint('a04_insecure_design_red', __name__)

# In-memory data stores
orders_db = {}
accounts_db = {
    1: {'id': 1, 'username': 'alice', 'balance': 1000.0, 'credits': 100},
    2: {'id': 2, 'username': 'bob', 'balance': 500.0, 'credits': 50}
}
workflow_states = {}
resource_usage = {}

# Simple lock for demonstration (but not used properly in vulnerable code)
order_lock = threading.Lock()


@a04_insecure_design_red.route('/api/red/insecure-design/race-condition', methods=['POST'])
def race_condition_order():
    """
    VULNERABLE: Race condition in order processing
    
    Problem: No proper locking or idempotency checks allow multiple simultaneous
    requests to process the same order multiple times, leading to:
    - Double charging
    - Inventory issues
    - Balance manipulation
    
    How to exploit:
    1. Create an order with POST
    2. Send multiple simultaneous POST requests to process it
    3. Observe multiple deductions from balance
    
    Example payload:
    {
        "user_id": 1,
        "item_id": 101,
        "price": 99.99,
        "action": "purchase"
    }
    """
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        item_id = data.get('item_id')
        price = float(data.get('price', 0))
        action = data.get('action', 'purchase')
        
        # VULNERABLE: No idempotency key check
        # VULNERABLE: No proper locking mechanism
        # VULNERABLE: Race window between check and update
        
        if user_id not in accounts_db:
            return jsonify({
                'ok': False,
                'error': 'User not found'
            }), 404
        
        account = accounts_db[user_id]
        
        # VULNERABLE: Check happens here
        if account['balance'] < price:
            return jsonify({
                'ok': False,
                'error': 'Insufficient balance',
                'balance': account['balance'],
                'required': price
            }), 400
        
        # VULNERABLE: Race window - another request can sneak in here
        time.sleep(0.1)  # Simulate processing delay, amplifies the race condition
        
        # VULNERABLE: Update happens here without rechecking
        account['balance'] -= price
        
        order_id = str(uuid.uuid4())
        order = {
            'order_id': order_id,
            'user_id': user_id,
            'item_id': item_id,
            'price': price,
            'status': 'completed',
            'timestamp': datetime.now().isoformat()
        }
        orders_db[order_id] = order
        
        return jsonify({
            'ok': True,
            'order': order,
            'new_balance': account['balance'],
            'vulnerability': 'Race condition - no atomic operations',
            'exploit_hint': 'Send multiple simultaneous requests to purchase with insufficient balance'
        }), 200
        
    except Exception as e:
        return jsonify({
            'ok': False,
            'error': str(e),
            'vulnerability': 'Race condition allows double-spending'
        }), 500


@a04_insecure_design_red.route('/api/red/insecure-design/workflow-bypass', methods=['POST'])
def workflow_bypass():
    """
    VULNERABLE: Workflow bypass allowing payment step to be skipped
    
    Problem: Order confirmation doesn't verify that payment was completed first.
    The workflow should be: Create → Pay → Confirm, but you can skip directly to Confirm.
    
    How to exploit:
    1. POST to create an order
    2. POST directly to confirm without paying
    3. Receive items without payment
    
    Example workflow:
    Step 1 - Create: {"user_id": 1, "items": ["laptop"], "total": 999.99}
    Step 2 - Skip payment!
    Step 3 - Confirm: {"order_id": "<id>", "skip_payment": true}
    """
    try:
        data = request.get_json()
        action = data.get('action', 'create')
        
        if action == 'create':
            # Create new order
            order_id = str(uuid.uuid4())
            order = {
                'order_id': order_id,
                'user_id': data.get('user_id'),
                'items': data.get('items', []),
                'total': data.get('total', 0),
                'status': 'pending',
                'payment_status': 'unpaid',
                'created_at': datetime.now().isoformat()
            }
            workflow_states[order_id] = order
            
            return jsonify({
                'ok': True,
                'order': order,
                'next_step': 'payment',
                'vulnerability': 'You can skip payment and go directly to confirm'
            }), 200
            
        elif action == 'pay':
            # Payment step (optional in vulnerable design)
            order_id = data.get('order_id')
            if order_id not in workflow_states:
                return jsonify({'ok': False, 'error': 'Order not found'}), 404
            
            order = workflow_states[order_id]
            # VULNERABLE: Payment doesn't actually verify funds or process payment
            order['payment_status'] = 'paid'
            order['paid_at'] = datetime.now().isoformat()
            
            return jsonify({
                'ok': True,
                'order': order,
                'message': 'Payment recorded (not verified)',
                'next_step': 'confirm'
            }), 200
            
        elif action == 'confirm':
            # VULNERABLE: Confirmation doesn't check payment status
            order_id = data.get('order_id')
            if order_id not in workflow_states:
                return jsonify({'ok': False, 'error': 'Order not found'}), 404
            
            order = workflow_states[order_id]
            
            # VULNERABLE: No check for payment_status == 'paid'
            # This is the critical flaw in insecure design
            
            order['status'] = 'confirmed'
            order['confirmed_at'] = datetime.now().isoformat()
            
            return jsonify({
                'ok': True,
                'order': order,
                'message': 'Order confirmed and will be shipped',
                'vulnerability': 'Payment was never verified!',
                'payment_status': order.get('payment_status', 'unknown')
            }), 200
            
        else:
            return jsonify({'ok': False, 'error': 'Invalid action'}), 400
            
    except Exception as e:
        return jsonify({
            'ok': False,
            'error': str(e)
        }), 500


@a04_insecure_design_red.route('/api/red/insecure-design/trust-boundary', methods=['POST'])
def trust_boundary_violation():
    """
    VULNERABLE: Trust boundary violation - trusting client-side data
    
    Problem: The server trusts critical data sent from the client without validation.
    Client can manipulate prices, discounts, and other sensitive values.
    
    How to exploit:
    1. Send a purchase request
    2. Manipulate price, discount, or is_premium flag in client payload
    3. Buy items at arbitrary prices
    
    Example exploit:
    {
        "user_id": 2,
        "item_name": "Laptop",
        "price": 0.01,
        "is_premium": true,
        "discount": 99
    }
    """
    try:
        data = request.get_json()
        
        # VULNERABLE: Trusting all values from client
        user_id = data.get('user_id')
        item_name = data.get('item_name', 'Unknown')
        client_price = float(data.get('price', 0))  # DANGER: Client sets price!
        is_premium = data.get('is_premium', False)  # DANGER: Client claims premium!
        discount = int(data.get('discount', 0))     # DANGER: Client sets discount!
        
        # VULNERABLE: Using client-provided values directly
        final_price = client_price * (1 - discount / 100.0)
        
        if is_premium:
            final_price *= 0.5  # Additional premium discount - based on client claim!
        
        # Process the purchase with manipulated price
        order_id = str(uuid.uuid4())
        order = {
            'order_id': order_id,
            'user_id': user_id,
            'item_name': item_name,
            'client_claimed_price': client_price,
            'client_claimed_discount': discount,
            'client_claimed_premium': is_premium,
            'final_price': final_price,
            'status': 'completed',
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify({
            'ok': True,
            'order': order,
            'message': 'Purchase completed',
            'vulnerability': 'Server trusts client-provided price, discount, and premium status',
            'exploit_hint': 'Try setting price=0.01, is_premium=true, discount=99'
        }), 200
        
    except Exception as e:
        return jsonify({
            'ok': False,
            'error': str(e)
        }), 500


@a04_insecure_design_red.route('/api/red/insecure-design/missing-limits', methods=['POST'])
def missing_resource_limits():
    """
    VULNERABLE: Missing resource limits and rate limiting
    
    Problem: No limits on:
    - Request rate (can spam requests)
    - Request size (can send huge payloads)
    - Expensive operations (can trigger DoS)
    - Resource allocation (can exhaust server resources)
    
    How to exploit:
    1. Send requests with huge arrays/strings
    2. Send thousands of requests rapidly
    3. Trigger expensive operations repeatedly
    
    Example exploit:
    {
        "operation": "expensive_compute",
        "data": ["x"] * 10000
    }
    """
    try:
        data = request.get_json()
        operation = data.get('operation', 'default')
        input_data = data.get('data', [])
        
        # VULNERABLE: No size check on input
        # VULNERABLE: No rate limiting
        # VULNERABLE: No timeout on operations
        
        if operation == 'expensive_compute':
            # VULNERABLE: Expensive operation with no limits
            result = []
            for item in input_data:
                # Simulate expensive computation
                for _ in range(1000):
                    result.append(str(item) * 10)
            
            return jsonify({
                'ok': True,
                'processed': len(result),
                'vulnerability': 'No limits on operation cost or input size',
                'input_size': len(input_data),
                'output_size': len(result)
            }), 200
            
        elif operation == 'allocate_memory':
            # VULNERABLE: Unbounded memory allocation
            large_list = ['x' * 1000] * len(input_data)
            
            return jsonify({
                'ok': True,
                'allocated': len(large_list),
                'vulnerability': 'No memory allocation limits',
                'memory_used': f'{len(large_list) * 1000} bytes'
            }), 200
            
        elif operation == 'infinite_loop_risk':
            # VULNERABLE: Operation that could run indefinitely
            iterations = data.get('iterations', 1000000)
            counter = 0
            for i in range(iterations):
                counter += 1
            
            return jsonify({
                'ok': True,
                'iterations': counter,
                'vulnerability': 'No timeout or iteration limits'
            }), 200
            
        else:
            return jsonify({
                'ok': True,
                'message': 'Operation completed',
                'vulnerability': 'No rate limiting - you can call this unlimited times',
                'hint': 'Try sending many requests simultaneously or with huge data arrays'
            }), 200
            
    except Exception as e:
        return jsonify({
            'ok': False,
            'error': str(e),
            'vulnerability': 'Error handling also vulnerable to resource exhaustion'
        }), 500


@a04_insecure_design_red.route('/api/red/insecure-design/info', methods=['GET'])
def insecure_design_info():
    """
    Get information about A04: Insecure Design vulnerabilities
    """
    return jsonify({
        'category': 'A04: Insecure Design',
        'description': 'Insecure design represents missing or ineffective control design',
        'vulnerabilities': [
            {
                'name': 'Race Condition',
                'endpoint': '/api/red/insecure-design/race-condition',
                'method': 'POST',
                'description': 'Order processing without proper locking allows double-spending',
                'severity': 'HIGH'
            },
            {
                'name': 'Workflow Bypass',
                'endpoint': '/api/red/insecure-design/workflow-bypass',
                'method': 'POST',
                'description': 'Payment step can be skipped in order workflow',
                'severity': 'CRITICAL'
            },
            {
                'name': 'Trust Boundary Violation',
                'endpoint': '/api/red/insecure-design/trust-boundary',
                'method': 'POST',
                'description': 'Server trusts client-provided prices and discounts',
                'severity': 'CRITICAL'
            },
            {
                'name': 'Missing Resource Limits',
                'endpoint': '/api/red/insecure-design/missing-limits',
                'method': 'POST',
                'description': 'No rate limiting or resource constraints',
                'severity': 'HIGH'
            }
        ],
        'owasp_reference': 'https://owasp.org/Top10/A04_2021-Insecure_Design/',
        'testing_guide': '/docs/vulnerabilities/owasp-web-2021/A04_INSECURE_DESIGN.md'
    }), 200


# Helper endpoint to reset state for testing
@a04_insecure_design_red.route('/api/red/insecure-design/reset', methods=['POST'])
def reset_state():
    """Reset all state for testing purposes"""
    global orders_db, accounts_db, workflow_states, resource_usage
    
    orders_db.clear()
    workflow_states.clear()
    resource_usage.clear()
    
    # Reset account balances
    accounts_db[1] = {'id': 1, 'username': 'alice', 'balance': 1000.0, 'credits': 100}
    accounts_db[2] = {'id': 2, 'username': 'bob', 'balance': 500.0, 'credits': 50}
    
    return jsonify({
        'ok': True,
        'message': 'State reset successfully'
    }), 200
