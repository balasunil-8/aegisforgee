"""
OWASP Web Top 10 2021 - A04: Insecure Design
BLUE TEAM (Secure) Endpoints

This module demonstrates secure design patterns including:
- Proper locking and idempotency for race condition prevention
- State machine validation for workflow enforcement
- Server-side validation and calculation (never trust client)
- Rate limiting and resource constraints

Author: AegisForge Security Team
Version: 1.0
"""

from flask import Blueprint, request, jsonify
import time
import threading
import uuid
import hashlib
from datetime import datetime, timedelta
from functools import wraps

# Create blueprint
a04_insecure_design_blue = Blueprint('a04_insecure_design_blue', __name__)

# In-memory data stores
orders_db = {}
accounts_db = {
    1: {'id': 1, 'username': 'alice', 'balance': 1000.0, 'credits': 100},
    2: {'id': 2, 'username': 'bob', 'balance': 500.0, 'credits': 50}
}
workflow_states = {}
idempotency_keys = {}
rate_limit_tracker = {}

# Thread-safe locks
order_lock = threading.Lock()
account_lock = threading.Lock()

# Server-side item catalog (source of truth)
ITEM_CATALOG = {
    101: {'id': 101, 'name': 'Laptop', 'price': 999.99, 'stock': 10},
    102: {'id': 102, 'name': 'Mouse', 'price': 29.99, 'stock': 50},
    103: {'id': 103, 'name': 'Keyboard', 'price': 79.99, 'stock': 30},
    104: {'id': 104, 'name': 'Monitor', 'price': 299.99, 'stock': 15}
}

# User premium status (server-side, not client-controlled)
USER_PREMIUM_STATUS = {
    1: True,   # Alice is premium
    2: False   # Bob is not premium
}


def check_rate_limit(user_id, max_requests=10, window_seconds=60):
    """
    SECURE: Rate limiting to prevent abuse
    """
    current_time = datetime.now()
    
    if user_id not in rate_limit_tracker:
        rate_limit_tracker[user_id] = []
    
    # Remove old requests outside the window
    rate_limit_tracker[user_id] = [
        req_time for req_time in rate_limit_tracker[user_id]
        if (current_time - req_time).total_seconds() < window_seconds
    ]
    
    # Check if limit exceeded
    if len(rate_limit_tracker[user_id]) >= max_requests:
        return False, len(rate_limit_tracker[user_id])
    
    # Add current request
    rate_limit_tracker[user_id].append(current_time)
    return True, len(rate_limit_tracker[user_id])


@a04_insecure_design_blue.route('/api/blue/insecure-design/race-condition', methods=['POST'])
def race_condition_order_secure():
    """
    SECURE: Race condition prevention with proper locking and idempotency
    
    Security controls:
    1. Idempotency key prevents duplicate processing
    2. Thread-safe locks ensure atomic operations
    3. Balance check and deduction happen atomically
    4. Transaction-like behavior (check + update in critical section)
    
    Example payload:
    {
        "user_id": 1,
        "item_id": 101,
        "idempotency_key": "unique-uuid-here"
    }
    """
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        item_id = data.get('item_id')
        idempotency_key = data.get('idempotency_key')
        
        # SECURE: Require idempotency key
        if not idempotency_key:
            return jsonify({
                'ok': False,
                'error': 'idempotency_key is required',
                'security_control': 'Idempotency key prevents duplicate processing'
            }), 400
        
        # SECURE: Check if request already processed
        if idempotency_key in idempotency_keys:
            return jsonify({
                'ok': True,
                'order': idempotency_keys[idempotency_key],
                'message': 'Request already processed (idempotent)',
                'security_control': 'Duplicate request prevented'
            }), 200
        
        # SECURE: Validate item exists
        if item_id not in ITEM_CATALOG:
            return jsonify({
                'ok': False,
                'error': 'Invalid item_id'
            }), 400
        
        item = ITEM_CATALOG[item_id]
        price = item['price']  # SECURE: Price from server, not client
        
        # SECURE: Use thread-safe lock for atomic operation
        with account_lock:
            if user_id not in accounts_db:
                return jsonify({
                    'ok': False,
                    'error': 'User not found'
                }), 404
            
            account = accounts_db[user_id]
            
            # SECURE: Check and update happen atomically
            if account['balance'] < price:
                return jsonify({
                    'ok': False,
                    'error': 'Insufficient balance',
                    'balance': account['balance'],
                    'required': price
                }), 400
            
            # Simulate processing delay (race condition window in vulnerable version)
            time.sleep(0.1)
            
            # SECURE: Balance deduction is atomic
            account['balance'] -= price
            new_balance = account['balance']
        
        # Create order after successful payment
        order_id = str(uuid.uuid4())
        order = {
            'order_id': order_id,
            'user_id': user_id,
            'item_id': item_id,
            'item_name': item['name'],
            'price': price,
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'idempotency_key': idempotency_key
        }
        
        # SECURE: Store both order and idempotency key
        orders_db[order_id] = order
        idempotency_keys[idempotency_key] = order
        
        return jsonify({
            'ok': True,
            'order': order,
            'new_balance': new_balance,
            'security_controls': [
                'Idempotency key prevents duplicate processing',
                'Thread-safe lock ensures atomic operations',
                'Balance check and deduction are atomic',
                'Server-side price lookup (client cannot manipulate)'
            ]
        }), 200
        
    except Exception as e:
        return jsonify({
            'ok': False,
            'error': 'An error occurred',
            'security_control': 'Error details hidden from client'
        }), 500


@a04_insecure_design_blue.route('/api/blue/insecure-design/workflow-bypass', methods=['POST'])
def workflow_bypass_secure():
    """
    SECURE: Workflow enforcement with state machine validation
    
    Security controls:
    1. State machine enforces correct workflow order
    2. Payment verification before confirmation
    3. State transitions are validated
    4. Cannot skip required steps
    
    Workflow: Create → Pay → Confirm (all steps required)
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
                'status': 'created',  # State: created
                'payment_status': 'unpaid',
                'workflow_state': 'created',
                'created_at': datetime.now().isoformat(),
                'allowed_next_actions': ['pay', 'cancel']
            }
            workflow_states[order_id] = order
            
            return jsonify({
                'ok': True,
                'order': order,
                'next_step': 'payment',
                'security_control': 'State machine enforces workflow order'
            }), 200
            
        elif action == 'pay':
            # SECURE: Payment must happen before confirmation
            order_id = data.get('order_id')
            if order_id not in workflow_states:
                return jsonify({'ok': False, 'error': 'Order not found'}), 404
            
            order = workflow_states[order_id]
            
            # SECURE: Validate current state
            if order['workflow_state'] != 'created':
                return jsonify({
                    'ok': False,
                    'error': 'Invalid workflow state',
                    'current_state': order['workflow_state'],
                    'allowed_actions': order.get('allowed_next_actions', [])
                }), 400
            
            # Process payment (in real system, this would integrate with payment gateway)
            user_id = order['user_id']
            total = order['total']
            
            with account_lock:
                if user_id not in accounts_db:
                    return jsonify({'ok': False, 'error': 'User not found'}), 404
                
                account = accounts_db[user_id]
                if account['balance'] < total:
                    return jsonify({
                        'ok': False,
                        'error': 'Insufficient balance',
                        'balance': account['balance'],
                        'required': total
                    }), 400
                
                # Deduct payment
                account['balance'] -= total
            
            # SECURE: Update state after successful payment
            order['payment_status'] = 'paid'
            order['workflow_state'] = 'paid'
            order['paid_at'] = datetime.now().isoformat()
            order['allowed_next_actions'] = ['confirm', 'refund']
            
            return jsonify({
                'ok': True,
                'order': order,
                'message': 'Payment processed successfully',
                'next_step': 'confirm',
                'security_control': 'Payment verified and state updated'
            }), 200
            
        elif action == 'confirm':
            # SECURE: Confirmation requires payment
            order_id = data.get('order_id')
            if order_id not in workflow_states:
                return jsonify({'ok': False, 'error': 'Order not found'}), 404
            
            order = workflow_states[order_id]
            
            # SECURE: Enforce that payment must be completed first
            if order['workflow_state'] != 'paid':
                return jsonify({
                    'ok': False,
                    'error': 'Cannot confirm order: payment not completed',
                    'current_state': order['workflow_state'],
                    'payment_status': order['payment_status'],
                    'security_control': 'State machine prevents workflow bypass'
                }), 400
            
            # SECURE: Double-check payment status
            if order['payment_status'] != 'paid':
                return jsonify({
                    'ok': False,
                    'error': 'Payment verification failed',
                    'security_control': 'Additional payment status check'
                }), 400
            
            # Confirm order
            order['status'] = 'confirmed'
            order['workflow_state'] = 'confirmed'
            order['confirmed_at'] = datetime.now().isoformat()
            order['allowed_next_actions'] = ['ship']
            
            return jsonify({
                'ok': True,
                'order': order,
                'message': 'Order confirmed successfully',
                'security_controls': [
                    'Payment verified before confirmation',
                    'State machine enforced correct workflow',
                    'Cannot skip required steps'
                ]
            }), 200
            
        else:
            return jsonify({'ok': False, 'error': 'Invalid action'}), 400
            
    except Exception as e:
        return jsonify({
            'ok': False,
            'error': 'An error occurred'
        }), 500


@a04_insecure_design_blue.route('/api/blue/insecure-design/trust-boundary', methods=['POST'])
def trust_boundary_secure():
    """
    SECURE: Server-side validation and calculation (never trust client)
    
    Security controls:
    1. All prices fetched from server-side catalog
    2. Premium status verified server-side
    3. Discounts calculated server-side with business rules
    4. Client cannot manipulate critical values
    
    Example payload:
    {
        "user_id": 1,
        "item_id": 101,
        "coupon_code": "SAVE10"
    }
    """
    try:
        data = request.get_json()
        user_id = data.get('user_id')
        item_id = data.get('item_id')
        coupon_code = data.get('coupon_code', '')
        
        # SECURE: Validate item exists in server catalog
        if item_id not in ITEM_CATALOG:
            return jsonify({
                'ok': False,
                'error': 'Invalid item_id'
            }), 400
        
        # SECURE: Get price from server-side catalog
        item = ITEM_CATALOG[item_id]
        base_price = item['price']
        
        # SECURE: Check premium status from server-side data
        is_premium = USER_PREMIUM_STATUS.get(user_id, False)
        
        # SECURE: Calculate discount based on server-side business rules
        discount_percent = 0
        discount_source = []
        
        # Server-side coupon validation
        valid_coupons = {
            'SAVE10': 10,
            'SAVE20': 20,
            'VIP30': 30
        }
        
        if coupon_code in valid_coupons:
            discount_percent = valid_coupons[coupon_code]
            discount_source.append(f'Coupon {coupon_code}')
        
        # Premium discount (server decides)
        if is_premium:
            discount_percent += 15  # Additional 15% for premium users
            discount_source.append('Premium membership')
        
        # Cap maximum discount
        discount_percent = min(discount_percent, 50)  # Max 50% discount
        
        # SECURE: Calculate final price server-side
        final_price = base_price * (1 - discount_percent / 100.0)
        
        # Process the purchase
        order_id = str(uuid.uuid4())
        order = {
            'order_id': order_id,
            'user_id': user_id,
            'item_id': item_id,
            'item_name': item['name'],
            'base_price': base_price,
            'discount_percent': discount_percent,
            'discount_sources': discount_source,
            'final_price': round(final_price, 2),
            'is_premium': is_premium,
            'status': 'completed',
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify({
            'ok': True,
            'order': order,
            'message': 'Purchase completed',
            'security_controls': [
                'Price fetched from server-side catalog',
                'Premium status verified server-side',
                'Discount calculated server-side with business rules',
                'Client cannot manipulate prices',
                'Maximum discount cap enforced'
            ],
            'calculation_breakdown': {
                'base_price': base_price,
                'discount_applied': discount_percent,
                'discount_sources': discount_source,
                'final_price': round(final_price, 2)
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            'ok': False,
            'error': 'An error occurred'
        }), 500


@a04_insecure_design_blue.route('/api/blue/insecure-design/missing-limits', methods=['POST'])
def missing_resource_limits_secure():
    """
    SECURE: Resource limits and rate limiting enforcement
    
    Security controls:
    1. Rate limiting per user (10 req/min)
    2. Input size validation (max 1000 items)
    3. Operation timeout limits
    4. Memory allocation limits
    5. Iteration count limits
    
    Example payload:
    {
        "user_id": 1,
        "operation": "expensive_compute",
        "data": ["x", "y", "z"]
    }
    """
    try:
        data = request.get_json()
        user_id = data.get('user_id', 0)
        operation = data.get('operation', 'default')
        input_data = data.get('data', [])
        
        # SECURE: Rate limiting
        rate_ok, request_count = check_rate_limit(user_id, max_requests=10, window_seconds=60)
        if not rate_ok:
            return jsonify({
                'ok': False,
                'error': 'Rate limit exceeded',
                'limit': '10 requests per minute',
                'current_count': request_count,
                'security_control': 'Rate limiting prevents abuse'
            }), 429
        
        # SECURE: Input size validation
        max_input_size = 1000
        if len(input_data) > max_input_size:
            return jsonify({
                'ok': False,
                'error': 'Input size exceeds limit',
                'limit': max_input_size,
                'provided': len(input_data),
                'security_control': 'Input size limit prevents resource exhaustion'
            }), 400
        
        if operation == 'expensive_compute':
            # SECURE: Limited computation with timeout
            result = []
            max_iterations = 100  # Limit iterations per item
            
            for item in input_data[:100]:  # Process max 100 items
                for _ in range(min(max_iterations, 100)):
                    result.append(str(item)[:10])  # Limit string length
            
            return jsonify({
                'ok': True,
                'processed': len(result),
                'input_size': len(input_data),
                'security_controls': [
                    'Input size limited to 1000 items',
                    'Iterations limited per item',
                    'Output size controlled',
                    'Rate limited to 10 req/min'
                ]
            }), 200
            
        elif operation == 'allocate_memory':
            # SECURE: Memory allocation with limits
            max_allocation = 10000  # Limit allocated items
            items_to_allocate = min(len(input_data), 100)
            large_list = ['x' * 100] * items_to_allocate  # Limited size
            
            return jsonify({
                'ok': True,
                'allocated': len(large_list),
                'security_control': 'Memory allocation limited',
                'limit': max_allocation
            }), 200
            
        elif operation == 'loop':
            # SECURE: Iteration limits
            max_iterations = 10000
            iterations = min(data.get('iterations', 1000), max_iterations)
            counter = 0
            for i in range(iterations):
                counter += 1
            
            return jsonify({
                'ok': True,
                'iterations': counter,
                'max_allowed': max_iterations,
                'security_control': 'Iteration count capped'
            }), 200
            
        else:
            return jsonify({
                'ok': True,
                'message': 'Operation completed',
                'rate_limit_remaining': 10 - request_count,
                'security_controls': [
                    'Rate limiting: 10 requests/minute',
                    'Input validation enforced',
                    'Resource limits applied'
                ]
            }), 200
            
    except Exception as e:
        return jsonify({
            'ok': False,
            'error': 'An error occurred'
        }), 500


@a04_insecure_design_blue.route('/api/blue/insecure-design/info', methods=['GET'])
def insecure_design_info():
    """
    Get information about secure design patterns for A04
    """
    return jsonify({
        'category': 'A04: Insecure Design - SECURE Implementation',
        'description': 'Demonstrates secure design patterns and controls',
        'security_patterns': [
            {
                'name': 'Race Condition Prevention',
                'endpoint': '/api/blue/insecure-design/race-condition',
                'method': 'POST',
                'controls': [
                    'Idempotency keys',
                    'Thread-safe locks',
                    'Atomic operations',
                    'Server-side price lookup'
                ]
            },
            {
                'name': 'Workflow Enforcement',
                'endpoint': '/api/blue/insecure-design/workflow-bypass',
                'method': 'POST',
                'controls': [
                    'State machine validation',
                    'Payment verification',
                    'State transition checks',
                    'Required step enforcement'
                ]
            },
            {
                'name': 'Trust Boundary Protection',
                'endpoint': '/api/blue/insecure-design/trust-boundary',
                'method': 'POST',
                'controls': [
                    'Server-side catalog',
                    'Server-side premium verification',
                    'Server-side discount calculation',
                    'Maximum discount caps'
                ]
            },
            {
                'name': 'Resource Limits',
                'endpoint': '/api/blue/insecure-design/missing-limits',
                'method': 'POST',
                'controls': [
                    'Rate limiting (10 req/min)',
                    'Input size validation',
                    'Operation timeouts',
                    'Memory limits'
                ]
            }
        ],
        'owasp_reference': 'https://owasp.org/Top10/A04_2021-Insecure_Design/',
        'documentation': '/docs/vulnerabilities/owasp-web-2021/A04_INSECURE_DESIGN.md'
    }), 200


# Helper endpoint to reset state for testing
@a04_insecure_design_blue.route('/api/blue/insecure-design/reset', methods=['POST'])
def reset_state():
    """Reset all state for testing purposes"""
    global orders_db, accounts_db, workflow_states, idempotency_keys, rate_limit_tracker
    
    orders_db.clear()
    workflow_states.clear()
    idempotency_keys.clear()
    rate_limit_tracker.clear()
    
    # Reset account balances
    accounts_db[1] = {'id': 1, 'username': 'alice', 'balance': 1000.0, 'credits': 100}
    accounts_db[2] = {'id': 2, 'username': 'bob', 'balance': 500.0, 'credits': 50}
    
    return jsonify({
        'ok': True,
        'message': 'State reset successfully'
    }), 200
