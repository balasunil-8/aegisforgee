"""
Rate Limiter Module
Provides rate limiting functionality for endpoints
"""

import time
from collections import defaultdict
from datetime import datetime, timedelta


class RateLimiter:
    """
    Token bucket rate limiter
    """
    
    def __init__(self):
        # Store: {identifier: {'count': int, 'reset_time': timestamp}}
        self.buckets = defaultdict(dict)
    
    def check_limit(self, identifier, limit=5, window=60):
        """
        Check if request is within rate limit
        
        Args:
            identifier: unique identifier (IP, user_id, etc.)
            limit: max requests allowed
            window: time window in seconds
            
        Returns:
            (allowed, remaining, reset_time)
        """
        now = time.time()
        
        # Get or create bucket
        if identifier not in self.buckets:
            self.buckets[identifier] = {
                'count': 0,
                'reset_time': now + window
            }
        
        bucket = self.buckets[identifier]
        
        # Reset if window expired
        if now >= bucket['reset_time']:
            bucket['count'] = 0
            bucket['reset_time'] = now + window
        
        # Check limit
        if bucket['count'] >= limit:
            remaining = 0
            reset_in = int(bucket['reset_time'] - now)
            return False, remaining, reset_in
        
        # Increment counter
        bucket['count'] += 1
        remaining = limit - bucket['count']
        reset_in = int(bucket['reset_time'] - now)
        
        return True, remaining, reset_in
    
    def reset(self, identifier):
        """
        Reset rate limit for identifier
        """
        if identifier in self.buckets:
            del self.buckets[identifier]
    
    def cleanup(self):
        """
        Remove expired buckets
        """
        now = time.time()
        expired = [
            identifier for identifier, bucket in self.buckets.items()
            if now >= bucket['reset_time'] + 3600  # Keep for 1 hour after expiration
        ]
        for identifier in expired:
            del self.buckets[identifier]

AegisForge Rate Limiting Module
Implements rate limiting to prevent brute force and DoS attacks
"""

from datetime import datetime, timedelta
from collections import defaultdict
from typing import Optional
import hashlib

class RateLimiter:
    """
    Simple in-memory rate limiter
    For production, use Redis with redis-py
    """
    
    def __init__(self):
        # Store format: {key: [(timestamp1, count1), (timestamp2, count2), ...]}
        self.requests = defaultdict(list)
        self.blocked_ips = {}  # {ip: until_timestamp}
    
    def _get_client_key(self, ip: str, endpoint: str = None) -> str:
        """Generate unique key for client + endpoint"""
        key = f"{ip}"
        if endpoint:
            key += f":{endpoint}"
        return hashlib.md5(key.encode()).hexdigest()
    
    def _cleanup_old_requests(self, key: str, window_seconds: int):
        """Remove requests older than the time window"""
        cutoff = datetime.utcnow() - timedelta(seconds=window_seconds)
        self.requests[key] = [
            (ts, count) for ts, count in self.requests[key]
            if ts > cutoff
        ]
    
    def is_allowed(
        self, 
        ip: str, 
        endpoint: str = None,
        max_requests: int = 100,
        window_seconds: int = 60
    ) -> tuple[bool, dict]:
        """
        Check if request is allowed under rate limit
        
        Args:
            ip: Client IP address
            endpoint: Optional endpoint identifier
            max_requests: Maximum requests allowed in window
            window_seconds: Time window in seconds
        
        Returns:
            (is_allowed, info_dict)
        """
        # Check if IP is blocked
        if ip in self.blocked_ips:
            if datetime.utcnow() < self.blocked_ips[ip]:
                return False, {
                    'blocked': True,
                    'reason': 'IP temporarily blocked for excessive requests',
                    'retry_after': (self.blocked_ips[ip] - datetime.utcnow()).seconds
                }
            else:
                # Unblock if time has passed
                del self.blocked_ips[ip]
        
        key = self._get_client_key(ip, endpoint)
        
        # Clean up old requests
        self._cleanup_old_requests(key, window_seconds)
        
        # Count current requests
        current_count = sum(count for _, count in self.requests[key])
        
        # Check limit
        if current_count >= max_requests:
            # Block IP for 5 minutes
            self.blocked_ips[ip] = datetime.utcnow() + timedelta(minutes=5)
            
            return False, {
                'blocked': True,
                'reason': 'Rate limit exceeded',
                'limit': max_requests,
                'window': window_seconds,
                'current': current_count,
                'retry_after': 300
            }
        
        # Add this request
        self.requests[key].append((datetime.utcnow(), 1))
        
        return True, {
            'blocked': False,
            'limit': max_requests,
            'remaining': max_requests - current_count - 1,
            'window': window_seconds
        }
    
    def block_ip(self, ip: str, duration_minutes: int = 60):
        """Manually block an IP address"""
        self.blocked_ips[ip] = datetime.utcnow() + timedelta(minutes=duration_minutes)
    
    def unblock_ip(self, ip: str):
        """Manually unblock an IP address"""
        if ip in self.blocked_ips:
            del self.blocked_ips[ip]
    
    def get_stats(self, ip: str = None) -> dict:
        """Get rate limiting statistics"""
        if ip:
            key = self._get_client_key(ip)
            self._cleanup_old_requests(key, 3600)  # Last hour
            count = sum(c for _, c in self.requests[key])
            
            return {
                'ip': ip,
                'requests_last_hour': count,
                'is_blocked': ip in self.blocked_ips
            }
        else:
            return {
                'total_tracked_clients': len(self.requests),
                'blocked_ips': len(self.blocked_ips)
            }

# Global rate limiter instance
_rate_limiter = RateLimiter()


def check_rate_limit(identifier, limit=5, window=60):
    """
    Check rate limit for identifier
    
    Args:
        identifier: unique identifier (IP, user_id, etc.)
        limit: max requests allowed (default: 5)
        window: time window in seconds (default: 60)
        
    Returns:
        boolean - True if allowed, False if rate limited
    """
    allowed, remaining, reset_in = _rate_limiter.check_limit(identifier, limit, window)
    return allowed


def check_rate_limit_with_info(identifier, limit=5, window=60):
    """
    Check rate limit and return detailed info
    
    Args:
        identifier: unique identifier (IP, user_id, etc.)
        limit: max requests allowed
        window: time window in seconds
        
    Returns:
        dict with keys: allowed, remaining, reset_in, limit
    """
    allowed, remaining, reset_in = _rate_limiter.check_limit(identifier, limit, window)
    return {
        'allowed': allowed,
        'remaining': remaining,
        'reset_in': reset_in,
        'limit': limit
    }


def reset_rate_limit(identifier):
    """
    Reset rate limit for identifier
    """
    _rate_limiter.reset(identifier)


def get_rate_limit_headers(identifier, limit=5, window=60):
    """
    Get rate limit headers for response
    
    Returns:
        dict of headers
    """
    info = check_rate_limit_with_info(identifier, limit, window)
    
    return {
        'X-RateLimit-Limit': str(limit),
        'X-RateLimit-Remaining': str(info['remaining']),
        'X-RateLimit-Reset': str(int(time.time() + info['reset_in']))
    }


class SlidingWindowRateLimiter:
    """
    Sliding window rate limiter for more precise rate limiting
    """
    
    def __init__(self):
        # Store: {identifier: [timestamp1, timestamp2, ...]}
        self.requests = defaultdict(list)
    
    def check_limit(self, identifier, limit=5, window=60):
        """
        Check if request is within rate limit using sliding window
        
        Args:
            identifier: unique identifier
            limit: max requests allowed
            window: time window in seconds
            
        Returns:
            (allowed, remaining)
        """
        now = time.time()
        cutoff = now - window
        
        # Get request history
        if identifier not in self.requests:
            self.requests[identifier] = []
        
        # Remove old requests
        self.requests[identifier] = [
            ts for ts in self.requests[identifier] if ts > cutoff
        ]
        
        # Check limit
        if len(self.requests[identifier]) >= limit:
            return False, 0
        
        # Add current request
        self.requests[identifier].append(now)
        remaining = limit - len(self.requests[identifier])
        
        return True, remaining
    
    def cleanup(self):
        """
        Remove old data
        """
        now = time.time()
        for identifier in list(self.requests.keys()):
            # Remove requests older than 1 hour
            self.requests[identifier] = [
                ts for ts in self.requests[identifier]
                if now - ts < 3600
            ]
            if not self.requests[identifier]:
                del self.requests[identifier]


# Global sliding window rate limiter
_sliding_rate_limiter = SlidingWindowRateLimiter()


def check_sliding_rate_limit(identifier, limit=5, window=60):
    """
    Check rate limit using sliding window algorithm
    
    Returns:
        boolean - True if allowed, False if rate limited
    """
    allowed, remaining = _sliding_rate_limiter.check_limit(identifier, limit, window)
    return allowed
def get_rate_limiter() -> RateLimiter:
    """Get the global rate limiter instance"""
    return _rate_limiter

def check_rate_limit(ip: str, endpoint: str = None, strict: bool = False) -> tuple[bool, dict]:
    """
    Convenience function to check rate limit
    
    Args:
        ip: Client IP
        endpoint: Optional endpoint
        strict: If True, use stricter limits
    
    Returns:
        (is_allowed, info_dict)
    """
    limiter = get_rate_limiter()
    
    if strict:
        # Stricter limits for sensitive endpoints (e.g., authentication)
        return limiter.is_allowed(ip, endpoint, max_requests=10, window_seconds=60)
    else:
        # Normal limits
        return limiter.is_allowed(ip, endpoint, max_requests=100, window_seconds=60)
