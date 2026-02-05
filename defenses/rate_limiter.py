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
