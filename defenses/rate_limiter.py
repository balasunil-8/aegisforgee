"""
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
