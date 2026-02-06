"""
AegisForge WAF Rules Module
Educational Web Application Firewall rules and patterns
"""

import re
from typing import List, Dict, Tuple

class WAFRule:
    """Represents a single WAF rule"""
    
    def __init__(self, rule_id: str, name: str, pattern: str, severity: str, description: str):
        self.rule_id = rule_id
        self.name = name
        self.pattern = re.compile(pattern, re.IGNORECASE)
        self.severity = severity  # 'high', 'medium', 'low'
        self.description = description
    
    def matches(self, input_str: str) -> bool:
        """Check if input matches this rule"""
        return bool(self.pattern.search(input_str))

# SQL Injection Detection Rules
SQL_INJECTION_RULES = [
    WAFRule(
        'SQL-001',
        'SQL Union Attack',
        r'\bUNION\b.*\bSELECT\b',
        'high',
        'Detects UNION-based SQL injection attempts'
    ),
    WAFRule(
        'SQL-002',
        'SQL Comment Injection',
        r'(--|#|/\*|\*/)',
        'high',
        'Detects SQL comment characters used to bypass authentication'
    ),
    WAFRule(
        'SQL-003',
        'SQL Time-Based Blind',
        r'\b(SLEEP|WAITFOR|DELAY|BENCHMARK)\b',
        'high',
        'Detects time-based blind SQL injection'
    ),
    WAFRule(
        'SQL-004',
        'SQL Boolean Logic',
        r"(\bOR\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+|\bAND\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+)",
        'high',
        'Detects boolean-based SQL injection (e.g., 1=1, 1=0)'
    ),
    WAFRule(
        'SQL-005',
        'SQL String Concatenation',
        r"(\|\||CONCAT|CHR|CHAR)",
        'medium',
        'Detects SQL string concatenation functions'
    )
]

# XSS Detection Rules
XSS_RULES = [
    WAFRule(
        'XSS-001',
        'Script Tag Injection',
        r'<script[^>]*>.*?</script>',
        'high',
        'Detects <script> tag injection'
    ),
    WAFRule(
        'XSS-002',
        'Event Handler Injection',
        r'\bon\w+\s*=',
        'high',
        'Detects JavaScript event handlers (onclick, onload, etc.)'
    ),
    WAFRule(
        'XSS-003',
        'JavaScript Protocol',
        r'javascript:',
        'high',
        'Detects javascript: protocol in URLs'
    ),
    WAFRule(
        'XSS-004',
        'Iframe Injection',
        r'<iframe[^>]*>',
        'high',
        'Detects iframe tag injection'
    ),
    WAFRule(
        'XSS-005',
        'SVG Script Injection',
        r'<svg[^>]*>.*?<script',
        'medium',
        'Detects SVG-based XSS'
    )
]

# Command Injection Rules
COMMAND_INJECTION_RULES = [
    WAFRule(
        'CMD-001',
        'Command Chaining',
        r'[;&|`]',
        'high',
        'Detects command chaining characters'
    ),
    WAFRule(
        'CMD-002',
        'Command Substitution',
        r'\$\(|\`',
        'high',
        'Detects command substitution attempts'
    ),
    WAFRule(
        'CMD-003',
        'File Operation Commands',
        r'\b(cat|ls|rm|cp|mv|chmod|chown)\b',
        'medium',
        'Detects common file operation commands'
    )
]

# Path Traversal Rules
PATH_TRAVERSAL_RULES = [
    WAFRule(
        'PATH-001',
        'Directory Traversal',
        r'\.\.[/\\]',
        'high',
        'Detects directory traversal attempts (../)'
    ),
    WAFRule(
        'PATH-002',
        'URL Encoded Traversal',
        r'%2e%2e[/\\]',
        'high',
        'Detects URL-encoded directory traversal'
    ),
    WAFRule(
        'PATH-003',
        'Absolute Path Access',
        r'^(/etc/|/proc/|/sys/|C:\\Windows\\)',
        'high',
        'Detects attempts to access sensitive system paths'
    )
]

# SSRF Detection Rules
SSRF_RULES = [
    WAFRule(
        'SSRF-001',
        'Localhost Access',
        r'(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)',
        'high',
        'Detects attempts to access localhost'
    ),
    WAFRule(
        'SSRF-002',
        'Private IP Range',
        r'(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2[0-9]|3[0-1])\.\d+\.\d+|192\.168\.\d+\.\d+)',
        'high',
        'Detects private IP address ranges'
    ),
    WAFRule(
        'SSRF-003',
        'Metadata Service',
        r'169\.254\.169\.254',
        'high',
        'Detects attempts to access cloud metadata service'
    )
]

class WAF:
    """Web Application Firewall"""
    
    def __init__(self):
        self.rules = {
            'sql': SQL_INJECTION_RULES,
            'xss': XSS_RULES,
            'cmd': COMMAND_INJECTION_RULES,
            'path': PATH_TRAVERSAL_RULES,
            'ssrf': SSRF_RULES
        }
    
    def check_input(self, input_str: str, rule_types: List[str] = None) -> Tuple[bool, List[Dict]]:
        """
        Check input against WAF rules
        
        Args:
            input_str: Input to check
            rule_types: List of rule types to check (default: all)
        
        Returns:
            (is_malicious, [matched_rules])
        """
        if not input_str:
            return False, []
        
        if rule_types is None:
            rule_types = self.rules.keys()
        
        matches = []
        
        for rule_type in rule_types:
            if rule_type not in self.rules:
                continue
            
            for rule in self.rules[rule_type]:
                if rule.matches(input_str):
                    matches.append({
                        'rule_id': rule.rule_id,
                        'name': rule.name,
                        'severity': rule.severity,
                        'description': rule.description,
                        'type': rule_type
                    })
        
        return len(matches) > 0, matches
    
    def get_rules_info(self) -> Dict:
        """Get information about all WAF rules"""
        info = {}
        for rule_type, rules in self.rules.items():
            info[rule_type] = [
                {
                    'rule_id': rule.rule_id,
                    'name': rule.name,
                    'severity': rule.severity,
                    'description': rule.description
                }
                for rule in rules
            ]
        return info

# Global WAF instance
_waf = WAF()

def get_waf() -> WAF:
    """Get the global WAF instance"""
    return _waf

def check_for_attacks(input_str: str, attack_types: List[str] = None) -> Tuple[bool, List[Dict]]:
    """
    Convenience function to check input for attacks
    
    Args:
        input_str: Input to check
        attack_types: Types of attacks to check for
    
    Returns:
        (is_attack_detected, [matched_rules])
    """
    waf = get_waf()
    return waf.check_input(input_str, attack_types)
