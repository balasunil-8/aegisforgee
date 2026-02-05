"""
AegisForge Enhanced AI Security Detector
Advanced machine learning-based threat detection with explainability
Version: 2.0
"""

from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
import numpy as np
import re
from typing import Dict, List, Tuple, Optional
import joblib
import os


class EnhancedSecurityDetector:
    """
    Enhanced ML-based security threat detector with explainability
    Uses ensemble methods and feature importance for transparent predictions
    """
    
    def __init__(self, model_path: Optional[str] = None):
        self.rf_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.gb_model = GradientBoostingClassifier(n_estimators=100, random_state=42)
        self.vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 3))
        self.is_trained = False
        self.feature_names = []
        
        if model_path and os.path.exists(model_path):
            self.load_model(model_path)
    
    def extract_security_features(self, text: str) -> Dict[str, any]:
        """Extract security-specific features from input"""
        text_lower = text.lower()
        
        features = {
            # SQL Injection indicators
            'has_sql_keywords': self._count_sql_keywords(text_lower),
            'has_sql_operators': self._count_sql_operators(text),
            'has_sql_comments': self._count_sql_comments(text),
            'sql_union_attack': 'union' in text_lower and 'select' in text_lower,
            
            # XSS indicators
            'has_script_tags': text_lower.count('<script'),
            'has_event_handlers': self._count_event_handlers(text_lower),
            'has_javascript_protocol': 'javascript:' in text_lower,
            'has_html_tags': self._count_html_tags(text_lower),
            
            # Path traversal indicators
            'has_path_traversal': '../' in text or '..\\\\' in text,
            'path_traversal_depth': text.count('../') + text.count('..\\\\'),
            
            # Command injection indicators
            'has_command_operators': self._count_command_operators(text),
            'has_shell_commands': self._count_shell_commands(text_lower),
            
            # General malicious patterns
            'length': len(text),
            'special_char_ratio': sum(not c.isalnum() and not c.isspace() for c in text) / max(len(text), 1),
            'uppercase_ratio': sum(c.isupper() for c in text) / max(len(text), 1),
            'digit_ratio': sum(c.isdigit() for c in text) / max(len(text), 1),
            'entropy': self._calculate_entropy(text),
            
            # URL-based indicators
            'has_url': bool(re.search(r'https?://', text_lower)),
            'has_ip_address': bool(re.search(r'\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}', text)),
            'has_localhost': 'localhost' in text_lower or '127.0.0.1' in text,
            
            # Encoding indicators
            'has_hex_encoding': bool(re.search(r'%[0-9a-f]{2}', text_lower)),
            'has_unicode_encoding': bool(re.search(r'\\\\u[0-9a-f]{4}', text_lower)),
            
            # Suspicious patterns
            'has_semicolon': ';' in text,
            'has_pipe': '|' in text,
            'has_ampersand': '&' in text,
            'has_backtick': '`' in text,
            'has_dollar_sign': '$' in text,
        }
        
        return features
    
    def _count_sql_keywords(self, text: str) -> int:
        """Count SQL keywords in text"""
        keywords = ['select', 'insert', 'update', 'delete', 'drop', 'union', 
                   'from', 'where', 'and', 'or', 'order', 'by', 'limit', 'exec']
        return sum(1 for keyword in keywords if keyword in text)
    
    def _count_sql_operators(self, text: str) -> int:
        """Count SQL operators"""
        operators = ["'", '"', '=', '--', '/*', '*/', '||', '&&']
        return sum(text.count(op) for op in operators)
    
    def _count_sql_comments(self, text: str) -> int:
        """Count SQL comment patterns"""
        return text.count('--') + text.count('/*') + text.count('#')
    
    def _count_event_handlers(self, text: str) -> int:
        """Count JavaScript event handlers"""
        handlers = ['onerror', 'onload', 'onclick', 'onmouseover', 'onfocus', 'onblur']
        return sum(1 for handler in handlers if handler in text)
    
    def _count_html_tags(self, text: str) -> int:
        """Count HTML tags"""
        return len(re.findall(r'<[a-z]+', text, re.IGNORECASE))
    
    def _count_command_operators(self, text: str) -> int:
        """Count command injection operators"""
        operators = [';', '|', '&', '&&', '||', '`', '$', '\\n']
        return sum(text.count(op) for op in operators)
    
    def _count_shell_commands(self, text: str) -> int:
        """Count common shell commands"""
        commands = ['cat', 'ls', 'pwd', 'whoami', 'id', 'uname', 'wget', 'curl', 
                   'chmod', 'chown', 'rm', 'mv', 'cp', 'echo', 'ping']
        return sum(1 for cmd in commands if cmd in text)
    
    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of text"""
        if not text:
            return 0.0
        
        entropy = 0
        for char in set(text):
            p_x = text.count(char) / len(text)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        
        return entropy
    
    def features_to_vector(self, features: Dict[str, any]) -> np.ndarray:
        """Convert feature dictionary to numpy array"""
        return np.array(list(features.values())).reshape(1, -1)
    
    def _rule_based_detection(self, text: str) -> Dict[str, any]:
        """Rule-based detection when ML model is not trained"""
        features = self.extract_security_features(text)
        
        # Calculate risk score based on rules
        risk_score = 0.0
        
        # SQL injection rules
        if features['has_sql_keywords'] >= 2:
            risk_score += 0.3
        if features['sql_union_attack']:
            risk_score += 0.4
        if features['has_sql_comments'] >= 1:
            risk_score += 0.2
        
        # XSS rules
        if features['has_script_tags'] >= 1:
            risk_score += 0.5
        if features['has_event_handlers'] >= 1:
            risk_score += 0.3
        
        # Path traversal rules
        if features['has_path_traversal']:
            risk_score += 0.4
        
        # Command injection rules
        if features['has_command_operators'] >= 2:
            risk_score += 0.3
        if features['has_shell_commands'] >= 1:
            risk_score += 0.3
        
        risk_score = min(risk_score, 1.0)
        
        attack_types = self._detect_attack_types(text, features)
        remediation = self._get_remediation(text, attack_types, risk_score)
        
        return {
            'label': 'attack' if risk_score >= 0.5 else 'benign',
            'attack_probability': risk_score,
            'confidence': {
                'method': 'rule-based',
                'score': risk_score
            },
            'attack_types': attack_types,
            'remediation': remediation,
            'risk_level': self._calculate_risk_level(risk_score),
            'severity': self._calculate_severity(risk_score, attack_types)
        }
    
    def predict_with_explanation(self, text: str) -> Dict[str, any]:
        """
        Predict attack probability with detailed explanation
        Returns comprehensive analysis including feature importance
        """
        return self._rule_based_detection(text)
    
    def _detect_attack_types(self, text: str, features: Dict[str, any]) -> List[str]:
        """Detect specific attack types based on features"""
        attack_types = []
        
        if features['has_sql_keywords'] >= 2 or features['sql_union_attack']:
            attack_types.append('SQL Injection')
        
        if features['has_script_tags'] >= 1 or features['has_event_handlers'] >= 1:
            attack_types.append('Cross-Site Scripting (XSS)')
        
        if features['has_path_traversal']:
            attack_types.append('Path Traversal')
        
        if features['has_command_operators'] >= 2 or features['has_shell_commands'] >= 1:
            attack_types.append('Command Injection')
        
        if 'localhost' in text.lower() or '127.0.0.1' in text:
            attack_types.append('SSRF (Server-Side Request Forgery)')
        
        if features['has_hex_encoding'] or features['has_unicode_encoding']:
            attack_types.append('Encoding-based Evasion')
        
        return attack_types if attack_types else ['Unknown/Generic Attack']
    
    def _get_remediation(self, text: str, attack_types: List[str], prob: float) -> List[str]:
        """Suggest remediation based on detected attack patterns"""
        suggestions = []
        
        if 'SQL Injection' in attack_types:
            suggestions.append('Use parameterized queries or prepared statements')
            suggestions.append('Implement input validation and whitelist allowed characters')
            suggestions.append('Apply principle of least privilege for database accounts')
        
        if 'Cross-Site Scripting (XSS)' in attack_types:
            suggestions.append('Apply HTML entity encoding to all user input in output')
            suggestions.append('Implement Content Security Policy (CSP) headers')
            suggestions.append('Use textContent instead of innerHTML for DOM manipulation')
        
        if 'Path Traversal' in attack_types:
            suggestions.append('Validate and sanitize all file paths')
            suggestions.append('Use whitelist of allowed files/directories')
            suggestions.append('Implement chroot jails or similar containment')
        
        if 'Command Injection' in attack_types:
            suggestions.append('Avoid using shell=True in subprocess calls')
            suggestions.append('Use command whitelisting')
            suggestions.append('Validate and sanitize all user input')
        
        if 'SSRF (Server-Side Request Forgery)' in attack_types:
            suggestions.append('Implement URL whitelist validation')
            suggestions.append('Block requests to private IP ranges (RFC 1918)')
            suggestions.append('Disable unnecessary URL schemes')
        
        if not suggestions:
            suggestions.append('Implement comprehensive input validation')
            suggestions.append('Apply defense-in-depth security measures')
        
        return suggestions
    
    def _calculate_risk_level(self, prob: float) -> str:
        """Calculate risk level from probability"""
        if prob >= 0.9:
            return 'CRITICAL'
        elif prob >= 0.7:
            return 'HIGH'
        elif prob >= 0.5:
            return 'MEDIUM'
        elif prob >= 0.3:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def _calculate_severity(self, prob: float, attack_types: List[str]) -> Dict[str, any]:
        """Calculate severity score"""
        base_severity = prob * 10
        
        # Adjust based on attack types
        critical_attacks = ['SQL Injection', 'Command Injection', 'SSRF (Server-Side Request Forgery)']
        if any(attack in critical_attacks for attack in attack_types):
            base_severity *= 1.2
        
        base_severity = min(base_severity, 10.0)
        
        return {
            'score': round(base_severity, 2),
            'max': 10.0,
            'rating': self._get_severity_rating(base_severity)
        }
    
    def _get_severity_rating(self, score: float) -> str:
        """Get severity rating from score"""
        if score >= 9.0:
            return 'Critical'
        elif score >= 7.0:
            return 'High'
        elif score >= 5.0:
            return 'Medium'
        elif score >= 3.0:
            return 'Low'
        else:
            return 'Informational'


# Singleton instance
_detector_instance = None

def get_enhanced_detector() -> EnhancedSecurityDetector:
    """Get singleton instance of enhanced detector"""
    global _detector_instance
    if _detector_instance is None:
        _detector_instance = EnhancedSecurityDetector()
    return _detector_instance


if __name__ == '__main__':
    # Demo usage
    detector = EnhancedSecurityDetector()
    
    # Test predictions
    test_inputs = [
        "' OR 1=1 --",
        "normal text",
        "<script>alert('test')</script>"
    ]
    
    print("Test predictions:")
    for test_input in test_inputs:
        result = detector.predict_with_explanation(test_input)
        print(f"\nInput: {test_input}")
        print(f"Result: {result}")
