# 🤝 Contributing to AegisForge

Thank you for your interest in contributing to AegisForge! This document provides guidelines and instructions for contributing to the project.

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Testing Guidelines](#testing-guidelines)
- [Commit Message Guidelines](#commit-message-guidelines)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)
- [Security Vulnerabilities](#security-vulnerabilities)

---

## 📜 Code of Conduct

This project adheres to a Code of Conduct that all contributors are expected to follow. Please read [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before contributing.

---

## 🚀 Getting Started

### Prerequisites

- Python 3.8+ (3.10+ recommended)
- Git
- Basic understanding of web security concepts
- Familiarity with Flask and RESTful APIs

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:
```bash
git clone https://github.com/YOUR-USERNAME/aegisforgee.git
cd aegisforgee
```

3. Add upstream remote:
```bash
git remote add upstream https://github.com/balasunil-8/aegisforgee.git
```

---

## 🛠️ How to Contribute

### Areas Where We Need Help

- **New Vulnerability Scenarios**: Add OWASP vulnerability examples
- **Defense Mechanisms**: Implement new security controls
- **CTF Challenges**: Create educational security challenges
- **Documentation**: Improve guides, tutorials, and API docs
- **Testing**: Write unit tests, integration tests, or security tests
- **Bug Fixes**: Fix reported issues
- **Performance**: Optimize code and queries
- **UI/UX**: Improve dashboard and frontend components
- **Tool Integration**: Add support for new security testing tools

---

## 💻 Development Setup

### 1. Install Dependencies

```bash
# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # Linux/macOS
.\venv\Scripts\activate   # Windows

# Install dependencies
pip install -r requirements.txt
pip install -r requirements_pro.txt  # Optional
```

### 2. Configure Environment

```bash
# Copy environment template
cp .env.example .env

# Edit configuration as needed
nano .env
```

### 3. Initialize Database

```bash
python init_db.py
```

### 4. Run Development Server

```bash
python aegisforge_api.py
```

### 5. Run Tests

```bash
# Run all tests
python -m pytest

# Run specific test file
python test_endpoints.py
```

---

## 📐 Coding Standards

### Python Style Guide

We follow **PEP 8** with some modifications:

- **Line Length**: Maximum 100 characters (not 79)
- **Indentation**: 4 spaces (no tabs)
- **Quotes**: Single quotes for strings (unless string contains single quote)
- **Imports**: Grouped and sorted (standard lib, third-party, local)

### Code Structure

```python
# Standard library imports
import os
import sys
from typing import Dict, List, Optional

# Third-party imports
from flask import Flask, request, jsonify
from sqlalchemy import Column, Integer, String

# Local imports
from config import Config
from defenses.input_validation import sanitize_input
```

### Naming Conventions

- **Functions/Variables**: `snake_case`
- **Classes**: `PascalCase`
- **Constants**: `UPPER_SNAKE_CASE`
- **Private methods**: `_leading_underscore`

```python
# Good
def calculate_risk_score(vulnerability_type: str) -> int:
    pass

class SecurityValidator:
    MAX_ATTEMPTS = 3
    
    def validate_input(self, data: str) -> bool:
        pass
    
    def _internal_check(self) -> bool:
        pass

# Bad
def CalculateRiskScore(VulnerabilityType):
    pass
```

### Documentation

Use docstrings for all public functions, classes, and modules:

```python
def validate_sql_input(user_input: str, allow_wildcards: bool = False) -> str:
    """
    Validate and sanitize SQL input to prevent SQL injection.
    
    Args:
        user_input: Raw user input string
        allow_wildcards: Whether to allow SQL wildcard characters (%, _)
    
    Returns:
        Sanitized input string safe for SQL queries
    
    Raises:
        ValueError: If input contains malicious patterns
    
    Example:
        >>> validate_sql_input("admin' OR '1'='1")
        "admin OR 1=1"
    """
    pass
```

### Type Hints

Use type hints for function parameters and return values:

```python
from typing import Dict, List, Optional, Tuple

def get_vulnerability_info(vuln_id: int) -> Optional[Dict[str, str]]:
    pass

def calculate_scores(attempts: List[int]) -> Tuple[float, float]:
    pass
```

---

## 🧪 Testing Guidelines

### Writing Tests

- Write tests for all new features
- Maintain test coverage above 70%
- Include both positive and negative test cases
- Test edge cases and error conditions

### Test Structure

```python
import unittest
from aegisforge_api import app

class TestVulnerabilityEndpoint(unittest.TestCase):
    
    def setUp(self):
        """Set up test client and test data"""
        self.app = app.test_client()
        self.app.testing = True
    
    def test_sql_injection_vulnerable(self):
        """Test SQL injection vulnerability detection"""
        response = self.app.get('/api/vulnerable/sqli?id=1 OR 1=1')
        self.assertEqual(response.status_code, 200)
        self.assertIn('admin', response.get_json())
    
    def test_sql_injection_secure(self):
        """Test SQL injection prevention in secure mode"""
        response = self.app.get('/api/secure/sqli?id=1 OR 1=1')
        self.assertEqual(response.status_code, 400)
        self.assertIn('Invalid input', response.get_json())
    
    def tearDown(self):
        """Clean up after tests"""
        pass

if __name__ == '__main__':
    unittest.main()
```

### Running Tests

```bash
# Run all tests
python -m pytest

# Run with coverage
python -m pytest --cov=. --cov-report=html

# Run specific test
python test_endpoints.py
```

---

## 💬 Commit Message Guidelines

### Format

```
<type>(<scope>): <subject>

<body>

<footer>
```

### Types

- **feat**: New feature
- **fix**: Bug fix
- **docs**: Documentation changes
- **style**: Code style changes (formatting, semicolons, etc.)
- **refactor**: Code refactoring
- **test**: Adding or updating tests
- **chore**: Maintenance tasks

### Examples

```bash
# Good
feat(ctf): add XSS challenge with DOM manipulation
fix(api): resolve SQL injection in user search endpoint
docs(readme): update installation instructions for Windows
test(auth): add unit tests for JWT token validation

# Bad
fixed stuff
update
changes
```

### Detailed Example

```
feat(defense): implement rate limiting for API endpoints

- Add Redis-based rate limiting
- Configure limits per endpoint and user role
- Add bypass for authenticated admin users
- Include rate limit headers in responses

Closes #123
```

---

## 🔄 Pull Request Process

### Before Submitting

1. **Update from upstream**:
```bash
git fetch upstream
git rebase upstream/main
```

2. **Run tests**:
```bash
python -m pytest
python test_endpoints.py
```

3. **Check code style**:
```bash
# Install flake8 if not installed
pip install flake8

# Run linter
flake8 . --max-line-length=100 --exclude=venv
```

4. **Update documentation** if needed

### Submitting PR

1. **Push to your fork**:
```bash
git push origin feature-branch-name
```

2. **Create Pull Request** on GitHub with:
   - Clear title describing the change
   - Detailed description of what and why
   - Reference related issues (e.g., "Closes #123")
   - Screenshots for UI changes
   - Test results if applicable

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Performance improvement
- [ ] Refactoring

## Related Issues
Closes #XXX

## Testing
- [ ] Unit tests pass
- [ ] Integration tests pass
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] No breaking changes
```

### Review Process

- PRs require at least one approval
- Address reviewer feedback promptly
- Keep PR scope focused and manageable
- Rebase if requested to resolve conflicts

---

## 🐛 Reporting Issues

### Before Creating an Issue

1. **Search existing issues** to avoid duplicates
2. **Check documentation** for known solutions
3. **Test with latest version** of AegisForge

### Issue Template

```markdown
## Description
Clear description of the issue

## Steps to Reproduce
1. Step one
2. Step two
3. ...

## Expected Behavior
What should happen

## Actual Behavior
What actually happens

## Environment
- OS: [e.g., Ubuntu 22.04]
- Python Version: [e.g., 3.10.5]
- AegisForge Version: [e.g., 2.0]
- Browser (if applicable): [e.g., Chrome 120]

## Additional Context
Screenshots, logs, or other relevant information
```

### Issue Labels

- `bug`: Something isn't working
- `enhancement`: New feature request
- `documentation`: Documentation improvement
- `good first issue`: Good for newcomers
- `help wanted`: Extra attention needed
- `security`: Security-related issue

---

## 🔒 Security Vulnerabilities

**DO NOT** report security vulnerabilities through public GitHub issues.

Instead, please report security issues to:
- **Email**: [Contact maintainer privately]
- **GitHub Security**: Use GitHub's security advisory feature

See [SECURITY.md](SECURITY.md) for detailed security policy.

---

## 📚 Additional Resources

### Learning Resources

- [Flask Documentation](https://flask.palletsprojects.com/)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)
- [Python Security Best Practices](https://python.readthedocs.io/en/latest/library/security_warnings.html)

### Project Documentation

- [README.md](README.md) - Project overview
- [INSTALL.md](INSTALL.md) - Installation guide
- [API_DOCUMENTATION.md](API_DOCUMENTATION.md) - API reference
- [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) - Production deployment

### Community

- **GitHub Discussions**: Ask questions and share ideas
- **Issue Tracker**: Report bugs and request features
- **Pull Requests**: Submit code contributions

---

## 🏆 Recognition

Contributors are recognized in:
- GitHub contributors list
- CHANGELOG.md for significant contributions
- README.md for major features

---

## 📝 License

By contributing to AegisForge, you agree that your contributions will be licensed under the MIT License.

---

**Thank you for contributing to AegisForge! Your efforts help make cybersecurity education better for everyone.** 🛡️
