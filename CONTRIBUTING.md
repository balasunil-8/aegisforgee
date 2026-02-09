# 🤝 Contributing to AegisForge

Thank you for your interest in contributing to AegisForge! This document provides guidelines and instructions for contributing.

---

## 📋 Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Coding Standards](#coding-standards)
- [Submitting Changes](#submitting-changes)
- [Reporting Bugs](#reporting-bugs)
- [Suggesting Enhancements](#suggesting-enhancements)

---

## 📜 Code of Conduct

This project adheres to a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold this code. Please report unacceptable behavior to the project maintainers.

---

## 🎯 How Can I Contribute?

### 1. Adding New Vulnerabilities

We welcome new vulnerability examples! Here's how:

**Requirements:**
- Must be based on real-world security issues
- Should follow OWASP standards
- Needs both vulnerable (Red) and secure (Blue) implementations
- Must include documentation

**Structure:**
```python
# backend/apps/yourapp/yourapp_red_api.py
@app.route('/api/red/yourapp/vulnerable_endpoint', methods=['POST'])
def vulnerable_endpoint():
    # Intentionally vulnerable code
    pass

# backend/apps/yourapp/yourapp_blue_api.py
@app.route('/api/blue/yourapp/secure_endpoint', methods=['POST'])
def secure_endpoint():
    # Secure implementation with proper validation
    pass
```

**Documentation Required:**
- Vulnerability description
- Attack vectors
- Exploitation steps
- Remediation guide
- OWASP mapping

### 2. Improving Documentation

Documentation is crucial! You can:

- Fix typos and grammatical errors
- Add code examples
- Clarify existing explanations
- Create new tutorials
- Translate documentation

**Documentation Structure:**
```
docs/
├── apps/                    # Application-specific docs
├── security/                # Security guides
├── vulnerabilities/         # Vulnerability details
├── installation/            # Setup guides
└── getting-started/         # Beginner tutorials
```

### 3. Bug Fixes

Found a bug? Please:

1. Check [existing issues](https://github.com/balasunil-8/aegisforgee/issues)
2. Create a new issue if not reported
3. Fork the repository
4. Fix the bug
5. Submit a pull request

### 4. New Features

Want to add a feature? Please:

1. Open an issue for discussion
2. Wait for approval from maintainers
3. Fork and implement
4. Submit pull request with tests

### 5. Security Tool Integration

Adding a new tool integration:

**Required:**
- Setup guide
- Usage examples
- Tool-specific configurations
- Test cases

**Example:**
```
tools/newtool/
├── README.md           # Setup and usage
├── config.yaml         # Configuration
├── examples/           # Usage examples
└── scripts/            # Helper scripts
```

---

## 🛠️ Development Setup

### 1. Fork the Repository

Click "Fork" on the [GitHub repository](https://github.com/balasunil-8/aegisforgee)

### 2. Clone Your Fork

```bash
git clone https://github.com/YOUR_USERNAME/aegisforgee.git
cd aegisforgee
```

### 3. Create a Virtual Environment

**Windows:**
```batch
python -m venv venv
venv\Scripts\activate
```

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 4. Install Dependencies

```bash
pip install -r requirements.txt
```

### 5. Set Up Databases

```bash
# Windows
scripts\windows\init_databases.bat

# Linux/Mac
./scripts/linux/init_databases.sh
```

### 6. Create a Branch

```bash
git checkout -b feature/your-feature-name
# or
git checkout -b fix/bug-description
```

---

## 📝 Coding Standards

### Python Style Guide

Follow [PEP 8](https://pep8.org/) with these specifics:

**Indentation:**
```python
# Use 4 spaces (no tabs)
def my_function():
    if condition:
        do_something()
```

**Naming Conventions:**
```python
# Functions and variables: snake_case
def calculate_total():
    user_count = 10

# Classes: PascalCase
class UserManager:
    pass

# Constants: UPPER_SNAKE_CASE
MAX_RETRIES = 3
```

**Imports:**
```python
# Standard library first
import os
import sys

# Third-party packages
from flask import Flask
import sqlalchemy

# Local imports
from backend.utils import helper
```

**Documentation:**
```python
def transfer_funds(from_user, to_user, amount):
    """
    Transfer funds between users.
    
    Args:
        from_user (int): Source user ID
        to_user (int): Destination user ID
        amount (float): Amount to transfer
        
    Returns:
        bool: True if successful, False otherwise
        
    Raises:
        ValueError: If amount is negative
    """
    pass
```

### Flask API Conventions

**Endpoint naming:**
```python
# Pattern: /api/{mode}/{app}/{resource}
@app.route('/api/red/securebank/transfer', methods=['POST'])
@app.route('/api/blue/securebank/transfer', methods=['POST'])
```

**Response format:**
```python
# Success
{
    "success": true,
    "data": {...},
    "message": "Operation successful"
}

# Error
{
    "error": "Error message",
    "details": {...}
}
```

### Security Annotations

Mark intentionally vulnerable code:
```python
# VULNERABILITY: SQL Injection - Intentional for educational purposes
query = f"SELECT * FROM users WHERE username='{username}'"
cursor.execute(query)
```

Mark secure implementations:
```python
# SECURE: Parameterized query prevents SQL injection
query = "SELECT * FROM users WHERE username=?"
cursor.execute(query, (username,))
```

---

## 🚀 Submitting Changes

### 1. Commit Your Changes

Write clear, concise commit messages:

```bash
git add .
git commit -m "Add: SQL injection example in payment endpoint"
git commit -m "Fix: XSS vulnerability in profile update"
git commit -m "Docs: Update installation guide for macOS"
```

**Commit message format:**
```
<Type>: <Short description>

<Optional longer description>
<Optional references to issues>
```

**Types:**
- `Add:` New feature or file
- `Fix:` Bug fix
- `Docs:` Documentation changes
- `Refactor:` Code refactoring
- `Test:` Adding or updating tests
- `Style:` Code style changes

### 2. Push to Your Fork

```bash
git push origin feature/your-feature-name
```

### 3. Create Pull Request

1. Go to your fork on GitHub
2. Click "Pull Request"
3. Fill in the template:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Documentation update
- [ ] Code refactoring

## Testing
How was this tested?

## Checklist
- [ ] Code follows style guidelines
- [ ] Documentation updated
- [ ] Tests added/updated
- [ ] No breaking changes
```

### 4. Review Process

- Maintainers will review your PR
- Address any requested changes
- Once approved, your PR will be merged

---

## 🐛 Reporting Bugs

### Before Submitting

1. Check [existing issues](https://github.com/balasunil-8/aegisforgee/issues)
2. Verify the bug exists in the latest version
3. Gather relevant information

### Bug Report Template

```markdown
**Describe the Bug**
A clear description of what the bug is.

**To Reproduce**
Steps to reproduce:
1. Go to '...'
2. Click on '...'
3. See error

**Expected Behavior**
What you expected to happen.

**Screenshots**
If applicable, add screenshots.

**Environment:**
- OS: [e.g., Windows 10]
- Python Version: [e.g., 3.10]
- Browser: [e.g., Chrome 90]

**Additional Context**
Any other relevant information.
```

---

## 💡 Suggesting Enhancements

### Enhancement Template

```markdown
**Is your feature request related to a problem?**
A clear description of the problem.

**Describe the solution**
Your proposed solution.

**Describe alternatives**
Alternative solutions you've considered.

**Additional context**
Any other relevant information, mockups, or examples.
```

---

## 🧪 Testing Guidelines

### Unit Tests

Place tests in `tests/` directory:

```python
# tests/test_authentication.py
import pytest
from backend.apps.securebank.securebank_blue_api import app

def test_login_valid_credentials():
    """Test login with valid credentials"""
    client = app.test_client()
    response = client.post('/api/blue/securebank/login', json={
        'username': 'alice',
        'password': 'password123'
    })
    assert response.status_code == 200
    assert b'success' in response.data

def test_login_sql_injection_blocked():
    """Test that SQL injection is blocked"""
    client = app.test_client()
    response = client.post('/api/blue/securebank/login', json={
        'username': "admin' OR '1'='1",
        'password': 'anything'
    })
    assert response.status_code == 401
```

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_authentication.py

# Run with coverage
pytest --cov=backend
```

---

## 📚 Documentation Standards

### Markdown Style

- Use ATX-style headers (`#`)
- Include table of contents for long documents
- Add code blocks with language tags
- Use relative links for internal references

### Documentation Structure

```markdown
# Title

Brief introduction

## Section 1

Content...

### Subsection 1.1

Content...

## Section 2

Content...
```

---

## 🏆 Recognition

Contributors will be recognized in:
- `CONTRIBUTORS.md` file
- Release notes
- Project documentation

Top contributors may be invited to become maintainers.

---

## ❓ Questions?

- 💬 [GitHub Discussions](https://github.com/balasunil-8/aegisforgee/discussions)
- 📧 Open an issue
- 📖 Check documentation

---

<div align="center">

**Thank you for contributing to AegisForge! 🙏**

**[Code of Conduct](CODE_OF_CONDUCT.md)** • **[README](README.md)** • **[License](LICENSE)**

</div>
