"""
OWASP Web Top 10 2021 - A06: Vulnerable and Outdated Components
RED TEAM (Vulnerable) Endpoints

This module demonstrates vulnerable component usage including:
- Using outdated libraries with known CVEs
- Known vulnerable dependencies
- Dependency confusion attacks
- Unpatched components with public exploits

Author: AegisForge Security Team
Version: 1.0
WARNING: These endpoints are intentionally insecure for educational purposes only
"""

from flask import Blueprint, request, jsonify
import json
from datetime import datetime

# Create blueprint
a06_vulnerable_components_red = Blueprint('a06_vulnerable_components_red', __name__)

# Simulated vulnerable component database
VULNERABLE_COMPONENTS = {
    'requests': {
        'current_version': '2.25.0',
        'latest_version': '2.31.0',
        'cve': 'CVE-2023-32681',
        'severity': 'CRITICAL',
        'description': 'Proxy-Authorization header leak in redirects',
        'exploit_available': True,
        'public_since': '2023-05-22'
    },
    'pillow': {
        'current_version': '8.0.0',
        'latest_version': '10.2.0',
        'cve': 'CVE-2023-50447',
        'severity': 'HIGH',
        'description': 'Arbitrary code execution via crafted image',
        'exploit_available': True,
        'public_since': '2023-12-31'
    },
    'flask': {
        'current_version': '1.0.2',
        'latest_version': '3.0.0',
        'cve': 'CVE-2023-30861',
        'severity': 'HIGH',
        'description': 'Cookie parsing vulnerability',
        'exploit_available': False,
        'public_since': '2023-05-02'
    },
    'pyyaml': {
        'current_version': '5.3',
        'latest_version': '6.0.1',
        'cve': 'CVE-2020-14343',
        'severity': 'CRITICAL',
        'description': 'Arbitrary code execution via unsafe YAML loading',
        'exploit_available': True,
        'public_since': '2020-07-15'
    }
}


@a06_vulnerable_components_red.route('/api/red/vulnerable-components/outdated-library', methods=['GET'])
def outdated_library():
    """
    VULNERABLE: Using severely outdated libraries with known vulnerabilities
    
    Problem: Application uses old versions of libraries with publicly known CVEs.
    Attackers can easily find and exploit these known vulnerabilities.
    
    How to exploit:
    1. Identify library versions (via headers, error messages, or this endpoint)
    2. Search CVE databases for known vulnerabilities
    3. Use public exploits or Metasploit modules
    4. Gain RCE, data theft, or DoS
    
    Example: GET /api/red/vulnerable-components/outdated-library?check=all
    """
    try:
        check_component = request.args.get('check', 'all')
        
        # VULNERABLE: Exposing exact versions of all components
        dependencies = {
            'python': '3.7.9',  # EOL since 2023-06-27
            'flask': '1.0.2',   # Very old, has CVEs
            'requests': '2.25.0',  # CVE-2023-32681
            'pillow': '8.0.0',     # CVE-2023-50447
            'pyyaml': '5.3',       # CVE-2020-14343
            'urllib3': '1.26.5',   # CVE-2023-45803
            'jinja2': '2.11.2',    # CVE-2024-22195
            'werkzeug': '1.0.1'    # Multiple CVEs
        }
        
        if check_component == 'all':
            # VULNERABLE: Returning complete dependency list with versions
            vulnerabilities = []
            for lib, version in dependencies.items():
                if lib in VULNERABLE_COMPONENTS:
                    vuln_info = VULNERABLE_COMPONENTS[lib]
                    vulnerabilities.append({
                        'library': lib,
                        'installed_version': version,
                        'latest_version': vuln_info['latest_version'],
                        'cve': vuln_info['cve'],
                        'severity': vuln_info['severity'],
                        'years_outdated': 2024 - int(version.split('.')[0])
                    })
            
            return jsonify({
                'ok': True,
                'dependencies': dependencies,
                'vulnerable_components': vulnerabilities,
                'total_vulnerabilities': len(vulnerabilities),
                'vulnerability': 'Outdated components with known CVEs',
                'exploit_hint': 'Search exploit-db.com or Metasploit for these CVEs'
            }), 200
        else:
            # Return specific component
            version = dependencies.get(check_component, 'unknown')
            vuln_info = VULNERABLE_COMPONENTS.get(check_component, {})
            
            return jsonify({
                'ok': True,
                'component': check_component,
                'version': version,
                'vulnerability_info': vuln_info,
                'vulnerability': f'Using outdated {check_component} version'
            }), 200
            
    except Exception as e:
        return jsonify({
            'ok': False,
            'error': str(e)
        }), 500


@a06_vulnerable_components_red.route('/api/red/vulnerable-components/known-cve', methods=['POST'])
def known_cve_exploitation():
    """
    VULNERABLE: Known CVE can be exploited (YAML deserialization)
    
    Problem: PyYAML 5.3 has CVE-2020-14343 allowing arbitrary code execution
    via yaml.load() with untrusted input (instead of yaml.safe_load()).
    
    How to exploit:
    1. Send YAML payload with Python object constructor
    2. Trigger arbitrary code execution via !!python/object/apply
    3. Execute system commands or exfiltrate data
    
    Example payload:
    {
        "data": "!!python/object/apply:os.system ['echo pwned > /tmp/hacked']"
    }
    
    Note: This is a simulation - actual execution disabled for safety
    """
    try:
        data = request.get_json()
        yaml_data = data.get('data', '')
        
        # VULNERABLE: Simulating unsafe YAML loading
        # In real vulnerable code: yaml.load(yaml_data)  # DANGEROUS!
        
        # For safety, we simulate the vulnerability without actually executing
        if '!!python/object/apply' in yaml_data or '!!python/object/new' in yaml_data:
            return jsonify({
                'ok': True,
                'message': 'YAML processed (exploitation simulated for safety)',
                'vulnerability': 'CVE-2020-14343: Arbitrary code execution via YAML deserialization',
                'vulnerable_code': 'yaml.load(untrusted_input)',
                'attack_detected': True,
                'payload_type': 'Python object constructor',
                'exploit_hint': 'In real scenario, this would execute arbitrary code',
                'dangerous_patterns': [
                    '!!python/object/apply:os.system',
                    '!!python/object/apply:subprocess.check_output',
                    '!!python/object/new:os.system'
                ],
                'severity': 'CRITICAL',
                'cvss_score': 9.8
            }), 200
        
        return jsonify({
            'ok': True,
            'message': 'YAML data processed',
            'data_received': yaml_data,
            'vulnerability': 'Using PyYAML 5.3 with yaml.load() instead of yaml.safe_load()',
            'exploit_hint': 'Try YAML payload with !!python/object/apply constructor'
        }), 200
        
    except Exception as e:
        return jsonify({
            'ok': False,
            'error': str(e),
            'vulnerability': 'Vulnerable YAML parser'
        }), 500


@a06_vulnerable_components_red.route('/api/red/vulnerable-components/dependency-confusion', methods=['POST'])
def dependency_confusion():
    """
    VULNERABLE: Dependency confusion / substitution attack
    
    Problem: Application doesn't verify package sources, allowing attackers to:
    1. Create malicious package with same name as internal package
    2. Publish to public PyPI with higher version number
    3. Build system pulls malicious public package instead of internal one
    
    How to exploit:
    1. Identify internal package names (often leaked in error messages)
    2. Create malicious package with same name
    3. Publish to public repository with version 99.99.99
    4. Wait for build system to pull your malicious package
    
    Example:
    Internal package: company-auth-lib 1.0.0 (private PyPI)
    Attacker creates: company-auth-lib 99.99.99 (public PyPI)
    Build pulls: Attacker's package (higher version)
    """
    try:
        data = request.get_json()
        package_name = data.get('package_name', '')
        package_version = data.get('version', '')
        
        # VULNERABLE: No verification of package source
        # VULNERABLE: No checksums or signature verification
        # VULNERABLE: Trusts version numbers without source verification
        
        # Simulate internal packages that could be confused
        internal_packages = [
            'aegisforge-auth',
            'aegisforge-utils',
            'company-internal-api',
            'private-crypto-lib'
        ]
        
        if package_name in internal_packages:
            return jsonify({
                'ok': True,
                'message': f'Installing {package_name} version {package_version}',
                'vulnerability': 'Dependency confusion - no source verification',
                'risk': 'Attacker could publish malicious package with same name to public PyPI',
                'exploitation_scenario': {
                    'step_1': 'Attacker discovers internal package name',
                    'step_2': 'Attacker publishes malicious package to public PyPI',
                    'step_3': 'Attacker uses high version number (99.99.99)',
                    'step_4': 'Build system pulls public package instead of internal',
                    'step_5': 'Malicious code executes during installation'
                },
                'real_world_impact': {
                    'microsoft': '2021 - Alex Birsan earned $130,000 bug bounty',
                    'apple': 'Affected by dependency confusion',
                    'paypal': 'Affected by dependency confusion',
                    'netflix': 'Affected by dependency confusion'
                },
                'exploit_hint': 'Create package on PyPI with same name and version 99.99.99'
            }), 200
        
        return jsonify({
            'ok': True,
            'message': f'Package {package_name} installed',
            'vulnerability': 'No package source verification',
            'exploit_hint': 'Try an internal package name like aegisforge-auth'
        }), 200
        
    except Exception as e:
        return jsonify({
            'ok': False,
            'error': str(e)
        }), 500


@a06_vulnerable_components_red.route('/api/red/vulnerable-components/unpatched', methods=['GET'])
def unpatched_vulnerability():
    """
    VULNERABLE: Unpatched component with active exploit in the wild
    
    Problem: Known vulnerability with public exploit, but component not patched.
    Often due to:
    - Lack of dependency monitoring
    - Fear of breaking changes when updating
    - Unaware of the vulnerability
    - No patch management process
    
    How to exploit:
    1. Scan for vulnerable versions (e.g., using Nmap, Nikto, or Nuclei)
    2. Use public exploit from Exploit-DB or Metasploit
    3. Often leads to RCE, SQL injection, or authentication bypass
    
    Example vulnerabilities shown:
    - Requests 2.25.0: Proxy header leak (CVE-2023-32681)
    - Pillow 8.0.0: RCE via image (CVE-2023-50447)
    """
    try:
        component = request.args.get('component', 'all')
        
        # VULNERABLE: Exposing unpatched vulnerabilities
        unpatched_vulns = []
        
        for lib_name, vuln_info in VULNERABLE_COMPONENTS.items():
            if component == 'all' or component == lib_name:
                if vuln_info['exploit_available']:
                    unpatched_vulns.append({
                        'component': lib_name,
                        'version': vuln_info['current_version'],
                        'cve': vuln_info['cve'],
                        'severity': vuln_info['severity'],
                        'description': vuln_info['description'],
                        'public_since': vuln_info['public_since'],
                        'days_unpatched': (datetime.now() - datetime.fromisoformat(vuln_info['public_since'])).days,
                        'exploit_available': True,
                        'metasploit_module': f'exploit/multi/http/{lib_name}_cve',
                        'exploit_db_link': f'https://exploit-db.com/search?cve={vuln_info["cve"]}'
                    })
        
        return jsonify({
            'ok': True,
            'unpatched_vulnerabilities': unpatched_vulns,
            'total_critical': sum(1 for v in unpatched_vulns if v['severity'] == 'CRITICAL'),
            'total_high': sum(1 for v in unpatched_vulns if v['severity'] == 'HIGH'),
            'vulnerability': 'Multiple unpatched components with public exploits',
            'risk_level': 'CRITICAL',
            'exploit_hint': 'Use Metasploit or Exploit-DB to find working exploits',
            'real_world_example': {
                'equifax_breach': 'Apache Struts CVE-2017-5638 (2 months unpatched)',
                'impact': '147 million people affected',
                'cost': '$1.4 billion in fines and settlements'
            }
        }), 200
        
    except Exception as e:
        return jsonify({
            'ok': False,
            'error': str(e)
        }), 500


@a06_vulnerable_components_red.route('/api/red/vulnerable-components/info', methods=['GET'])
def vulnerable_components_info():
    """
    Get information about A06: Vulnerable and Outdated Components
    """
    return jsonify({
        'category': 'A06: Vulnerable and Outdated Components',
        'description': 'Using components with known vulnerabilities or outdated versions',
        'vulnerabilities': [
            {
                'name': 'Outdated Library',
                'endpoint': '/api/red/vulnerable-components/outdated-library',
                'method': 'GET',
                'description': 'Multiple severely outdated libraries with CVEs',
                'severity': 'HIGH'
            },
            {
                'name': 'Known CVE Exploitation',
                'endpoint': '/api/red/vulnerable-components/known-cve',
                'method': 'POST',
                'description': 'PyYAML deserialization RCE (CVE-2020-14343)',
                'severity': 'CRITICAL'
            },
            {
                'name': 'Dependency Confusion',
                'endpoint': '/api/red/vulnerable-components/dependency-confusion',
                'method': 'POST',
                'description': 'Package substitution attack possible',
                'severity': 'HIGH'
            },
            {
                'name': 'Unpatched Vulnerabilities',
                'endpoint': '/api/red/vulnerable-components/unpatched',
                'method': 'GET',
                'description': 'Known vulnerabilities with public exploits',
                'severity': 'CRITICAL'
            }
        ],
        'affected_components': VULNERABLE_COMPONENTS,
        'owasp_reference': 'https://owasp.org/Top10/A06_2021-Vulnerable_and_Outdated_Components/',
        'testing_guide': '/docs/vulnerabilities/owasp-web-2021/A06_VULNERABLE_COMPONENTS.md',
        'tools_for_detection': [
            'OWASP Dependency-Check',
            'Snyk',
            'npm audit',
            'pip-audit',
            'GitHub Dependabot',
            'Trivy',
            'Grype'
        ]
    }), 200
