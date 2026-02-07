"""
AegisForge OWASP Module Integration
This module registers all OWASP vulnerability endpoints (both Red and Blue Team)
into the main Flask application.

Usage:
    from owasp_integration import register_owasp_modules
    register_owasp_modules(app)
"""

def register_owasp_modules(app):
    """
    Register all OWASP vulnerability modules as blueprints
    
    Args:
        app: Flask application instance
    """
    try:
        # OWASP Web Top 10 2021
        from backend.owasp.web_2021.a04_insecure_design_red import a04_insecure_design_red
        from backend.owasp.web_2021.a04_insecure_design_blue import a04_insecure_design_blue
        
        app.register_blueprint(a04_insecure_design_red)
        app.register_blueprint(a04_insecure_design_blue)
        
        print("✓ Registered A04: Insecure Design endpoints")
        
    except ImportError as e:
        print(f"⚠️ Could not import OWASP modules: {e}")
    except Exception as e:
        print(f"⚠️ Error registering OWASP modules: {e}")
    
    return app


def get_owasp_endpoints():
    """
    Get a list of all OWASP endpoints for documentation
    
    Returns:
        dict: Categorized list of endpoints
    """
    endpoints = {
        'owasp_web_2021': {
            'A04_Insecure_Design': {
                'red_team': [
                    {
                        'path': '/api/red/insecure-design/race-condition',
                        'method': 'POST',
                        'description': 'Race condition in order processing'
                    },
                    {
                        'path': '/api/red/insecure-design/workflow-bypass',
                        'method': 'POST',
                        'description': 'Workflow bypass allowing payment skip'
                    },
                    {
                        'path': '/api/red/insecure-design/trust-boundary',
                        'method': 'POST',
                        'description': 'Trust boundary violation (client-side price)'
                    },
                    {
                        'path': '/api/red/insecure-design/missing-limits',
                        'method': 'POST',
                        'description': 'Missing resource limits and rate limiting'
                    },
                    {
                        'path': '/api/red/insecure-design/info',
                        'method': 'GET',
                        'description': 'Information about A04 vulnerabilities'
                    }
                ],
                'blue_team': [
                    {
                        'path': '/api/blue/insecure-design/race-condition',
                        'method': 'POST',
                        'description': 'Secure: Idempotency and locking'
                    },
                    {
                        'path': '/api/blue/insecure-design/workflow-bypass',
                        'method': 'POST',
                        'description': 'Secure: State machine validation'
                    },
                    {
                        'path': '/api/blue/insecure-design/trust-boundary',
                        'method': 'POST',
                        'description': 'Secure: Server-side validation'
                    },
                    {
                        'path': '/api/blue/insecure-design/missing-limits',
                        'method': 'POST',
                        'description': 'Secure: Rate limiting and resource limits'
                    },
                    {
                        'path': '/api/blue/insecure-design/info',
                        'method': 'GET',
                        'description': 'Information about secure design patterns'
                    }
                ]
            }
        }
    }
    
    return endpoints


if __name__ == '__main__':
    # Test import
    endpoints = get_owasp_endpoints()
    import json
    print(json.dumps(endpoints, indent=2))
