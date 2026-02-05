"""
Infrastructure-as-Code security analyzers.

Each analyzer provides:
- Resource extraction
- Misconfiguration detection
- Best practice validation
"""

# Lazy imports to avoid circular dependencies
def _import_analyzers():
    from . import terraform
    from . import kubernetes
    from . import cloudformation
    from . import dockerfile

# Import on first access
_import_analyzers()

__all__ = [
    'terraform',
    'kubernetes',
    'cloudformation',
    'dockerfile',
]
