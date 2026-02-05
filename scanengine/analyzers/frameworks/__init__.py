"""
Framework-specific security analyzers.

Each analyzer provides:
- Framework detection
- Endpoint discovery
- Security configuration analysis
- Framework-specific vulnerability patterns
"""

def _import_analyzers():
    """Lazy import to trigger registration."""
    from . import react
    from . import vue
    from . import angular
    from . import django
    from . import flask
    from . import rails
    from . import express
    from . import aspnet
    from . import gin
    from . import laravel
    from . import graphql
    from . import grpc
    from . import android
    from . import ios

_import_analyzers()

__all__ = [
    'react', 'vue', 'angular', 'django', 'flask', 'rails',
    'express', 'aspnet', 'gin', 'laravel', 'graphql', 'grpc',
    'android', 'ios',
]
