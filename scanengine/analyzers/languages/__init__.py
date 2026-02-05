"""
Language-specific AST analyzers.

Each analyzer uses tree-sitter for parsing and provides:
- Dangerous sink detection
- Taint source identification
- Class/function extraction
- Method call tracking
"""

def _import_analyzers():
    """Lazy import to trigger registration."""
    from . import go
    from . import csharp
    from . import kotlin
    from . import php
    from . import ruby
    from . import rust
    from . import swift

_import_analyzers()

__all__ = [
    'go',
    'csharp',
    'kotlin',
    'php',
    'ruby',
    'rust',
    'swift',
]
