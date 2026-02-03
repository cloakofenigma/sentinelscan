"""
Entry point for running as module: python -m scanengine
"""

import sys
from .cli import main

if __name__ == '__main__':
    sys.exit(main())
