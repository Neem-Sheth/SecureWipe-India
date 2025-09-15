#!/usr/bin/env python3
'''
SecureWipe India - Main Application Entry Point
'''

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

if __name__ == "__main__":
    try:
        from src.ui.main_gui import main
        sys.exit(main())
    except ImportError:
        print("GUI dependencies not available, starting CLI...")
        from src.ui.cli import main
        sys.exit(main())