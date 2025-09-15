'''
SecureWipe India - Basic Tests
'''

import unittest
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'src'))

class TestSecureWipe(unittest.TestCase):
    '''Basic tests for SecureWipe India'''
    
    def test_import_core(self):
        '''Test that core modules can be imported'''
        try:
            from src.core.engine import SecureWipeEngine
            self.assertTrue(True)
        except ImportError as e:
            self.fail(f"Failed to import core engine: {e}")
    
    def test_import_utils(self):
        '''Test that utility modules can be imported'''
        try:
            from src.utils.constants import APP_NAME
            self.assertEqual(APP_NAME, "SecureWipe India")
        except ImportError as e:
            self.fail(f"Failed to import utils: {e}")
    
    def test_nist_levels(self):
        '''Test NIST compliance levels'''
        try:
            from src.core.engine import WipeLevel
            levels = [WipeLevel.CLEAR, WipeLevel.PURGE, WipeLevel.DESTROY]
            self.assertEqual(len(levels), 3)
        except ImportError as e:
            self.fail(f"Failed to import WipeLevel: {e}")

if __name__ == '__main__':
    unittest.main()