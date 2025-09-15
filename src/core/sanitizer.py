"""
SecureWipe India - Data Sanitizer
Implements NIST 800-88 compliant data sanitization methods
"""

import os
import random
import hashlib
import subprocess
from typing import Callable, Optional, Dict, List
import logging

class DataSanitizer:
    """Implements various data sanitization methods according to NIST standards"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.patterns = {
            'zeros': b'\\x00',
            'ones': b'\\xFF',
            'random': None,  # Generated dynamically
            'dod_5220': [b'\\x00', b'\\xFF', b'\\x92'],  # DoD 5220.22-M
        }
    
    def single_pass_overwrite(self, device_path: str, 
                            progress_callback: Optional[Callable] = None) -> bool:
        """NIST Clear level - Single pass overwrite with zeros"""
        try:
            self.logger.info(f"Starting single pass overwrite: {device_path}")
            return self._overwrite_device(device_path, [b'\\x00'], progress_callback)
        except Exception as e:
            self.logger.error(f"Single pass overwrite failed: {e}")
            return False
    
    def multi_pass_overwrite(self, device_path: str, passes: int = 3,
                           progress_callback: Optional[Callable] = None) -> bool:
        """NIST Purge level - Multiple pass overwrite"""
        try:
            self.logger.info(f"Starting {passes}-pass overwrite: {device_path}")
            
            patterns = []
            for i in range(passes):
                if i == 0:
                    patterns.append(b'\\x00')  # First pass: zeros
                elif i == passes - 1:
                    patterns.append(self._generate_random_pattern())  # Last pass: random
                else:
                    patterns.append(b'\\xFF')  # Middle passes: ones
            
            return self._overwrite_device(device_path, patterns, progress_callback)
            
        except Exception as e:
            self.logger.error(f"Multi-pass overwrite failed: {e}")
            return False
    
    def secure_random_wipe(self, device_path: str, passes: int = 1,
                          progress_callback: Optional[Callable] = None) -> bool:
        """Cryptographically secure random overwrite"""
        try:
            self.logger.info(f"Starting secure random wipe ({passes} passes): {device_path}")
            patterns = [self._generate_crypto_random_pattern() for _ in range(passes)]
            return self._overwrite_device(device_path, patterns, progress_callback)
        except Exception as e:
            self.logger.error(f"Secure random wipe failed: {e}")
            return False
    
    def clear_hidden_areas(self, device_path: str) -> bool:
        """Clear Hidden Protected Areas (HPA) and Device Configuration Overlay (DCO)"""
        try:
            self.logger.info(f"Clearing hidden areas: {device_path}")
            
            success = True
            
            # Clear HPA (Host Protected Area)
            if not self._clear_hpa(device_path):
                self.logger.warning(f"Failed to clear HPA on {device_path}")
                success = False
            
            # Clear DCO (Device Configuration Overlay)
            if not self._clear_dco(device_path):
                self.logger.warning(f"Failed to clear DCO on {device_path}")
                success = False
            
            return success
            
        except Exception as e:
            self.logger.error(f"Hidden area clearing failed: {e}")
            return False
    
    def verify_wipe(self, device_path: str, wipe_level) -> Dict:
        """Verify that the wipe was successful"""
        try:
            self.logger.info(f"Verifying wipe: {device_path}")
            
            result = {
                "success": False,
                "passes": 0,
                "sectors_checked": 0,
                "non_zero_sectors": 0,
                "error": None
            }
            
            # Read random sectors and verify they're wiped
            device_size = self._get_device_size(device_path)
            if device_size == 0:
                return {"success": False, "error": "Cannot determine device size"}
                
            sector_size = 512  # Standard sector size
            sectors_to_check = min(1000, max(100, device_size // sector_size // 100))  # Check 1% or 1000 sectors
            
            non_zero_count = 0
            
            with open(device_path, 'rb') as device:
                for i in range(sectors_to_check):
                    # Random sector position
                    sector_pos = random.randint(0, (device_size // sector_size) - 1) * sector_size
                    device.seek(sector_pos)
                    data = device.read(sector_size)
                    
                    # Check if sector contains non-zero data
                    if any(byte != 0 for byte in data):
                        non_zero_count += 1
                        if non_zero_count > sectors_to_check * 0.01:  # More than 1% non-zero
                            break
            
            result["passes"] = 1
            result["sectors_checked"] = sectors_to_check
            result["non_zero_sectors"] = non_zero_count
            result["success"] = non_zero_count <= sectors_to_check * 0.01  # Allow 1% margin
            
            if result["success"]:
                self.logger.info(f"Wipe verification passed: {device_path}")
            else:
                self.logger.warning(f"Wipe verification failed: {non_zero_count}/{sectors_to_check} sectors contain data")
            
            return result
            
        except Exception as e:
            self.logger.error(f"Wipe verification failed: {e}")
            return {"success": False, "error": str(e)}
    
    def _overwrite_device(self, device_path: str, patterns: List[bytes],
                         progress_callback: Optional[Callable] = None) -> bool:
        """Core method to overwrite device with specified patterns"""
        try:
            device_size = self._get_device_size(device_path)
            if device_size == 0:
                self.logger.error(f"Cannot determine size of {device_path}")
                return False
                
            block_size = 1024 * 1024  # 1MB blocks for better performance
            total_blocks = device_size // block_size
            
            for pass_num, pattern in enumerate(patterns):
                self.logger.info(f"Pass {pass_num + 1}/{len(patterns)}: Writing pattern")
                
                with open(device_path, 'r+b') as device:
                    for block_num in range(total_blocks):
                        # Generate block data
                        if pattern is None or len(pattern) == 0:
                            block_data = self._generate_random_pattern(block_size)
                        else:
                            block_data = pattern * (block_size // len(pattern) + 1)
                            block_data = block_data[:block_size]
                        
                        # Write block
                        device.write(block_data)
                        device.flush()
                        
                        # Progress callback
                        if progress_callback:
                            progress = ((pass_num * total_blocks + block_num + 1) /
                                      (len(patterns) * total_blocks)) * 100
                            progress_callback(progress)
                    
                    # Handle remaining bytes
                    remaining = device_size % block_size
                    if remaining > 0:
                        if pattern is None:
                            remaining_data = self._generate_random_pattern(remaining)
                        else:
                            remaining_data = pattern * (remaining // len(pattern) + 1)
                            remaining_data = remaining_data[:remaining]
                        device.write(remaining_data)
                        device.flush()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Device overwrite failed: {e}")
            return False
    
    def _get_device_size(self, device_path: str) -> int:
        """Get the size of the device in bytes"""
        try:
            if not os.path.exists(device_path):
                return 0
                
            with open(device_path, 'rb') as device:
                device.seek(0, 2)  # Seek to end
                return device.tell()
        except Exception as e:
            self.logger.error(f"Failed to get device size: {e}")
            return 0
    
    def _generate_random_pattern(self, size: int = 1) -> bytes:
        """Generate random pattern using standard random"""
        return bytes([random.randint(0, 255) for _ in range(size)])
    
    def _generate_crypto_random_pattern(self, size: int = 1) -> bytes:
        """Generate cryptographically secure random pattern"""
        return os.urandom(size)
    
    def _clear_hpa(self, device_path: str) -> bool:
        """Clear Host Protected Area using hdparm"""
        try:
            # Check if HPA exists
            result = subprocess.run(['hdparm', '-N', device_path], 
                                  capture_output=True, text=True, timeout=30)
            if result.returncode != 0:
                return True  # No HPA or hdparm not available
            
            # Remove HPA
            result = subprocess.run(['hdparm', '-N', 'p', device_path], 
                                  capture_output=True, text=True, timeout=30)
            return result.returncode == 0
            
        except FileNotFoundError:
            self.logger.warning("hdparm not found, skipping HPA clearing")
            return True
        except Exception as e:
            self.logger.error(f"HPA clearing failed: {e}")
            return False
    
    def _clear_dco(self, device_path: str) -> bool:
        """Clear Device Configuration Overlay using hdparm"""
        try:
            # Remove DCO
            result = subprocess.run(['hdparm', '--dco-restore', device_path], 
                                  capture_output=True, text=True, timeout=30)
            return result.returncode == 0
            
        except FileNotFoundError:
            self.logger.warning("hdparm not found, skipping DCO clearing")
            return True
        except Exception as e:
            self.logger.error(f"DCO clearing failed: {e}")
            return False