"""
SecureWipe India - Core Engine
Orchestrates the entire data wiping process across platforms
"""

import os
import sys
import json
import logging
import platform
import time
from typing import Dict, List, Optional, Tuple
from enum import Enum
from dataclasses import dataclass

class WipeLevel(Enum):
    CLEAR = "clear"
    PURGE = "purge"
    DESTROY = "destroy"

@dataclass
class WipeResult:
    success: bool
    device_path: str
    wipe_level: WipeLevel
    duration_seconds: float
    certificate_path: Optional[str] = None
    error_message: Optional[str] = None
    verification_passes: int = 0

class SecureWipeEngine:
    """Main engine that coordinates the entire data wiping process"""
    
    def __init__(self, config_path: str = "config/settings.json"):
        self.config = self._load_config(config_path)
        self.logger = self._setup_logger()
        
        # Initialize components. Try importing via package-qualified names
        # (when running via the project entrypoint that adds 'src' to sys.path),
        # otherwise fall back to local relative imports.
        try:
            from src.core.sanitizer import DataSanitizer
            from src.core.detector import StorageDetector
            from src.core.nist_compliance import NISTCompliance
            from src.certificate.generator import CertificateGenerator
        except Exception:
            from .sanitizer import DataSanitizer
            from .detector import StorageDetector
            from .nist_compliance import NISTCompliance
            from ..certificate.generator import CertificateGenerator

        self.detector = StorageDetector()
        self.sanitizer = DataSanitizer()
        self.nist = NISTCompliance()
        self.cert_generator = CertificateGenerator()
        
        # Platform detection
        self.platform = platform.system().lower()
        self._load_platform_module()
    
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from JSON file"""
        try:
            with open(config_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Config file not found: {config_path}, using defaults")
            return self._get_default_config()
    
    def _get_default_config(self) -> Dict:
        """Return default configuration"""
        return {
            "app_name": "SecureWipe India",
            "version": "1.0.0",
            "nist_compliance": {
                "default_level": "purge",
                "supported_levels": ["clear", "purge", "destroy"],
                "verification_passes": 3
            }
        }
    
    def _setup_logger(self):
        """Setup logging"""
        logging.basicConfig(level=logging.INFO)
        return logging.getLogger(__name__)
    
    def _load_platform_module(self):
        """Load platform-specific implementation"""
        try:
            if self.platform == "windows":
                try:
                    from src.platforms.windows import WindowsPlatform
                except Exception:
                    from ..platforms.windows import WindowsPlatform
                self.platform_impl = WindowsPlatform()
            elif self.platform == "linux":
                try:
                    from src.platforms.linux import LinuxPlatform
                except Exception:
                    from ..platforms.linux import LinuxPlatform
                self.platform_impl = LinuxPlatform()
            elif self.platform == "android":
                try:
                    from src.platforms.android import AndroidPlatform
                except Exception:
                    from src.platforms.android import AndroidPlatform
                self.platform_impl = AndroidPlatform()
            else:
                print(f"Platform {self.platform} not fully supported, using basic implementation")
                self.platform_impl = None
        except ImportError as e:
            self.logger.error(f"Failed to load platform module: {e}")
            self.platform_impl = None
    
    def detect_storage_devices(self) -> List[Dict]:
        """Detect all storage devices on the system"""
        self.logger.info("Detecting storage devices...")
        devices = self.detector.scan_devices()
        
        # Add platform-specific information if available
        if self.platform_impl:
            for device in devices:
                try:
                    device.update(self.platform_impl.get_device_info(device['path']))
                except Exception as e:
                    self.logger.warning(f"Failed to get platform info for {device['path']}: {e}")
        
        self.logger.info(f"Found {len(devices)} storage devices")
        return devices
    
    def analyze_device(self, device_path: str) -> Dict:
        """Analyze a specific device for wiping capabilities"""
        self.logger.info(f"Analyzing device: {device_path}")
        
        analysis = {
            "device_path": device_path,
            "platform": self.platform,
            "size_gb": 0,
            "device_type": "unknown",
            "encryption_status": "unknown",
            "hidden_areas": [],
            "supported_methods": [],
            "estimated_time": 0
        }
        
        try:
            # Basic device info
            analysis.update(self.detector.analyze_device(device_path))
            
            # Platform-specific analysis
            if self.platform_impl:
                analysis.update(self.platform_impl.analyze_device(device_path))
            
            # NIST compliance check
            analysis["nist_methods"] = self.nist.get_supported_methods(analysis)
            
            # Hidden areas detection
            analysis["hidden_areas"] = self.detector.detect_hidden_areas(device_path)
            
        except Exception as e:
            self.logger.error(f"Device analysis failed: {e}")
            analysis["error"] = str(e)
        
        return analysis
    
    def wipe_device(self, device_path: str, wipe_level: WipeLevel, 
                   progress_callback=None) -> WipeResult:
        """Execute secure wipe on specified device"""
        
        self.logger.info(f"Starting {wipe_level.value} wipe on {device_path}")
        
        start_time = time.time()
        result = WipeResult(
            success=False,
            device_path=device_path,
            wipe_level=wipe_level,
            duration_seconds=0
        )
        
        try:
            # Pre-wipe analysis
            analysis = self.analyze_device(device_path)
            if "error" in analysis:
                result.error_message = analysis["error"]
                return result
            
            # Check if device supports requested wipe level
            if wipe_level.value not in analysis.get("nist_methods", []):
                result.error_message = f"Device does not support {wipe_level.value} level wipe"
                return result
            
            # Execute platform-specific pre-wipe setup
            if self.platform_impl:
                self.platform_impl.prepare_device(device_path)
            
            # Perform the actual wipe based on NIST level
            if wipe_level == WipeLevel.CLEAR:
                success = self._execute_clear_wipe(device_path, progress_callback)
            elif wipe_level == WipeLevel.PURGE:
                success = self._execute_purge_wipe(device_path, progress_callback)
            elif wipe_level == WipeLevel.DESTROY:
                success = self._execute_destroy_guidance(device_path)
            
            if success:
                # Verify the wipe
                verification_result = self._verify_wipe(device_path, wipe_level)
                result.verification_passes = verification_result["passes"]
                
                if verification_result["success"]:
                    # Generate certificate
                    cert_path = self._generate_certificate(device_path, wipe_level, analysis)
                    result.certificate_path = cert_path
                    result.success = True
                    self.logger.info(f"Wipe completed successfully: {device_path}")
                else:
                    result.error_message = "Wipe verification failed"
            else:
                result.error_message = "Wipe execution failed"
                
        except Exception as e:
            self.logger.error(f"Wipe failed: {e}")
            result.error_message = str(e)
        
        finally:
            result.duration_seconds = time.time() - start_time
            # Cleanup
            if self.platform_impl:
                self.platform_impl.cleanup_device(device_path)
        
        return result
    
    def _execute_clear_wipe(self, device_path: str, progress_callback) -> bool:
        """Execute NIST Clear level wipe (single pass)"""
        return self.sanitizer.single_pass_overwrite(device_path, progress_callback)
    
    def _execute_purge_wipe(self, device_path: str, progress_callback) -> bool:
        """Execute NIST Purge level wipe (multi-pass + secure erase)"""
        # Multi-pass overwrite
        if not self.sanitizer.multi_pass_overwrite(device_path, 3, progress_callback):
            return False
        
        # Clear hidden areas
        if not self.sanitizer.clear_hidden_areas(device_path):
            self.logger.warning("Failed to clear some hidden areas")
        
        # Execute hardware secure erase if available
        if self.platform_impl:
            return self.platform_impl.hardware_secure_erase(device_path)
        return True
    
    def _execute_destroy_guidance(self, device_path: str) -> bool:
        """Provide NIST Destroy level guidance (physical destruction)"""
        guidance = self.nist.get_destroy_guidance(device_path)
        self.logger.info(f"Physical destruction guidance: {guidance}")
        return True  # This just provides guidance, actual destruction is manual
    
    def _verify_wipe(self, device_path: str, wipe_level: WipeLevel) -> Dict:
        """Verify that the wipe was successful"""
        return self.sanitizer.verify_wipe(device_path, wipe_level)
    
    def _generate_certificate(self, device_path: str, wipe_level: WipeLevel, 
                            analysis: Dict) -> str:
        """Generate tamper-proof certificate"""
        cert_data = {
            "device_path": device_path,
            "device_info": analysis,
            "wipe_level": wipe_level.value,
            "timestamp": time.time(),
            "platform": self.platform,
            "nist_compliance": True,
            "verification_passed": True
        }
        
        return self.cert_generator.generate_certificate(cert_data)

class UnsupportedPlatformError(Exception):
    """Raised when platform is not supported"""
    pass