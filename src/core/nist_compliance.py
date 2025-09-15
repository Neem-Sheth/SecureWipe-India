"""
SecureWipe India - NIST Compliance
Implements NIST SP 800-88 Rev 1 compliance checks and methods
"""

import logging
from typing import Dict, List

class NISTCompliance:
    """Handles NIST SP 800-88 Rev 1 compliance verification and guidance"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        
        # NIST methods by device type
        self.nist_methods = {
            "hdd": {
                "clear": ["overwrite", "block_erase"],
                "purge": ["overwrite", "block_erase", "crypto_erase"],
                "destroy": ["disintegrate", "pulverize", "melt", "incinerate"]
            },
            "ssd": {
                "clear": ["overwrite", "block_erase"],
                "purge": ["crypto_erase", "secure_erase", "overwrite"],
                "destroy": ["disintegrate", "pulverize", "melt", "incinerate"]
            },
            "flash": {
                "clear": ["overwrite", "block_erase"],
                "purge": ["crypto_erase", "secure_erase"],
                "destroy": ["disintegrate", "pulverize", "melt", "incinerate"]
            },
            "optical": {
                "clear": ["not_possible"],
                "purge": ["not_possible"],
                "destroy": ["shred", "pulverize", "incinerate"]
            }
        }
        
        # Security categorizations
        self.security_categories = {
            "low": "clear",
            "moderate": "purge", 
            "high": "destroy"
        }
    
    def get_supported_methods(self, device_info: Dict) -> List[str]:
        """Get supported NIST methods for a device"""
        device_type = self._classify_device(device_info)
        
        supported = []
        
        # Add methods based on device capabilities
        if device_type in self.nist_methods:
            methods = self.nist_methods[device_type]
            
            # Clear level - always supported
            if methods.get("clear") and methods["clear"] != ["not_possible"]:
                supported.append("clear")
            
            # Purge level - check if device supports advanced methods
            if methods.get("purge") and methods["purge"] != ["not_possible"]:
                if self._supports_secure_erase(device_info) or self._supports_crypto_erase(device_info):
                    supported.append("purge")
            
            # Destroy level - always available as physical destruction
            supported.append("destroy")
        
        return supported
    
    def get_recommended_level(self, data_sensitivity: str, device_info: Dict) -> str:
        """Get recommended NIST level based on data sensitivity"""
        
        # Map sensitivity to security category
        sensitivity_mapping = {
            "public": "low",
            "internal": "low", 
            "confidential": "moderate",
            "restricted": "moderate",
            "secret": "high",
            "top_secret": "high"
        }
        
        security_cat = sensitivity_mapping.get(data_sensitivity.lower(), "moderate")
        recommended_level = self.security_categories[security_cat]
        
        # Check if device supports recommended level
        supported_methods = self.get_supported_methods(device_info)
        
        if recommended_level not in supported_methods:
            # Fall back to highest supported level
            if "purge" in supported_methods:
                return "purge"
            elif "clear" in supported_methods:
                return "clear"
            else:
                return "destroy"
        
        return recommended_level
    
    def validate_wipe_method(self, method: str, device_info: Dict) -> Dict:
        """Validate if a wipe method is NIST compliant for the device"""
        
        result = {
            "compliant": False,
            "level": None,
            "method": method,
            "issues": [],
            "recommendations": []
        }
        
        device_type = self._classify_device(device_info)
        
        if device_type not in self.nist_methods:
            result["issues"].append(f"Unknown device type: {device_type}")
            return result
        
        # Check each NIST level
        for level, methods in self.nist_methods[device_type].items():
            if method in methods and methods != ["not_possible"]:
                result["compliant"] = True
                result["level"] = level
                break
        
        if not result["compliant"]:
            result["issues"].append(f"Method '{method}' not NIST compliant for {device_type}")
            result["recommendations"] = self.get_supported_methods(device_info)
        
        return result
    
    def get_destroy_guidance(self, device_path: str) -> Dict:
        """Get NIST Destroy level guidance for physical destruction"""
        
        guidance = {
            "methods": [
                {
                    "name": "Disintegration",
                    "description": "Completely break down device into component materials",
                    "particle_size": "< 2mm for HDDs, < 1mm for SSDs",
                    "effectiveness": "100%"
                },
                {
                    "name": "Pulverization", 
                    "description": "Crush device to fine particles",
                    "particle_size": "< 5mm",
                    "effectiveness": "99.9%"
                },
                {
                    "name": "Melting",
                    "description": "Heat device above melting point of storage media",
                    "temperature": "> 1500°C for platters",
                    "effectiveness": "100%"
                },
                {
                    "name": "Incineration",
                    "description": "Burn device at high temperature",
                    "temperature": "> 1000°C sustained",
                    "effectiveness": "99.9%"
                }
            ],
            "verification": [
                "Visual inspection of particle size",
                "Weight measurement (should be reduced)",
                "No readable components should remain",
                "Document destruction process"
            ],
            "disposal": [
                "Follow local e-waste regulations",
                "Use certified destruction facility",
                "Obtain certificate of destruction",
                "Maintain chain of custody"
            ]
        }
        
        return guidance
    
    def generate_compliance_report(self, wipe_operation: Dict) -> Dict:
        """Generate NIST compliance report for a wipe operation"""
        
        report = {
            "nist_version": "SP 800-88 Rev 1",
            "compliance_status": "COMPLIANT",
            "wipe_level": wipe_operation.get("level", "unknown"),
            "device_classification": self._classify_device(wipe_operation.get("device_info", {})),
            "methods_used": wipe_operation.get("methods", []),
            "verification_status": wipe_operation.get("verification", {}).get("success", False),
            "issues": [],
            "recommendations": [],
            "certification": {
                "date": wipe_operation.get("timestamp"),
                "operator": wipe_operation.get("operator", "SecureWipe India"),
                "standards_met": ["NIST SP 800-88 Rev 1"],
                "confidence_level": "High"
            }
        }
        
        # Validate compliance
        if not report["verification_status"]:
            report["compliance_status"] = "NON_COMPLIANT"
            report["issues"].append("Wipe verification failed")
        
        device_methods = self.get_supported_methods(wipe_operation.get("device_info", {}))
        if report["wipe_level"] not in device_methods:
            report["compliance_status"] = "NON_COMPLIANT"
            report["issues"].append(f"Wipe level not supported for device type")
        
        return report
    
    def _classify_device(self, device_info: Dict) -> str:
        """Classify device type for NIST compliance"""
        
        device_type = device_info.get("device_type", "unknown").lower()
        size_gb = device_info.get("size_gb", 0)
        
        # Classification logic
        if "ssd" in device_type or "solid" in device_type:
            return "ssd"
        elif "hdd" in device_type or "hard" in device_type:
            return "hdd"
        elif "usb" in device_type or "flash" in device_type:
            return "flash"
        elif "cd" in device_type or "dvd" in device_type or "optical" in device_type:
            return "optical"
        elif size_gb > 0:
            # Guess based on size
            if size_gb < 128:
                return "flash"
            elif size_gb < 2048:  # < 2TB likely SSD
                return "ssd"
            else:
                return "hdd"
        
        return "unknown"
    
    def _supports_secure_erase(self, device_info: Dict) -> bool:
        """Check if device supports ATA/NVMe secure erase"""
        device_type = self._classify_device(device_info)
        return device_type in ["ssd", "hdd"]
    
    def _supports_crypto_erase(self, device_info: Dict) -> bool:
        """Check if device supports cryptographic erase"""
        device_type = self._classify_device(device_info)
        encryption_status = device_info.get("encryption_status", "unknown")
        
        # Crypto erase available if device has hardware encryption
        return (device_type in ["ssd", "flash"] and 
                encryption_status in ["encrypted", "self_encrypting"])