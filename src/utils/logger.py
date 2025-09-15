"""
SecureWipe India - Logging Utilities
Centralized logging configuration for the application
"""

import logging
import os
import sys
from datetime import datetime
from pathlib import Path

def setup_logger(name: str, level: int = logging.INFO, log_file: str = None) -> logging.Logger:
    """Setup a logger with consistent formatting"""
    
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # Prevent duplicate handlers
    if logger.handlers:
        return logger
    
    # Create formatter
    formatter = logging.Formatter(
        fmt='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # File handler (optional)
    if log_file:
        # Create logs directory if it doesn't exist
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)  # File gets all messages
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    else:
        # Default log file based on current date
        log_dir = Path("logs")
        log_dir.mkdir(exist_ok=True)
        
        log_filename = f"securewipe_{datetime.now().strftime('%Y%m%d')}.log"
        log_file_path = log_dir / log_filename
        
        file_handler = logging.FileHandler(log_file_path)
        file_handler.setLevel(logging.DEBUG)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger

def get_audit_logger() -> logging.Logger:
    """Get a special logger for audit trail"""
    
    audit_logger = logging.getLogger("audit")
    audit_logger.setLevel(logging.INFO)
    
    if audit_logger.handlers:
        return audit_logger
    
    # Create audit-specific formatter
    audit_formatter = logging.Formatter(
        fmt='%(asctime)s - AUDIT - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Audit log file
    audit_dir = Path("logs/audit")
    audit_dir.mkdir(parents=True, exist_ok=True)
    
    audit_filename = f"audit_{datetime.now().strftime('%Y%m%d')}.log"
    audit_file_path = audit_dir / audit_filename
    
    audit_handler = logging.FileHandler(audit_file_path)
    audit_handler.setLevel(logging.INFO)
    audit_handler.setFormatter(audit_formatter)
    audit_logger.addHandler(audit_handler)
    
    return audit_logger

class AuditLogger:
    """Specialized audit logger for compliance tracking"""
    
    def __init__(self):
        self.logger = get_audit_logger()
    
    def log_wipe_start(self, device_path: str, wipe_level: str, user: str = "system"):
        """Log the start of a wipe operation"""
        self.logger.info(f"WIPE_START - Device: {device_path}, Level: {wipe_level}, User: {user}")
    
    def log_wipe_complete(self, device_path: str, success: bool, duration: float, cert_id: str = None):
        """Log the completion of a wipe operation"""
        status = "SUCCESS" if success else "FAILED"
        cert_info = f", Certificate: {cert_id}" if cert_id else ""
        self.logger.info(f"WIPE_COMPLETE - Device: {device_path}, Status: {status}, Duration: {duration:.1f}s{cert_info}")
    
    def log_certificate_generated(self, cert_id: str, device_path: str):
        """Log certificate generation"""
        self.logger.info(f"CERT_GENERATED - ID: {cert_id}, Device: {device_path}")
    
    def log_certificate_verified(self, cert_id: str, valid: bool):
        """Log certificate verification"""
        status = "VALID" if valid else "INVALID"
        self.logger.info(f"CERT_VERIFIED - ID: {cert_id}, Status: {status}")
    
    def log_device_access(self, device_path: str, operation: str):
        """Log device access operations"""
        self.logger.info(f"DEVICE_ACCESS - Device: {device_path}, Operation: {operation}")
    
    def log_security_event(self, event_type: str, details: str):
        """Log security-related events"""
        self.logger.warning(f"SECURITY_EVENT - Type: {event_type}, Details: {details}")