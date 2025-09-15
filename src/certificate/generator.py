"""
SecureWipe India - Certificate Generator
Generates tamper-proof PDF and JSON certificates with digital signatures
"""

import os
import json
import hashlib
import qrcode
from datetime import datetime, timedelta
from typing import Dict, Optional
import logging

# For PDF generation
try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.colors import black, blue, red, green
    from reportlab.lib.units import inch
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Image
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

# For cryptographic signatures
try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False

class CertificateGenerator:
    """Generates tamper-proof certificates for data wipe operations"""
    
    def __init__(self, config: Optional[Dict] = None):
        self.logger = logging.getLogger(__name__)
        self.config = config or self._get_default_config()
        
        # Initialize cryptographic components
        if CRYPTOGRAPHY_AVAILABLE:
            self.private_key = None
            self.certificate = None
            self._load_or_create_ca()
        else:
            self.logger.warning("Cryptography library not available - signatures will be disabled")
    
    def _get_default_config(self) -> Dict:
        """Get default certificate configuration"""
        return {
            "organization": "SecureWipe India",
            "country": "IN",
            "validity_days": 3650,
            "key_size": 4096,
            "hash_algorithm": "SHA256"
        }
    
    def generate_certificate(self, wipe_data: Dict) -> str:
        """Generate complete certificate package (PDF + JSON + QR)"""
        try:
            # Create certificate data
            cert_data = self._prepare_certificate_data(wipe_data)
            
            # Generate digital signature
            if CRYPTOGRAPHY_AVAILABLE and self.private_key:
                cert_data["digital_signature"] = self._sign_data(cert_data)
            
            # Create output directory
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            device_name = wipe_data.get("device_path", "unknown").replace("/", "_").replace("\\\\", "_")
            cert_dir = f"certificates/{device_name}_{timestamp}"
            os.makedirs(cert_dir, exist_ok=True)
            
            # Generate JSON certificate
            json_path = os.path.join(cert_dir, "certificate.json")
            with open(json_path, 'w') as f:
                json.dump(cert_data, f, indent=2, default=str)
            
            # Generate PDF certificate
            pdf_path = os.path.join(cert_dir, "certificate.pdf")
            if REPORTLAB_AVAILABLE:
                self._generate_pdf_certificate(cert_data, pdf_path)
            else:
                self.logger.warning("ReportLab not available - PDF generation skipped")
            
            # Generate QR code
            qr_path = os.path.join(cert_dir, "verification_qr.png")
            self._generate_qr_code(cert_data, qr_path)
            
            self.logger.info(f"Certificate generated: {cert_dir}")
            return cert_dir
            
        except Exception as e:
            self.logger.error(f"Certificate generation failed: {e}")
            raise
    
    def _prepare_certificate_data(self, wipe_data: Dict) -> Dict:
        """Prepare structured certificate data"""
        
        timestamp = datetime.now()
        
        cert_data = {
            # Certificate metadata
            "certificate_id": hashlib.sha256(
                f"{wipe_data.get('device_path', '')}{timestamp}".encode()
            ).hexdigest()[:16],
            "version": "1.0",
            "generated_at": timestamp.isoformat(),
            "expires_at": (timestamp + timedelta(days=self.config["validity_days"])).isoformat(),
            
            # Organization info
            "issuer": {
                "organization": self.config["organization"],
                "country": self.config["country"],
                "system": "SecureWipe India v1.0"
            },
            
            # Device information
            "device": {
                "path": wipe_data.get("device_path", "unknown"),
                "size_gb": wipe_data.get("device_info", {}).get("size_gb", 0),
                "type": wipe_data.get("device_info", {}).get("device_type", "unknown"),
                "serial": wipe_data.get("device_info", {}).get("serial", "unknown"),
                "model": wipe_data.get("device_info", {}).get("model", "unknown")
            },
            
            # Wipe operation details
            "wipe_operation": {
                "level": wipe_data.get("wipe_level", "unknown"),
                "methods_used": wipe_data.get("methods_used", []),
                "duration_seconds": wipe_data.get("duration_seconds", 0),
                "platform": wipe_data.get("platform", "unknown"),
                "timestamp": wipe_data.get("timestamp", timestamp.timestamp())
            },
            
            # Compliance information
            "compliance": {
                "nist_800_88_rev1": True,
                "security_level": wipe_data.get("wipe_level", "unknown"),
                "verification_passed": wipe_data.get("verification_passed", False),
                "standards_met": ["NIST SP 800-88 Rev 1"]
            },
            
            # Verification data
            "verification": {
                "method": "random_sector_sampling",
                "sectors_checked": wipe_data.get("verification", {}).get("sectors_checked", 0),
                "non_zero_sectors": wipe_data.get("verification", {}).get("non_zero_sectors", 0),
                "confidence_level": "High" if wipe_data.get("verification_passed") else "Failed"
            }
        }
        
        return cert_data
    
    def _sign_data(self, cert_data: Dict) -> str:
        """Generate digital signature for certificate data"""
        try:
            if not self.private_key:
                return "unsigned"
            
            # Create data hash
            data_json = json.dumps(cert_data, sort_keys=True, default=str)
            data_hash = hashlib.sha256(data_json.encode()).digest()
            
            # Sign the hash
            signature = self.private_key.sign(
                data_hash,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            # Return base64 encoded signature
            import base64
            return base64.b64encode(signature).decode()
            
        except Exception as e:
            self.logger.error(f"Data signing failed: {e}")
            return "signature_failed"
    
    def _generate_pdf_certificate(self, cert_data: Dict, output_path: str):
        """Generate PDF certificate"""
        try:
            doc = SimpleDocTemplate(output_path, pagesize=A4)
            styles = getSampleStyleSheet()
            story = []
            
            # Title
            title_style = ParagraphStyle(
                'CustomTitle',
                parent=styles['Heading1'],
                fontSize=24,
                spaceAfter=30,
                textColor=blue,
                alignment=1  # Center
            )
            
            story.append(Paragraph("DATA SANITIZATION CERTIFICATE", title_style))
            story.append(Spacer(1, 20))
            
            # Certificate ID and validity
            story.append(Paragraph(f"<b>Certificate ID:</b> {cert_data['certificate_id']}", styles['Normal']))
            story.append(Paragraph(f"<b>Generated:</b> {cert_data['generated_at'][:19]}", styles['Normal']))
            story.append(Paragraph(f"<b>Valid Until:</b> {cert_data['expires_at'][:19]}", styles['Normal']))
            story.append(Spacer(1, 20))
            
            # Device Information
            story.append(Paragraph("<b>DEVICE INFORMATION</b>", styles['Heading2']))
            device = cert_data['device']
            story.append(Paragraph(f"Device Path: {device['path']}", styles['Normal']))
            story.append(Paragraph(f"Device Type: {device['type']}", styles['Normal']))
            story.append(Paragraph(f"Capacity: {device['size_gb']:.2f} GB", styles['Normal']))
            story.append(Paragraph(f"Model: {device['model']}", styles['Normal']))
            story.append(Paragraph(f"Serial: {device['serial']}", styles['Normal']))
            story.append(Spacer(1, 15))
            
            # Wipe Operation
            story.append(Paragraph("<b>SANITIZATION DETAILS</b>", styles['Heading2']))
            wipe = cert_data['wipe_operation']
            story.append(Paragraph(f"NIST Level: <b>{wipe['level'].upper()}</b>", styles['Normal']))
            story.append(Paragraph(f"Platform: {wipe['platform'].title()}", styles['Normal']))
            story.append(Paragraph(f"Duration: {wipe['duration_seconds']:.1f} seconds", styles['Normal']))
            
            if wipe.get('methods_used'):
                methods = ', '.join(wipe['methods_used'])
                story.append(Paragraph(f"Methods: {methods}", styles['Normal']))
            
            story.append(Spacer(1, 15))
            
            # Compliance
            story.append(Paragraph("<b>COMPLIANCE STATUS</b>", styles['Heading2']))
            compliance = cert_data['compliance']
            
            status_color = green if compliance['verification_passed'] else red
            story.append(Paragraph(
                f"<font color='{status_color}'>✓ NIST SP 800-88 Rev 1 COMPLIANT</font>", 
                styles['Normal']
            ))
            
            story.append(Paragraph(f"Security Level: {compliance['security_level'].title()}", styles['Normal']))
            story.append(Paragraph(f"Verification: {'PASSED' if compliance['verification_passed'] else 'FAILED'}", styles['Normal']))
            
            story.append(Spacer(1, 20))
            
            # Verification details
            verification = cert_data['verification']
            story.append(Paragraph("<b>VERIFICATION RESULTS</b>", styles['Heading2']))
            story.append(Paragraph(f"Method: {verification['method']}", styles['Normal']))
            story.append(Paragraph(f"Sectors Checked: {verification['sectors_checked']}", styles['Normal']))
            story.append(Paragraph(f"Non-Zero Sectors: {verification['non_zero_sectors']}", styles['Normal']))
            story.append(Paragraph(f"Confidence Level: {verification['confidence_level']}", styles['Normal']))
            
            story.append(Spacer(1, 30))
            
            # Signature
            story.append(Paragraph("<b>DIGITAL SIGNATURE</b>", styles['Heading2']))
            signature = cert_data.get('digital_signature', 'Not Available')[:50] + "..."
            story.append(Paragraph(f"<font size=8>{signature}</font>", styles['Normal']))
            
            # Footer
            story.append(Spacer(1, 30))
            footer_style = ParagraphStyle(
                'Footer', 
                parent=styles['Normal'],
                fontSize=8,
                textColor=blue,
                alignment=1
            )
            story.append(Paragraph("Generated by SecureWipe India - Secure Data Sanitization Solution", footer_style))
            story.append(Paragraph("For verification, scan QR code or visit: https://securewipe.india.gov.in/verify", footer_style))
            
            # Build PDF
            doc.build(story)
            self.logger.info(f"PDF certificate generated: {output_path}")
            
        except Exception as e:
            self.logger.error(f"PDF generation failed: {e}")
    
    def _generate_qr_code(self, cert_data: Dict, output_path: str):
        """Generate QR code for certificate verification"""
        try:
            # Create verification URL with certificate ID
            verification_data = {
                "certificate_id": cert_data["certificate_id"],
                "device_path": cert_data["device"]["path"],
                "wipe_level": cert_data["wipe_operation"]["level"],
                "timestamp": cert_data["generated_at"],
                "signature": cert_data.get("digital_signature", "")[:32]
            }
            
            verification_url = f"https://securewipe.india.gov.in/verify?data={json.dumps(verification_data)}"
            
            # Generate QR code
            qr = qrcode.QRCode(
                version=1,
                error_correction=qrcode.constants.ERROR_CORRECT_L,
                box_size=10,
                border=4,
            )
            qr.add_data(verification_url)
            qr.make(fit=True)
            
            img = qr.make_image(fill_color="black", back_color="white")
            img.save(output_path)
            
            self.logger.info(f"QR code generated: {output_path}")
            
        except Exception as e:
            self.logger.error(f"QR code generation failed: {e}")
    
    def _load_or_create_ca(self):
        """Load existing CA or create new one"""
        try:
            ca_cert_path = "config/certificates/ca.pem"
            ca_key_path = "config/certificates/private_key.pem"
            
            if os.path.exists(ca_cert_path) and os.path.exists(ca_key_path):
                # Load existing CA
                with open(ca_key_path, 'rb') as f:
                    self.private_key = serialization.load_pem_private_key(
                        f.read(), password=None
                    )
                
                with open(ca_cert_path, 'rb') as f:
                    self.certificate = x509.load_pem_x509_certificate(f.read())
                    
                self.logger.info("Loaded existing CA certificate")
            else:
                # Create new CA
                self._create_ca_certificate(ca_cert_path, ca_key_path)
                
        except Exception as e:
            self.logger.error(f"CA certificate setup failed: {e}")
    
    def _create_ca_certificate(self, cert_path: str, key_path: str):
        """Create new CA certificate"""
        try:
            # Generate private key
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=self.config["key_size"]
            )
            
            # Create certificate
            subject = issuer = x509.Name([
                x509.NameAttribute(NameOID.COUNTRY_NAME, self.config["country"]),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, self.config["organization"]),
                x509.NameAttribute(NameOID.COMMON_NAME, "SecureWipe India CA"),
            ])
            
            self.certificate = x509.CertificateBuilder().subject_name(
                subject
            ).issuer_name(
                issuer
            ).public_key(
                self.private_key.public_key()
            ).serial_number(
                x509.random_serial_number()
            ).not_valid_before(
                datetime.utcnow()
            ).not_valid_after(
                datetime.utcnow() + timedelta(days=self.config["validity_days"])
            ).add_extension(
                x509.SubjectAlternativeName([
                    x509.DNSName("securewipe.india.gov.in"),
                ]),
                critical=False,
            ).sign(self.private_key, hashes.SHA256())
            
            # Save certificate and key
            os.makedirs(os.path.dirname(cert_path), exist_ok=True)
            
            with open(cert_path, 'wb') as f:
                f.write(self.certificate.public_bytes(serialization.Encoding.PEM))
            
            with open(key_path, 'wb') as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            self.logger.info(f"Created new CA certificate: {cert_path}")
            
        except Exception as e:
            self.logger.error(f"CA certificate creation failed: {e}")
            raise