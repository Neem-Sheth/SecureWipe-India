# SecureWipe India

A comprehensive cross-platform data wiping solution designed to address India's e-waste crisis through secure, verifiable data sanitization.

## Features

- **Cross-Platform Support**: Windows, Linux, and Android
- **NIST 800-88 Compliance**: Clear, Purge, and Destroy levels
- **Tamper-Proof Certificates**: PDF and JSON with digital signatures
- **Hidden Area Clearing**: HPA/DCO detection and erasure
- **One-Click Operation**: User-friendly interface
- **Multi-Language Support**: Hindi, English, and 10 regional languages
- **Bootable Environment**: USB/ISO for offline operation
- **Third-Party Verification**: QR codes and blockchain anchoring

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run GUI application
python -m src.ui.main_gui

# Run CLI version
python -m src.ui.cli --device /dev/sdb --level purge
```

## Documentation

- [User Manual](docs/user_manual.md)
- [Technical Specifications](docs/technical_specs.md)
- [API Reference](docs/api_reference.md)

## License

MIT License - See LICENSE file for details
