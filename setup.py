'''
SecureWipe India - Setup Script
Installation and packaging configuration
'''

from setuptools import setup, find_packages

setup(
    name="securewipe-india",
    version="1.0.0",
    author="Government of India",
    author_email="support@securewipe.india.gov.in", 
    description="NIST 800-88 Compliant Data Sanitization for India's E-Waste Crisis",
    long_description="SecureWipe India addresses India's e-waste crisis through secure data sanitization",
    url="https://securewipe.india.gov.in",
    package_dir={"": "src"},
    packages=find_packages(where="src"),
    python_requires=">=3.7",
    install_requires=[
        "cryptography>=3.4.8",
        "psutil>=5.8.0", 
        "qrcode[pil]>=7.3.1",
        "reportlab>=3.6.0",
        "requests>=2.28.0",
    ],
    extras_require={
        "gui": ["PyQt5>=5.15.4"],
        "dev": ["pytest>=7.0.0", "black>=22.0.0"],
    },
    entry_points={
        "console_scripts": [
            "securewipe=ui.cli:main",
            "securewipe-gui=ui.main_gui:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
    ],
)