#!/usr/bin/env python3
"""
Certificate generation script for mTLS authentication.
"""

import argparse
import os
from typing import Optional, Tuple, Dict, Any
from datetime import datetime, timedelta

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519


# Ed25519 key management functions
def generate_ed25519_keypair() -> Tuple[ed25519.Ed25519PrivateKey, bytes]:
    """
    Generate Ed25519 private/public key pair

    Returns:
        Tuple of (private_key_object, public_key_bytes)
    """
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return private_key, public_key_bytes


def save_private_key(private_key: ed25519.Ed25519PrivateKey, filepath: str, password: Optional[str] = None):
    """Save private key to disk in PEM format"""
    encryption_algorithm = serialization.NoEncryption()
    if password:
        encryption_algorithm = serialization.BestAvailableEncryption(password.encode())

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption_algorithm
    )

    with open(filepath, 'wb') as f:
        f.write(private_key_pem)


def load_private_key(filepath: str, password: Optional[str] = None) -> ed25519.Ed25519PrivateKey:
    """Load private key from disk"""
    with open(filepath, 'rb') as f:
        private_key_pem = f.read()

    password_bytes = password.encode() if password else None
    return serialization.load_pem_private_key(
        private_key_pem,
        password=password_bytes,
        backend=default_backend()
    )


def private_key_to_pem(private_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Convert private key object to PEM bytes"""
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )


def get_public_key_bytes(private_key: ed25519.Ed25519PrivateKey) -> bytes:
    """Get public key bytes from private key"""
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )


# Certificate creation functions
def create_certificate(
    private_key: ed25519.Ed25519PrivateKey,
    subject_data: Dict[str, str],
    extensions: Optional[Dict[str, Any]] = None,
    days_valid: int = 9999
) -> bytes:
    """
    Create X.509 certificate from existing private key

    Args:
        private_key: Ed25519 private key object
        subject_data: Dictionary with subject information (e.g., {'O': 'org', 'OU': 'unit'})
        extensions: Optional dictionary of extensions
        days_valid: Certificate validity period in days

    Returns:
        PEM-encoded certificate
    """
    # Create certificate subject
    subject_attributes = []
    if 'O' in subject_data:
        subject_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, subject_data['O']))
    if 'OU' in subject_data:
        subject_attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, subject_data['OU']))
    if 'CN' in subject_data:
        subject_attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, subject_data['CN']))

    subject = x509.Name(subject_attributes)

    # Create the certificate
    cert_builder = x509.CertificateBuilder()
    cert_builder = cert_builder.subject_name(subject)
    cert_builder = cert_builder.issuer_name(subject)  # Self-signed
    cert_builder = cert_builder.public_key(private_key.public_key())
    cert_builder = cert_builder.serial_number(x509.random_serial_number())
    cert_builder = cert_builder.not_valid_before(datetime.utcnow())
    cert_builder = cert_builder.not_valid_after(datetime.utcnow() + timedelta(days=days_valid))

    # Add extensions if provided
    if extensions:
        for ext_name, ext_data in extensions.items():
            if ext_name == 'subject_alt_name_other':
                # Custom extension for SR25519 signature or other data
                oid, value = ext_data

                # Convert value to hex string if it's bytes
                if isinstance(value, bytes):
                    value_str = value.hex()
                else:
                    value_str = str(value)
                    # Remove 0x prefix if present
                    if value_str.startswith('0x'):
                        value_str = value_str[2:]

                # Create DER-encoded IA5String
                # IA5String tag is 0x16
                def encode_der_ia5string(data: str) -> bytes:
                    data_bytes = data.encode('ascii')  # IA5String is ASCII
                    length = len(data_bytes)
                    if length < 0x80:
                        # Short form
                        return bytes([0x16, length]) + data_bytes
                    else:
                        # Long form
                        length_bytes = []
                        temp_length = length
                        while temp_length > 0:
                            length_bytes.insert(0, temp_length & 0xFF)
                            temp_length >>= 8
                        return bytes([0x16, 0x80 | len(length_bytes)]) + bytes(length_bytes) + data_bytes

                der_value = encode_der_ia5string(value_str)

                san_extension = x509.SubjectAlternativeName([
                    x509.OtherName(
                        x509.ObjectIdentifier(oid),
                        der_value
                    )
                ])
                cert_builder = cert_builder.add_extension(san_extension, critical=False)

    # Sign the certificate - Ed25519 uses None as hash algorithm
    certificate = cert_builder.sign(private_key, None, default_backend())

    return certificate.public_bytes(serialization.Encoding.PEM)


def create_bittensor_certificate(
    private_key: ed25519.Ed25519PrivateKey,
    ss58_address: str,
    sr25519_public_key: Optional[str] = None,
    sr25519_signature: Optional[bytes] = None
) -> bytes:
    """
    Create certificate in bittensor format from existing private key

    Args:
        private_key: Ed25519 private key object for certificate
        ss58_address: SS58 address for certificate subject
        sr25519_public_key: Optional SR25519 public key hex string for subject
        sr25519_signature: Optional SR25519 signature for extension

    Returns:
        PEM-encoded certificate
    """
    # Prepare subject data
    subject_data = {'O': ss58_address}
    if sr25519_public_key:
        # Remove 0x prefix if present
        clean_pubkey = sr25519_public_key.replace('0x', '')
        subject_data['OU'] = clean_pubkey

    # Prepare extensions
    extensions = {}
    if sr25519_signature:
        extensions['subject_alt_name_other'] = ("2.5.5.1.9", sr25519_signature.hex())

    # Create certificate
    return create_certificate(
        private_key,
        subject_data,
        extensions if extensions else None
    )


# High-level convenience functions
def generate_x509_certificate(private_key: ed25519.Ed25519PrivateKey, ss58_address: str) -> Tuple[bytes, bytes]:
    """
    Create a X.509 certificate with existing Ed25519 key and SS58 address

    Args:
        private_key: Existing Ed25519 private key
        ss58_address: SS58 address

    Returns:
        Tuple of (private_key_pem, certificate_pem)
    """
    private_key_pem = private_key_to_pem(private_key)
    certificate_pem = create_bittensor_certificate(private_key, ss58_address)
    return private_key_pem, certificate_pem




# CLI interface
def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description='Certificate generation library')
    subparsers = parser.add_subparsers(dest='command', help='Commands')

    # Generate Ed25519 keypair
    gen_parser = subparsers.add_parser('generate-keypair', help='Generate Ed25519 keypair')
    gen_parser.add_argument('--output', required=True, help='Output file for private key')
    gen_parser.add_argument('--password', help='Password to encrypt private key')

    # X.509 certificate
    simple_parser = subparsers.add_parser('generate-cert', help='Generate X.509 certificate from the Ed25519 keypair')
    simple_parser.add_argument('private_key_file', help='Private key file')
    simple_parser.add_argument('ss58_address', help='SS58 address')
    simple_parser.add_argument('--password', help='Private key password')
    simple_parser.add_argument('--output-dir', help='Output directory')
    simple_parser.add_argument('--name', default='cert', help='Output filename base')


    args = parser.parse_args()

    if args.command == 'generate-keypair':
        private_key, public_key_bytes = generate_ed25519_keypair()
        save_private_key(private_key, args.output, args.password)
        print(f"Private key saved to: {args.output}")
        print(f"Public key (hex): {public_key_bytes.hex()}")

    elif args.command == 'generate-cert':
        private_key = load_private_key(args.private_key_file, args.password)
        key_pem, cert_pem = generate_x509_certificate(private_key, args.ss58_address)

        if args.output_dir:
            os.makedirs(args.output_dir, exist_ok=True)
            with open(os.path.join(args.output_dir, f'{args.name}.key'), 'wb') as f:
                f.write(key_pem)
            with open(os.path.join(args.output_dir, f'{args.name}.crt'), 'wb') as f:
                f.write(cert_pem)
            print(f"Generated {args.name}.key and {args.name}.crt in {args.output_dir}")
        else:
            print("Private Key:")
            print(key_pem.decode())
            print("\nCertificate:")
            print(cert_pem.decode())
    else:
        parser.print_help()


if __name__ == '__main__':
    main()