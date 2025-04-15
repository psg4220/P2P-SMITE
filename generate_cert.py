import os
import argparse
import time
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from microcurrency import Certificate, Permission, create_root_certificate, create_node_certificate, verify_certificate


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='Generate certificates for microcurrency nodes')
    parser.add_argument('--type', choices=['root', 'standard'], required=True,
                        help='Type of certificate to generate (root or standard)')
    parser.add_argument('--output-dir', default='blocks',
                        help='Directory where the certificate will be stored')
    parser.add_argument('--private-key',
                        help='Private key in hex format. If not provided for root, a new key pair will be generated')
    parser.add_argument('--node-public-key',
                        help='Public key of the node for which to generate certificate (for standard certificates)')
    parser.add_argument('--issuer-private-key',
                        help='Private key of the issuer (required for standard certificates)')
    parser.add_argument('--permissions', default='verify,mint',
                        help='Comma-separated list of permissions: verify,mint,root (default: verify,mint)')
    # New arguments
    parser.add_argument('--transaction-fee', type=int, default=0,
                        help='Base transaction fee amount (default: 0)')
    parser.add_argument('--fee-percentage', type=float, default=0.0,
                        help='Percentage fee as decimal (e.g., 0.001 for 0.1%) (default: 0.0)')
    parser.add_argument('--currency-name', default="Microcurrency",
                        help='Full name of the currency (default: Microcurrency)')
    parser.add_argument('--currency-ticker', default="MCC",
                        help='Ticker symbol for the currency (default: MCC)')
    parser.add_argument('--fee-recipient',
                        help='Public key of fee recipient (default: issuer/public key)')
    return parser.parse_args()


def parse_permissions(perm_string):
    """Parse permission string into permission bit flags."""
    permissions = 0
    perms = [p.strip().lower() for p in perm_string.split(',')]

    if 'root' in perms:
        return Permission.ROOT.value

    if 'verify' in perms:
        permissions |= Permission.CAN_VERIFY.value
    if 'mint' in perms:
        permissions |= Permission.CAN_MINT.value

    return permissions


def generate_or_load_key_pair(private_key_hex=None):
    """Generate a new key pair or load from hex."""
    if private_key_hex:
        try:
            private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
            public_key = private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ).hex()
            return private_key, public_key
        except Exception as e:
            print(f"Error loading private key: {e}")
            exit(1)
    else:
        private_key = ed25519.Ed25519PrivateKey.generate()
        private_key_hex = private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        ).hex()
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()
        return private_key, public_key, private_key_hex


def main():
    args = parse_args()

    # Ensure output directory exists
    if not os.path.exists(args.output_dir):
        os.makedirs(args.output_dir)

    cert_path = os.path.join(args.output_dir, "certificate.dat")

    if args.type == 'root':
        # Generate root certificate
        if args.private_key:
            private_key, public_key = generate_or_load_key_pair(args.private_key)
            print(f"Using provided private key")
        else:
            private_key, public_key, private_key_hex = generate_or_load_key_pair()
            print(f"Generated new key pair")
            print(f"Private key (save this securely): {private_key_hex}")

        print(f"Public key: {public_key}")

        # Create root certificate (self-signed with ROOT permission)
        certificate = create_root_certificate(
            public_key,
            private_key,
            transaction_fee=args.transaction_fee,
            fee_percentage=args.fee_percentage,
            currency_name=args.currency_name,
            currency_ticker=args.currency_ticker,
            fee_recipient=args.fee_recipient
        )

        # Save the certificate
        with open(cert_path, 'wb') as f:
            f.write(certificate.serialize())

        print(f"Root certificate created and saved to {cert_path}")
        print("Configuration for .env file:")
        if not args.private_key:
            print(f"PRIVATE_KEY={private_key_hex}")

    elif args.type == 'standard':
        # Generate standard certificate
        if not args.issuer_private_key:
            print("Error: --issuer-private-key is required for standard certificates")
            exit(1)

        if not args.node_public_key:
            print("Error: --node-public-key is required for standard certificates")
            exit(1)

        # Load issuer's private key
        try:
            issuer_private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(args.issuer_private_key))
            issuer_public_key = issuer_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.Raw,
                format=serialization.PublicFormat.Raw
            ).hex()
        except Exception as e:
            print(f"Error loading issuer private key: {e}")
            exit(1)

        # Parse permissions
        permissions = parse_permissions(args.permissions)

        # Create certificate for the node
        certificate = create_node_certificate(
            args.node_public_key,
            permissions,
            issuer_public_key,
            issuer_private_key,
            transaction_fee=args.transaction_fee,
            fee_percentage=args.fee_percentage,
            currency_name=args.currency_name,
            currency_ticker=args.currency_ticker,
            fee_recipient=args.fee_recipient
        )

        # Save the certificate
        with open(cert_path, 'wb') as f:
            f.write(certificate.serialize())

        # Print permissions in a readable format
        perms_list = []
        if permissions & Permission.ROOT.value:
            perms_list.append("ROOT")
        if permissions & Permission.CAN_VERIFY.value:
            perms_list.append("CAN_VERIFY")
        if permissions & Permission.CAN_MINT.value:
            perms_list.append("CAN_MINT")

        print(f"Standard certificate created and saved to {cert_path}")
        print(f"Certificate issued by: {issuer_public_key}")
        print(f"Certificate issued to: {args.node_public_key}")
        print(f"Permissions: {', '.join(perms_list)}")
        print(f"Currency: {certificate.currency_name} ({certificate.currency_ticker})")
        print(f"Base transaction fee: {certificate.transaction_fee}")
        print(f"Fee percentage: {certificate.fee_percentage*100}%")
        print(f"Fee recipient: {certificate.fee_recipient}")

if __name__ == "__main__":
    main()