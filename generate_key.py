import argparse
import json
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

import microcurrency
from microcurrency import Transaction, TransactionType

def derive_public_key(private_key_hex: str) -> str:
    """Derive public key from private key."""
    try:
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        ).hex()
        return public_key
    except ValueError as e:
        raise ValueError(f"Invalid private key: {e}")

def generate_signature(private_key_hex: str, sender: str, recipient: str, amount: int, tx_type: TransactionType) -> str:
    """Generate signature for a transaction."""
    try:
        private_key = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(private_key_hex))
        tx_data = f"{sender}{recipient}{amount}{tx_type.value}"
        signature = private_key.sign(tx_data.encode()).hex()
        return signature
    except ValueError as e:
        raise ValueError(f"Failed to generate signature: {e}")

def create_transaction(private_key_hex: str, sender: str, recipient: str, amount: int, tx_type: str) -> Transaction:
    """Create a Transaction with a valid signature."""
    # Validate transaction type
    try:
        tx_type_enum = TransactionType[tx_type.upper()]
    except KeyError:
        raise ValueError(f"Invalid transaction type: {tx_type}. Must be MINT, OUTPUT, or BURN")

    # Validate amount
    if amount <= 0:
        raise ValueError("Amount must be positive")

    # Validate keys
    if not sender or not recipient:
        raise ValueError("Sender and recipient public keys must be non-empty")

    # For MINT, sender must match private key's public key
    expected_public_key = derive_public_key(private_key_hex)
    if tx_type_enum == TransactionType.MINT and sender != expected_public_key:
        raise ValueError(f"MINT transaction sender {sender} must match private key's public key {expected_public_key}")

    # Generate signature
    signature = generate_signature(private_key_hex, sender, recipient, amount, tx_type_enum)

    # Create Transaction
    tx = Transaction(
        sender=sender,
        recipient=recipient,
        amount=amount,
        tx_type=tx_type_enum,
        signature=signature
    )

    return tx

def main():

    print(microcurrency.generate_key_pair())

    parser = argparse.ArgumentParser(description="Generate a signed transaction for microcurrency.")
    parser.add_argument("--private-key", help="Private key (hex) for signing")
    parser.add_argument("--sender", help="Sender public key (hex)")
    parser.add_argument("--recipient", help="Recipient public key (hex)")
    parser.add_argument("--amount", type=int, help="Transaction amount")
    parser.add_argument("--tx-type", help="Transaction type (MINT, OUTPUT, BURN)")

    args = parser.parse_args()

    # Interactive mode if no arguments
    if not any(vars(args).values()):
        private_key_hex = input("Enter private key (hex): ").strip()
        sender = input("Enter sender public key (hex): ").strip()
        recipient = input("Enter recipient public key (hex): ").strip()
        amount = int(input("Enter amount: ").strip())
        tx_type = input("Enter transaction type (MINT, OUTPUT, BURN): ").strip()
    else:
        private_key_hex = args.private_key
        sender = args.sender
        recipient = args.recipient
        amount = args.amount
        tx_type = args.tx_type

    try:
        # Create transaction
        tx = create_transaction(private_key_hex, sender, recipient, amount, tx_type)

        # Output transaction details as JSON
        tx_data = {
            "sender": tx.sender,
            "recipient": tx.recipient,
            "amount": tx.amount,
            "tx_type": tx.tx_type.name,
            "signature": tx.signature
        }
        print(f"curl -XPOST -H \"Content-type: application/json\" -d '"+json.dumps(tx_data, indent=2)+"' 'localhost:5000/transaction'")


    except ValueError as e:
        print(f"Error: {e}")
    except Exception as e:
        print(f"Unexpected error: {e}")

if __name__ == "__main__":
    main()