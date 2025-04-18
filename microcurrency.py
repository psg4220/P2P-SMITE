import hashlib
import json
import time
import os
from enum import Enum
from typing import List, Tuple
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from google.protobuf.timestamp_pb2 import Timestamp
import microcurrency_pb2  # Generated from proto file

# Transaction types
class TransactionType(Enum):
    MINT = 0
    BURN = 1
    OUTPUT = 2

# Permissions as bit flags
class Permission(Enum):
    CAN_VERIFY = 0b001  # Can create/verify blocks
    CAN_MINT = 0b010    # Can mint coins
    BOTH = 0b011        # Can both verify blocks and mint coins

    @classmethod
    def has_permission(cls, perms: int, check: 'Permission') -> bool:
        if perms & Permission.BOTH.value == Permission.BOTH.value:
            return True
        return (perms & check.value) == check.value

# Transaction object
class Transaction:
    def __init__(self, sender: str, recipient: str, amount: float,
                 tx_type: TransactionType, signature: str, tx_id: str = None, timestamp: int = None):
        self.sender = sender
        self.recipient = recipient
        self.amount = round(float(amount), 2)  # Ensure two decimal places
        self.tx_type = tx_type
        self.signature = signature
        self.timestamp = timestamp if timestamp else int(time.time())
        self.tx_id = tx_id if tx_id else self.calculate_tx_id()

    def calculate_tx_id(self) -> str:
        tx_data = f"{self.sender}{self.recipient}{self.amount:.2f}{self.tx_type.value}{self.signature}{self.timestamp}"
        return hashlib.sha256(tx_data.encode()).hexdigest()

    def to_proto(self) -> microcurrency_pb2.Transaction:
        proto_tx = microcurrency_pb2.Transaction()
        proto_tx.sender = self.sender
        proto_tx.recipient = self.recipient
        proto_tx.amount = self.amount
        proto_tx.tx_type = self.tx_type.value
        proto_tx.signature = self.signature
        proto_tx.tx_id = self.tx_id
        proto_tx.timestamp = self.timestamp
        return proto_tx

    @staticmethod
    def from_proto(proto_tx: microcurrency_pb2.Transaction) -> "Transaction":
        return Transaction(
            sender=proto_tx.sender,
            recipient=proto_tx.recipient,
            amount=proto_tx.amount,
            tx_type=TransactionType(proto_tx.tx_type),
            signature=proto_tx.signature,
            tx_id=proto_tx.tx_id,
            timestamp=proto_tx.timestamp
        )

    def serialize(self) -> bytes:
        return self.to_proto().SerializeToString()

    @staticmethod
    def deserialize(data: bytes) -> "Transaction":
        proto_tx = microcurrency_pb2.Transaction()
        proto_tx.ParseFromString(data)
        return Transaction.from_proto(proto_tx)

    def __str__(self) -> str:
        data = {
            "sender": self.sender,
            "recipient": self.recipient,
            "amount": f"{self.amount:.2f}",
            "tx_type": self.tx_type.name,
            "signature": self.signature,
            "tx_id": self.tx_id,
            "timestamp": self.timestamp
        }
        return json.dumps(data, indent=2)

# Certificate object
class Certificate:
    def __init__(self, issued_to: str, permissions: int, issued_by: str,
                 valid_from: int, valid_until: int, signature: str,
                 fee_percentage: float = 0.0, currency_name: str = "Microcurrency",
                 currency_ticker: str = "MCC", fee_recipient: str = ""):
        self.issued_to = issued_to
        self.permissions = permissions
        self.issued_by = issued_by
        self.valid_from = valid_from
        self.valid_until = valid_until
        self.signature = signature
        self.fee_percentage = fee_percentage
        self.currency_name = currency_name
        self.currency_ticker = currency_ticker
        self.fee_recipient = fee_recipient

    def to_proto(self) -> microcurrency_pb2.Certificate:
        proto_cert = microcurrency_pb2.Certificate()
        proto_cert.issued_to = self.issued_to
        proto_cert.permissions = self.permissions
        proto_cert.issued_by = self.issued_by
        proto_cert.valid_from = self.valid_from
        proto_cert.valid_until = self.valid_until
        proto_cert.signature = self.signature
        proto_cert.fee_percentage = self.fee_percentage
        proto_cert.currency_name = self.currency_name
        proto_cert.currency_ticker = self.currency_ticker
        proto_cert.fee_recipient = self.fee_recipient
        return proto_cert

    @staticmethod
    def from_proto(proto_cert: microcurrency_pb2.Certificate) -> "Certificate":
        return Certificate(
            issued_to=proto_cert.issued_to,
            permissions=proto_cert.permissions,
            issued_by=proto_cert.issued_by,
            valid_from=proto_cert.valid_from,
            valid_until=proto_cert.valid_until,
            signature=proto_cert.signature,
            fee_percentage=proto_cert.fee_percentage,
            currency_name=proto_cert.currency_name,
            currency_ticker=proto_cert.currency_ticker,
            fee_recipient=proto_cert.fee_recipient
        )

    def serialize(self) -> bytes:
        return self.to_proto().SerializeToString()

    @staticmethod
    def deserialize(data: bytes) -> "Certificate":
        proto_cert = microcurrency_pb2.Certificate()
        proto_cert.ParseFromString(data)
        return Certificate.from_proto(proto_cert)

    def __str__(self) -> str:
        perms = []
        if self.permissions & Permission.BOTH.value == Permission.BOTH.value:
            perms.append("BOTH")
        if self.permissions & Permission.CAN_VERIFY.value:
            perms.append("CAN_VERIFY")
        if self.permissions & Permission.CAN_MINT.value:
            perms.append("CAN_MINT")
        data = {
            "issued_to": self.issued_to,
            "permissions": perms if perms else f"0b{self.permissions:03b}",
            "issued_by": self.issued_by,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "signature": self.signature,
            "fee_percentage": self.fee_percentage,
            "currency_name": self.currency_name,
            "currency_ticker": self.currency_ticker,
            "fee_recipient": self.fee_recipient if self.fee_recipient else "None"
        }
        return json.dumps(data, indent=2)

class Block:
    def __init__(self, block_number: int, previous_hash: str, timestamp: int,
                 transactions: List[Transaction], node_certificate: Certificate,
                 block_signature: str, block_hash: str, merkle_root: str = None):
        self.block_number = block_number
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.transactions = transactions
        self.node_certificate = node_certificate
        self.block_signature = block_signature
        self.block_hash = block_hash
        self.merkle_root = merkle_root if merkle_root else compute_merkle_root([tx.tx_id for tx in transactions])

    def to_proto(self) -> microcurrency_pb2.Block:
        proto_block = microcurrency_pb2.Block()
        proto_block.block_number = self.block_number
        proto_block.previous_hash = self.previous_hash
        proto_block.timestamp = self.timestamp
        proto_block.merkle_root = self.merkle_root
        for tx in self.transactions:
            proto_block.transactions.append(tx.to_proto())
        proto_block.node_certificate.CopyFrom(self.node_certificate.to_proto())
        proto_block.block_signature = self.block_signature
        proto_block.block_hash = self.block_hash
        return proto_block

    @staticmethod
    def from_proto(proto_block: microcurrency_pb2.Block) -> "Block":
        transactions = [Transaction.from_proto(tx) for tx in proto_block.transactions]
        certificate = Certificate.from_proto(proto_block.node_certificate)
        return Block(
            block_number=proto_block.block_number,
            previous_hash=proto_block.previous_hash,
            timestamp=proto_block.timestamp,
            transactions=transactions,
            node_certificate=certificate,
            block_signature=proto_block.block_signature,
            block_hash=proto_block.block_hash,
            merkle_root=proto_block.merkle_root
        )

    def serialize(self) -> bytes:
        return self.to_proto().SerializeToString()

    @staticmethod
    def deserialize(data: bytes) -> "Block":
        proto_block = microcurrency_pb2.Block()
        proto_block.ParseFromString(data)
        return Block.from_proto(proto_block)

    def __str__(self) -> str:
        data = {
            "block_number": self.block_number,
            "previous_hash": self.previous_hash,
            "timestamp": self.timestamp,
            "merkle_root": self.merkle_root,
            "transactions": [json.loads(str(tx)) for tx in self.transactions],
            "node_certificate": json.loads(str(self.node_certificate)),
            "block_signature": self.block_signature,
            "block_hash": self.block_hash
        }
        return json.dumps(data, indent=2)

def compute_merkle_root(tx_ids: List[str]) -> str:
    """Compute the Merkle root from a list of transaction IDs."""
    if not tx_ids:
        return ""

    # Convert transaction IDs to bytes
    hashes = [bytes.fromhex(tx_id) for tx_id in tx_ids]

    # Build Merkle tree iteratively
    while len(hashes) > 1:
        temp_hashes = []
        for i in range(0, len(hashes), 2):
            if i + 1 < len(hashes):
                # Pair two hashes and hash them together
                combined = hashes[i] + hashes[i + 1]
                new_hash = hashlib.sha256(combined).digest()
            else:
                # Odd number of hashes, duplicate the last one
                combined = hashes[i] + hashes[i]
                new_hash = hashlib.sha256(combined).digest()
            temp_hashes.append(new_hash)
        hashes = temp_hashes

    # Return the root as hex
    return hashes[0].hex()

# Utility to create a root issuer certificate
def create_root_certificate(public_key: str, private_key: ed25519.Ed25519PrivateKey,
                            fee_percentage: float = 0.0, currency_name: str = "Microcurrency",
                            currency_ticker: str = "MCC", fee_recipient: str = "") -> Certificate:
    timestamp_now = int(time.time())
    valid_duration = 1000 * 365 * 24 * 60 * 60  # 1000 years
    cert = Certificate(
        issued_to=public_key,
        permissions=Permission.BOTH.value,
        issued_by=public_key,
        valid_from=timestamp_now,
        valid_until=timestamp_now + valid_duration,
        signature="",
        fee_percentage=fee_percentage,
        currency_name=currency_name,
        currency_ticker=currency_ticker,
        fee_recipient=fee_recipient if fee_recipient else public_key
    )
    proto_cert = cert.to_proto()
    proto_cert.signature = ""
    signature_data = proto_cert.SerializeToString()
    signature = private_key.sign(signature_data)
    cert.signature = signature.hex()
    return cert

def create_node_certificate(node_public_key: str, permissions: int,
                            issuer_public_key: str, issuer_private_key: ed25519.Ed25519PrivateKey,
                            fee_percentage: float = 0.0, currency_name: str = "Microcurrency",
                            currency_ticker: str = "MCC", fee_recipient: str = "") -> Certificate:
    timestamp_now = int(time.time())
    valid_duration = 365 * 24 * 60 * 60  # 1 year
    cert = Certificate(
        issued_to=node_public_key,
        permissions=permissions,
        issued_by=issuer_public_key,
        valid_from=timestamp_now,
        valid_until=timestamp_now + valid_duration,
        signature="",
        fee_percentage=fee_percentage,
        currency_name=currency_name,
        currency_ticker=currency_ticker,
        fee_recipient=fee_recipient if fee_recipient else issuer_public_key
    )
    proto_cert = cert.to_proto()
    proto_cert.signature = ""
    signature_data = proto_cert.SerializeToString()
    signature = issuer_private_key.sign(signature_data)
    cert.signature = signature.hex()
    return cert

# Verify a certificate's validity and signature
def verify_certificate(certificate: Certificate, issuer_public_key: str) -> bool:
    try:
        current_time = int(time.time())
        if not (certificate.valid_from <= current_time <= certificate.valid_until):
            return False
        issuer_pubkey = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(issuer_public_key))
        proto_cert = certificate.to_proto()
        signature = proto_cert.signature
        proto_cert.signature = ""
        verification_data = proto_cert.SerializeToString()
        issuer_pubkey.verify(bytes.fromhex(signature), verification_data)
        return True
    except Exception:
        return False

# Verify if a node has sufficient permissions to create a block
def verify_block_authority(block: Block, issuer_public_key: str) -> bool:
    if not verify_certificate(block.node_certificate, issuer_public_key):
        return False
    if not Permission.has_permission(block.node_certificate.permissions, Permission.CAN_VERIFY):
        return False
    try:
        node_pubkey = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(block.node_certificate.issued_to))
        block_data = f"{block.block_number}{block.previous_hash}{block.timestamp}{block.merkle_root}{block.node_certificate.signature}"
        node_pubkey.verify(bytes.fromhex(block.block_signature), block_data.encode())
        return True
    except Exception:
        return False

# Verify transaction permissions
def verify_transaction(transaction: Transaction, certificate: Certificate, issuer_public_key: str) -> bool:
    if not verify_certificate(certificate, issuer_public_key):
        return False
    if transaction.tx_type == TransactionType.MINT:
        if not Permission.has_permission(certificate.permissions, Permission.CAN_MINT):
            return False
    try:
        sender_pubkey = ed25519.Ed25519PublicKey.from_public_bytes(bytes.fromhex(transaction.sender))
        tx_data = f"{transaction.sender}{transaction.recipient}{transaction.amount:.2f}{transaction.tx_type.value}"
        sender_pubkey.verify(bytes.fromhex(transaction.signature), tx_data.encode())
        return True
    except Exception:
        return False

# Example key generation
def generate_key_pair():
    private_key = ed25519.Ed25519PrivateKey.generate()
    private_key_raw = private_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption()
    ).hex()
    public_key = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    ).hex()
    return private_key_raw, public_key

# Utility functions for storage
def save_block(block: Block, directory: str = 'blocks'):
    if not os.path.exists(directory):
        os.makedirs(directory)
    file_path = os.path.join(directory, f"blk{block.block_number}.dat")
    with open(file_path, 'wb') as f:
        f.write(block.serialize())

def load_block(block_number: int, directory: str = 'blocks') -> Block:
    file_path = os.path.join(directory, f"blk{block_number}.dat")
    if os.path.exists(file_path):
        with open(file_path, 'rb') as f:
            return Block.deserialize(f.read())
    return None
