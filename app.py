import os
import sqlite3
import json
import time
from flask import Flask, request, jsonify
from threading import Timer
import requests
from dotenv import load_dotenv
from microcurrency import (
    Transaction, Certificate, Block, Permission, TransactionType,
    create_root_certificate, create_node_certificate, verify_block_authority,
    verify_transaction, generate_key_pair, save_block, load_block, compute_merkle_root
)
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
import hashlib
from waitress import serve
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# Load environment variables from .env
load_dotenv()

app = Flask(__name__)

# Configure JSON output for indentation
app.json.compact = False
app.json.indent = 2

limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Configuration from .env
NODES_FILE = os.getenv("NODES_FILE", "nodes.txt")
FILES_DIR = os.getenv("FILES_DIR", "blocks")
BLOCK_CREATION_INTERVAL = int(os.getenv("BLOCK_CREATION_INTERVAL", 30))
PRIVATE_KEY_HEX = os.getenv("PRIVATE_KEY")
DB_FILE = os.path.join(FILES_DIR, "transactions.db")

# Validate private key
if not PRIVATE_KEY_HEX:
    raise ValueError("PRIVATE_KEY is required in .env")
try:
    PRIVATE_KEY = ed25519.Ed25519PrivateKey.from_private_bytes(bytes.fromhex(PRIVATE_KEY_HEX))
except Exception as e:
    raise ValueError(f"Invalid PRIVATE_KEY format: {str(e)}")

# Load certificate
cert_path = os.path.join(FILES_DIR, "certificate.dat")
if not os.path.exists(cert_path):
    raise ValueError(f"No certificate found at {cert_path}. All nodes require a valid certificate.")
with open(cert_path, 'rb') as f:
    NODE_CERTIFICATE = Certificate.deserialize(f.read())

# Derive public key and verify
PUBLIC_KEY = PRIVATE_KEY.public_key().public_bytes(
    encoding=serialization.Encoding.Raw,
    format=serialization.PublicFormat.Raw
).hex()
if PUBLIC_KEY != NODE_CERTIFICATE.issued_to:
    raise ValueError(f"PRIVATE_KEY does not match certificate issued_to {NODE_CERTIFICATE.issued_to}")

# Determine if root node
IS_ROOT = NODE_CERTIFICATE.issued_to == NODE_CERTIFICATE.issued_by

PENDING_TRANSACTIONS = []
BLOCK_CREATION_TIMER = None

# Ensure blocks directory exists
if not os.path.exists(FILES_DIR):
    os.makedirs(FILES_DIR)


# Initialize SQLite database
def init_db():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS transactions (
            tx_id TEXT PRIMARY KEY,
            sender TEXT,
            recipient TEXT,
            amount INTEGER,
            tx_type TEXT,
            signature TEXT,
            timestamp INTEGER,
            block_number INTEGER
        )
    ''')
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS metadata (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_sender ON transactions (sender)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_recipient ON transactions (recipient)')
    conn.commit()
    conn.close()


def get_latest_indexed_block_number():
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT value FROM metadata WHERE key = 'latest_block_number'")
    result = cursor.fetchone()
    conn.close()
    return int(result[0]) if result else -1


def set_latest_indexed_block_number(block_number):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT OR REPLACE INTO metadata (key, value) VALUES ('latest_block_number', ?)",
                   (str(block_number),))
    conn.commit()
    conn.close()


def index_block(block):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    for tx in block.transactions:
        cursor.execute('''
            INSERT OR IGNORE INTO transactions (tx_id, sender, recipient, amount, tx_type, signature, timestamp, block_number)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
        tx.tx_id, tx.sender, tx.recipient, tx.amount, tx.tx_type.name, tx.signature, tx.timestamp, block.block_number))
    conn.commit()
    conn.close()


def index_missing_blocks():
    latest_indexed = get_latest_indexed_block_number()
    latest_on_disk = get_latest_block_number()
    for block_num in range(latest_indexed + 1, latest_on_disk + 1):
        block = load_block(block_num, FILES_DIR)
        if block:
            index_block(block)
            set_latest_indexed_block_number(block_num)
            print(f" * Indexed block {block_num}")


def get_committed_balance(address):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT 
            COALESCE(SUM(CASE WHEN recipient = ? THEN amount ELSE 0 END), 0) -
            COALESCE(SUM(CASE WHEN sender = ? AND tx_type != 'MINT' THEN amount ELSE 0 END), 0)
        FROM transactions
        WHERE sender = ? OR recipient = ?
    """, (address, address, address, address))
    balance = cursor.fetchone()[0]
    conn.close()
    return balance or 0


def get_latest_block_number():
    block_files = [f for f in os.listdir(FILES_DIR) if f.startswith("blk") and f.endswith(".dat")]
    if not block_files:
        return -1
    return max(int(f.split('blk')[1].split('.')[0]) for f in block_files)


def load_nodes():
    try:
        with open(NODES_FILE, 'r') as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"Warning: {NODES_FILE} not found.")
        return []


def create_block():
    global PENDING_TRANSACTIONS, BLOCK_CREATION_TIMER
    if not PENDING_TRANSACTIONS:
        return

    latest_block_number = get_latest_block_number()
    previous_block = load_block(latest_block_number, FILES_DIR)
    previous_hash = previous_block.block_hash if previous_block else '0' * 64
    block_number = latest_block_number + 1
    timestamp = int(time.time())

    merkle_root = compute_merkle_root([tx.tx_id for tx in PENDING_TRANSACTIONS])
    block_data = f"{block_number}{previous_hash}{timestamp}{merkle_root}{NODE_CERTIFICATE.signature}"
    block_signature = PRIVATE_KEY.sign(block_data.encode()).hex()
    block_hash = hashlib.sha256(block_data.encode()).hexdigest()

    block = Block(
        block_number=block_number,
        previous_hash=previous_hash,
        timestamp=timestamp,
        transactions=PENDING_TRANSACTIONS,
        node_certificate=NODE_CERTIFICATE,
        block_signature=block_signature,
        block_hash=block_hash,
        merkle_root=merkle_root
    )

    if verify_block_authority(block, NODE_CERTIFICATE.issued_by):
        save_block(block, FILES_DIR)
        index_block(block)
        set_latest_indexed_block_number(block.block_number)
        print(f"Block {block_number} created.")
        broadcast_block(block)
        PENDING_TRANSACTIONS = []
        BLOCK_CREATION_TIMER = None


def create_pending_block():
    if not PENDING_TRANSACTIONS:
        return None

    latest_block_number = get_latest_block_number()
    previous_block = load_block(latest_block_number, FILES_DIR)
    previous_hash = previous_block.block_hash if previous_block else '0' * 64
    block_number = latest_block_number + 1
    timestamp = int(time.time())

    merkle_root = compute_merkle_root([tx.tx_id for tx in PENDING_TRANSACTIONS])
    block_data = f"{block_number}{previous_hash}{timestamp}{merkle_root}{NODE_CERTIFICATE.signature}"
    block_signature = PRIVATE_KEY.sign(block_data.encode()).hex()
    block_hash = hashlib.sha256(block_data.encode()).hexdigest()

    return Block(
        block_number=block_number,
        previous_hash=previous_hash,
        timestamp=timestamp,
        transactions=PENDING_TRANSACTIONS,
        node_certificate=NODE_CERTIFICATE,
        block_signature=block_signature,
        block_hash=block_hash,
        merkle_root=merkle_root
    )


def find_fork_point(new_block):
    current_block = new_block
    while current_block.block_number > 0:
        prev_block = load_block(current_block.block_number - 1, FILES_DIR)
        if prev_block and prev_block.block_hash == current_block.previous_hash:
            return current_block.block_number - 1
        current_block = fetch_block(current_block.previous_hash)
        if not current_block:
            return None
    return None


def fetch_block(block_hash):
    for node_uri in load_nodes():
        try:
            response = requests.get(f"{node_uri}/get_block/{block_hash}", timeout=5)
            if response.status_code == 200:
                return Block.deserialize(response.content)
        except requests.RequestException:
            continue
    return None


def fetch_new_chain_segment(fork_point, new_block):
    chain_segment = [new_block]
    current_block = new_block
    while current_block.block_number > fork_point + 1:
        prev_block = fetch_block(current_block.previous_hash)
        if not prev_block:
            return None
        chain_segment.insert(0, prev_block)
        current_block = prev_block
    return chain_segment


def validate_chain_segment(chain_segment):
    for i, block in enumerate(chain_segment):
        if not verify_block_authority(block, block.node_certificate.issued_by):
            return False
        if i > 0 and block.previous_hash != chain_segment[i - 1].block_hash:
            return False
    return True


def reorganize_chain(fork_point, new_chain):
    latest_block_number = get_latest_block_number()
    for block_num in range(fork_point + 1, latest_block_number + 1):
        block_path = os.path.join(FILES_DIR, f"blk{block_num}.dat")
        if os.path.exists(block_path):
            os.remove(block_path)

    for block in new_chain:
        save_block(block, FILES_DIR)
        index_block(block)

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM transactions WHERE block_number > ?", (fork_point,))
    for block in new_chain:
        for tx in block.transactions:
            cursor.execute('''
                INSERT OR IGNORE INTO transactions (tx_id, sender, recipient, amount, tx_type, signature, timestamp, block_number)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (tx.tx_id, tx.sender, tx.recipient, tx.amount, tx.tx_type.name, tx.signature, tx.timestamp,
                  block.block_number))
    conn.commit()
    conn.close()
    set_latest_indexed_block_number(new_chain[-1].block_number)


def broadcast_block(block):
    serialized_block = block.serialize()
    for node_uri in load_nodes():
        try:
            requests.post(f"{node_uri}/block", data=serialized_block, timeout=5)
        except requests.RequestException as e:
            print(f"Error broadcasting to {node_uri}: {e}")


def start_block_timer():
    global BLOCK_CREATION_TIMER
    if BLOCK_CREATION_TIMER is None:
        BLOCK_CREATION_TIMER = Timer(BLOCK_CREATION_INTERVAL, create_block)
        BLOCK_CREATION_TIMER.start()


@app.route('/block', methods=['POST'])
@limiter.limit("10 per minute")
def receive_block():
    try:
        new_block = Block.deserialize(request.data)
        latest_block_number = get_latest_block_number()
        current_tip = load_block(latest_block_number, FILES_DIR)

        if new_block.previous_hash == current_tip.block_hash:
            if verify_block_authority(new_block, new_block.node_certificate.issued_by):
                save_block(new_block, FILES_DIR)
                index_block(new_block)
                set_latest_indexed_block_number(new_block.block_number)
                print(f"Block {new_block.block_number} added to the chain.")
                return jsonify({"message": "Block accepted"})
            else:
                return jsonify({"error": "Block verification failed"}), 400
        else:
            fork_point = find_fork_point(new_block)
            if fork_point is None:
                return jsonify({"error": "Block does not connect to any known block"}), 400

            new_chain = fetch_new_chain_segment(fork_point, new_block)
            if not new_chain:
                return jsonify({"error": "Failed to fetch new chain segment"}), 500

            if validate_chain_segment(new_chain):
                current_chain_length = latest_block_number - fork_point
                new_chain_length = len(new_chain)
                if new_chain_length > current_chain_length:
                    reorganize_chain(fork_point, new_chain)
                    print(f"Chain reorganized to new chain starting from block {fork_point}")
                    return jsonify({"message": "Chain reorganized"})
                else:
                    return jsonify({"message": "New chain not longer, ignoring"})
            else:
                return jsonify({"error": "New chain segment invalid"}), 400

    except Exception as e:
        print(f"Error processing block: {str(e)}")
        return jsonify({"error": f"Invalid block data: {str(e)}"}), 400


@app.route('/transaction', methods=['POST'])
@limiter.limit("10000 per minute")
def receive_transaction():
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No JSON data provided"}), 400

        sender = data.get("sender")
        recipient = data.get("recipient")
        amount = data.get("amount")
        tx_type = data.get("tx_type")
        signature = data.get("signature")
        fee_signature = data.get("fee_signature")  # New field for fee transaction

        if not all([sender, recipient, amount, tx_type, signature]):
            return jsonify({"error": "Missing transaction parameters"}), 400

        try:
            amount = int(amount)
            if amount <= 0:
                raise ValueError("Amount must be positive")
        except (ValueError, TypeError):
            return jsonify({"error": "Invalid amount format"}), 400

        try:
            tx_type = TransactionType[tx_type]
        except KeyError:
            return jsonify({"error": "Invalid transaction type"}), 400

        if tx_type == TransactionType.MINT:
            if sender != NODE_CERTIFICATE.issued_to:
                return jsonify({"error": "MINT transaction sender must be the node's public key"}), 400
            if not IS_ROOT:
                return jsonify({"error": "Only root nodes can mint"}), 403

        # Calculate fee for OUTPUT transactions using only fee_percentage
        fee = 0
        fee_tx_id = None
        if tx_type == TransactionType.OUTPUT and NODE_CERTIFICATE.fee_percentage:
            fee = int(amount * NODE_CERTIFICATE.fee_percentage)

            # Validate balance including fee
            committed_balance = get_committed_balance(sender)
            if committed_balance < amount + fee:
                return jsonify({"error": f"Insufficient balance for amount + fee ({amount + fee})"}), 400

            # Require fee_signature if fee is non-zero
            if fee > 0 and not fee_signature:
                return jsonify({"error": "Fee signature required for transactions with a fee"}), 400

        # Create primary transaction
        tx = Transaction(
            sender=sender,
            recipient=recipient,
            amount=amount,
            tx_type=tx_type,
            signature=signature
        )

        # Verify primary transaction
        if not verify_transaction(tx, NODE_CERTIFICATE, NODE_CERTIFICATE.issued_by):
            print(f"Transaction verification failed for tx_id: {tx.tx_id}")
            return jsonify({"error": "Transaction verification failed"}), 400

        # Create fee transaction if applicable
        if tx_type == TransactionType.OUTPUT and fee > 0:
            fee_recipient = NODE_CERTIFICATE.fee_recipient or NODE_CERTIFICATE.issued_to
            fee_tx = Transaction(
                sender=sender,
                recipient=fee_recipient,
                amount=fee,
                tx_type=TransactionType.OUTPUT,
                signature=fee_signature
            )

            # Verify fee transaction
            if not verify_transaction(fee_tx, NODE_CERTIFICATE, NODE_CERTIFICATE.issued_by):
                print(f"Fee transaction verification failed for tx_id: {fee_tx.tx_id}")
                return jsonify({"error": "Fee transaction verification failed"}), 400

            fee_tx_id = fee_tx.tx_id
            PENDING_TRANSACTIONS.append(fee_tx)

        # Append primary transaction
        PENDING_TRANSACTIONS.append(tx)
        start_block_timer()

        response = {
            "message": "Transaction accepted",
            "tx_id": tx.tx_id,
            "fee": fee
        }
        if fee_tx_id:
            response["fee_tx_id"] = fee_tx_id

        return jsonify(response)

    except Exception as e:
        print(f"Error processing transaction: {str(e)}")
        return jsonify({"error": f"Transaction processing failed: {str(e)}"}), 400

@app.route('/', methods=['GET'])
@limiter.limit("10 per minute")
def get_root():
    try:
        block_height = get_latest_block_number()
        seconds_until_next = BLOCK_CREATION_INTERVAL
        if block_height >= 0:
            latest_block = load_block(block_height, FILES_DIR)
            if latest_block:
                time_since_block = int(time.time()) - latest_block.timestamp
                seconds_until_next = max(0, BLOCK_CREATION_INTERVAL - (time_since_block % BLOCK_CREATION_INTERVAL))

        response = {
            "block_height": block_height,
            "seconds_until_next_block": seconds_until_next
        }
        return jsonify(response)
    except Exception as e:
        return jsonify({"error": f"Error retrieving info: {str(e)}"}), 500


@app.route('/balance/<address>', methods=['GET'])
@limiter.limit("10 per minute")
def get_balance(address):
    try:
        balance = get_committed_balance(address)
        return jsonify({"address": address, "balance": balance})
    except Exception as e:
        print(f"Error retrieving balance: {str(e)}")
        return jsonify({"error": f"Error retrieving balance: {str(e)}"}), 500


@app.route('/status', methods=['GET'])
@limiter.limit("10 per minute")
def get_status():
    latest_block_num = get_latest_block_number()
    latest_block = load_block(latest_block_num, FILES_DIR) if latest_block_num >= 0 else None

    status = {
        "node_type": "root" if IS_ROOT else "standard",
        "public_key": NODE_CERTIFICATE.issued_to,
        "issuer_public_key": NODE_CERTIFICATE.issued_by,
        "latest_block": latest_block_num,
        "pending_transactions": len(PENDING_TRANSACTIONS),
        "block_time": latest_block.timestamp if latest_block else 0,
        "network_nodes": len(load_nodes())
    }
    return jsonify(status)


@app.route('/get_current_block', methods=['GET'])
@limiter.limit("500 per minute")
def get_current_block():
    try:
        latest_block_number = get_latest_block_number()
        if latest_block_number < 0:
            return jsonify({"error": "No blocks found"}), 404
        block = load_block(latest_block_number, FILES_DIR)
        if not block:
            return jsonify({"error": f"Failed to load block {latest_block_number}"}), 500
        return jsonify(json.loads(str(block)))
    except Exception as e:
        return jsonify({"error": f"Error retrieving block: {str(e)}"}), 500


@app.route('/get_pending_block', methods=['GET'])
@limiter.limit("100 per minute")
def get_pending_block():
    try:
        block = create_pending_block()
        if not block:
            return jsonify({"error": "No pending transactions"}), 404
        return jsonify(json.loads(str(block)))
    except Exception as e:
        return jsonify({"error": f"Error generating pending block: {str(e)}"}), 500


@app.route('/block/<int:id>', methods=['GET'])
@limiter.limit("200 per minute")
def get_block_by_id(id):
    try:
        if id < 0:
            return jsonify({"error": "Block ID must be non-negative"}), 400
        block = load_block(id, FILES_DIR)
        if not block:
            return jsonify({"error": f"Block {id} not found"}), 404
        return jsonify(json.loads(str(block)))
    except Exception as e:
        return jsonify({"error": f"Error retrieving block {id}: {str(e)}"}), 500


@app.route('/get_block/<int:id>', methods=['GET'])
@limiter.limit("1000 per minute")
def get_block_binary(id):
    try:
        if id < 0:
            return jsonify({"error": "Block ID must be non-negative"}), 400
        block = load_block(id, FILES_DIR)
        if not block:
            return jsonify({"error": f"Block {id} not found"}), 404
        return block.serialize(), 200, {"Content-Type": "application/octet-stream"}
    except Exception as e:
        return jsonify({"error": f"Error retrieving block {id}: {str(e)}"}), 500


if __name__ == '__main__':
    port = int(os.getenv("PORT", 5000))
    host = os.getenv("HOST", "127.0.0.1")
    debug = os.getenv("DEBUG", "False").lower() == "true"
    disable_tor = os.getenv("DISABLE_TOR", "False").lower() == "true"

    print(f"Starting microcurrency node on {host}:{port}")
    print(f"Node type: {'Root' if IS_ROOT else 'Standard'}")
    print(f"Public key: {NODE_CERTIFICATE.issued_to}")
    print(f"Issuer public key: {NODE_CERTIFICATE.issued_by}")

    init_db()
    index_missing_blocks()
    if debug:
        print("Running in debug mode with Flask development server...")
        app.run(host=host, port=port, debug=debug)
    else:
        print("Running in production mode with Waitress...")
        serve(app, host=host, port=port, threads=8)