import requests
import time
import threading
import json
from microcurrency import Transaction, TransactionType
from cryptography.hazmat.primitives.asymmetric import ed25519

# Configuration
BASE_URL = "http://localhost:5000"
TRANSACTION_ENDPOINT = f"{BASE_URL}/transaction"
STATUS_ENDPOINT = f"{BASE_URL}/status"
BALANCE_ENDPOINT = f"{BASE_URL}/balance"
CURRENT_BLOCK_ENDPOINT = f"{BASE_URL}/get_current_block"
TIMEOUT = 5
DELAY_BETWEEN_BATCHES = 5  # Seconds between batches
BLOCK_WAIT_TIMEOUT = 60  # Max seconds to wait for block confirmation
MAX_THREADS = 3  # Maximum concurrent threads
BATCH_SIZE = 2  # Number of OUTPUT transactions per batch
OUTPUT_AMOUNT = 100  # Amount for OUTPUT transactions

# Keys
ROOT_PRIVATE_KEY = "de7cff4d79e4959d7664b618f731d150c194a40378685f82a6afc18abe11bb30"
ROOT_PUBLIC_KEY = "5a8dbba5f562da04a4fb963cc438ecc2cbbf74382d6f9dc6a79f6c11f009405a"
TX_PRIVATE_KEY = "d5c433a8320d6b3658fb897777d648c337c1ba10ad8162c9ca5ae8b450be8152"
TX_PUBLIC_KEY = "db660afa86e9df455fefbe241b411546a5c51c3c7429435d6b3e2773434d3dfd"

# Lock for thread-safe printing
print_lock = threading.Lock()


def safe_print(*args, **kwargs):
    """Thread-safe print function."""
    with print_lock:
        print(*args, **kwargs)


def create_transaction(private_key, sender, recipient, amount, tx_type, fee=0, fee_recipient=None):
    """Create a signed transaction with optional fee signature."""
    try:
        private_key_bytes = bytes.fromhex(private_key)
        private_key_obj = ed25519.Ed25519PrivateKey.from_private_bytes(private_key_bytes)

        # Primary transaction signature
        tx_data = f"{sender}{recipient}{amount}{tx_type.value}"
        signature = private_key_obj.sign(tx_data.encode()).hex()

        tx = Transaction(
            sender=sender,
            recipient=recipient,
            amount=amount,
            tx_type=tx_type,
            signature=signature
        )

        fee_signature = None
        if fee > 0 and fee_recipient and tx_type == TransactionType.OUTPUT:
            # Fee transaction signature
            fee_tx_data = f"{sender}{fee_recipient}{fee}{TransactionType.OUTPUT.value}"
            fee_signature = private_key_obj.sign(fee_tx_data.encode()).hex()
            safe_print(f"Generated fee signature for fee={fee} to {fee_recipient}")

        return tx, fee_signature
    except Exception as e:
        safe_print(f"Error creating transaction: {e}")
        return None, None


def get_node_info():
    """Fetch the node's fee percentage and fee recipient from the status endpoint."""
    try:
        response = requests.get(STATUS_ENDPOINT, timeout=TIMEOUT)
        response.raise_for_status()
        status = response.json()
        certificate = status.get("certificate", {})
        return {
            "fee_percentage": float(certificate.get("fee_percentage", 0.0)),
            "fee_recipient": certificate.get("fee_recipient", ROOT_PUBLIC_KEY)
        }
    except requests.RequestException as e:
        safe_print(f"Error fetching node status: {e}")
        return {"fee_percentage": 0.0, "fee_recipient": ROOT_PUBLIC_KEY}
    except ValueError as e:
        safe_print(f"Invalid node status response: {e}")
        return {"fee_percentage": 0.0, "fee_recipient": ROOT_PUBLIC_KEY}


def get_balance(address):
    """Fetch the committed balance for an address."""
    try:
        response = requests.get(f"{BALANCE_ENDPOINT}/{address}", timeout=TIMEOUT)
        response.raise_for_status()
        data = response.json()
        return int(data.get("balance", 0))
    except requests.RequestException as e:
        safe_print(f"Error fetching balance for {address}: {e}")
        return 0
    except ValueError as e:
        safe_print(f"Invalid balance response for {address}: {e}")
        return 0


def wait_for_block_inclusion(tx_id, initial_block_height):
    """Wait until a transaction is included in a block."""
    start_time = time.time()
    while time.time() - start_time < BLOCK_WAIT_TIMEOUT:
        try:
            response = requests.get(CURRENT_BLOCK_ENDPOINT, timeout=TIMEOUT)
            response.raise_for_status()
            block = response.json()
            current_height = block.get("block_number", -1)
            if current_height > initial_block_height:
                for tx in block.get("transactions", []):
                    if tx.get("tx_id") == tx_id:
                        safe_print(f"Transaction {tx_id} included in block {current_height}")
                        return True
                # Check previous blocks
                for height in range(initial_block_height + 1, current_height + 1):
                    block_response = requests.get(f"{BASE_URL}/block/{height}", timeout=TIMEOUT)
                    if block_response.status_code == 200:
                        block_data = block_response.json()
                        for tx in block_data.get("transactions", []):
                            if tx.get("tx_id") == tx_id:
                                safe_print(f"Transaction {tx_id} included in block {height}")
                                return True
        except requests.RequestException as e:
            safe_print(f"Error checking block: {e}")
        time.sleep(1)
    safe_print(f"Timeout waiting for transaction {tx_id} to be included in a block")
    return False


def send_transaction(sender, recipient, amount, tx_type, private_key, thread_name):
    """Send a transaction to the /transaction endpoint with fee handling."""
    try:
        # Get node fee info
        node_info = get_node_info()
        fee_percentage = node_info["fee_percentage"]
        fee_recipient = node_info["fee_recipient"]

        # Calculate fee for OUTPUT transactions
        fee = 0
        if tx_type == TransactionType.OUTPUT and fee_percentage > 0:
            fee = int(amount * fee_percentage)
            safe_print(f"Calculated fee: {fee} (amount={amount}, fee_percentage={fee_percentage})")

        # Check balance for OUTPUT transactions
        if tx_type == TransactionType.OUTPUT:
            balance = get_balance(sender)
            total_required = amount + fee
            if balance < total_required:
                safe_print(f"Insufficient balance for {sender}: {balance} < {total_required} (Thread: {thread_name})")
                return None

        # Create transaction
        tx, fee_signature = create_transaction(
            private_key, sender, recipient, amount, tx_type, fee, fee_recipient
        )
        if not tx:
            safe_print(f"Transaction creation failed (Thread: {thread_name})")
            return None

        payload = {
            "sender": tx.sender,
            "recipient": tx.recipient,
            "amount": tx.amount,
            "tx_type": tx.tx_type.name,
            "signature": tx.signature
        }
        if fee_signature and fee > 0:
            payload["fee_signature"] = fee_signature
            safe_print(f"Including fee_signature in payload (Thread: {thread_name})")

        headers = {"Content-Type": "application/json"}
        response = requests.post(
            TRANSACTION_ENDPOINT,
            json=payload,
            headers=headers,
            timeout=TIMEOUT
        )

        safe_print(f"Status Code: {response.status_code} (Thread: {thread_name})")
        response_json = response.json()
        safe_print(f"Response (Thread: {thread_name}):")
        safe_print(json.dumps(response_json, indent=2))

        return response_json
    except requests.RequestException as e:
        safe_print(f"Error sending transaction (Thread: {thread_name}): {e}")
        return None
    except ValueError as e:
        safe_print(f"Invalid response format (Thread: {thread_name}): {e}")
        return None


def simulate_mint_transaction():
    """Simulate a MINT transaction."""
    thread_name = threading.current_thread().name
    safe_print(f"\n=== Simulating MINT Transaction (Thread: {thread_name}) ===")
    return send_transaction(
        sender=ROOT_PUBLIC_KEY,
        recipient=TX_PUBLIC_KEY,
        amount=100000,
        tx_type=TransactionType.MINT,
        private_key=ROOT_PRIVATE_KEY,
        thread_name=thread_name
    )


def simulate_output_transaction():
    """Simulate an OUTPUT transaction."""
    thread_name = threading.current_thread().name
    safe_print(f"\n=== Simulating OUTPUT Transaction (Thread: {thread_name}) ===")
    return send_transaction(
        sender=TX_PUBLIC_KEY,
        recipient=ROOT_PUBLIC_KEY,
        amount=OUTPUT_AMOUNT,
        tx_type=TransactionType.OUTPUT,
        private_key=TX_PRIVATE_KEY,
        thread_name=thread_name
    )


def run_transaction_batch(batch_number):
    """Run a batch of transactions with thread pool."""
    try:
        # Get current block height
        initial_block_height = -1
        try:
            response = requests.get(CURRENT_BLOCK_ENDPOINT, timeout=TIMEOUT)
            if response.status_code == 200:
                initial_block_height = response.json().get("block_number", -1)
        except requests.RequestException:
            safe_print("Error fetching current block height, proceeding with mint")

        # Step 1: Send MINT transaction
        mint_response = simulate_mint_transaction()
        if not mint_response or "tx_id" not in mint_response:
            safe_print(f"Batch {batch_number}: MINT transaction failed, aborting batch")
            return

        tx_id = mint_response["tx_id"]
        safe_print(f"Batch {batch_number}: MINT transaction sent with tx_id {tx_id}")

        # Step 2: Wait for MINT transaction to be included in a block
        if not wait_for_block_inclusion(tx_id, initial_block_height):
            safe_print(f"Batch {batch_number}: MINT transaction not confirmed, aborting batch")
            return

        # Step 3: Verify balance
        node_info = get_node_info()
        fee_percentage = node_info["fee_percentage"]
        required_balance = OUTPUT_AMOUNT + int(OUTPUT_AMOUNT * fee_percentage)
        balance = get_balance(TX_PUBLIC_KEY)
        if balance < required_balance * BATCH_SIZE:
            safe_print(
                f"Batch {batch_number}: Insufficient balance after MINT: {balance} < {required_balance * BATCH_SIZE}")
            return

        # Step 4: Send OUTPUT transactions in parallel
        threads = []
        semaphore = threading.Semaphore(MAX_THREADS)

        def run_transaction(task, name):
            with semaphore:
                result = task()
                safe_print(f"Completed {name}")
                return result

        for i in range(BATCH_SIZE):
            thread = threading.Thread(
                target=run_transaction,
                args=(simulate_output_transaction, f"OUTPUT-{i + 1}"),
                name=f"Batch-{batch_number}-OUTPUT-{i + 1}"
            )
            threads.append(thread)

        # Start OUTPUT threads
        for thread in threads:
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join()

    except Exception as e:
        safe_print(f"Batch {batch_number}: Error in batch execution: {e}")


def main():
    """Run continuous transaction batches with improved management."""
    safe_print("Starting transaction simulation with threads...")
    batch_count = 0

    try:
        while True:
            batch_count += 1
            safe_print(f"\n=== Starting Batch {batch_count} ===")
            run_transaction_batch(batch_count)
            safe_print(f"\n=== Batch {batch_count} Complete ===")
            time.sleep(DELAY_BETWEEN_BATCHES)
    except KeyboardInterrupt:
        safe_print("\nStopping transaction simulation...")
    finally:
        safe_print("Simulation terminated.")


if __name__ == "__main__":
    main()