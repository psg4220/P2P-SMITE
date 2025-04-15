import requests
import os
import json

# Configuration
BASE_URL = "http://localhost:5000/block/"
OUTPUT_DIR = "blocksTest"
BATCH_SIZE = 5


def ensure_output_dir():
    """Create OUTPUT_DIR if it doesn't exist."""
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)


def download_block(block_id):
    """Download a single block by ID and return its data or None if failed."""
    try:
        response = requests.get(f"{BASE_URL}{block_id}")
        if response.status_code == 200:
            return response.json()  # JSON data from the endpoint
        elif response.status_code == 404:
            print(f"Block {block_id} not found.")
            return None
        elif response.status_code == 400:
            print(f"Invalid block ID {block_id} (must be non-negative).")
            return None
        else:
            print(f"Error fetching block {block_id}: {response.status_code} - {response.text}")
            return None
    except requests.RequestException as e:
        print(f"Network error fetching block {block_id}: {str(e)}")
        return None


def save_block(block_id, data):
    """Save block data to /blocksTest/blk{block_id}.dat."""
    filename = os.path.join(OUTPUT_DIR, f"blk{block_id}.dat")
    try:
        # Save as JSON for now, since endpoint returns JSON
        # Note: For true .dat compatibility, the endpoint should return binary data
        with open(filename, "w") as f:
            json.dump(data, f)
        print(f"Saved block {block_id} to {filename}")
    except Exception as e:
        print(f"Error saving block {block_id} to {filename}: {str(e)}")


def download_blocks_in_batch(start_id, batch_size):
    """Download a batch of blocks starting from start_id."""
    for block_id in range(start_id, start_id + batch_size):
        data = download_block(block_id)
        if data:
            save_block(block_id, data)


def main():
    """Download blocks in batches of 5."""
    ensure_output_dir()

    # Start from block 0 and continue until no more blocks are found
    current_id = 0
    while True:
        print(f"Fetching batch starting at block {current_id}...")
        download_blocks_in_batch(current_id, BATCH_SIZE)
        # Check if the last block in the batch exists to decide whether to continue
        response = requests.get(f"{BASE_URL}{current_id + BATCH_SIZE - 1}")
        if response.status_code == 404:
            print("Reached end of available blocks.")
            break
        current_id += BATCH_SIZE


if __name__ == "__main__":
    main()