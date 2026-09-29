import argparse
import json
import time
import urllib.request
import urllib.error
import random
from datetime import datetime

# Import generator logic from generate_dataset
# We need to make sure we can import it. The directory is 'simulator'.
try:
    from .generate_dataset import generate_record
except ImportError:
    from generate_dataset import generate_record

def send_to_api(url, data):
    """Post flow data to backend API."""
    req = urllib.request.Request(
        url, 
        data=json.dumps(data).encode('utf-8'), 
        headers={'Content-Type': 'application/json'}, 
        method='POST'
    )
    try:
        urllib.request.urlopen(req, timeout=2)
    except Exception as e:
        print(f"Error posting to API: {e}")

def main():
    parser = argparse.ArgumentParser(description="Real-time traffic simulator.")
    parser.add_argument("--mode", choices=["normal", "mixed"], default="mixed", help="Traffic mode (normal only or mixed).")
    parser.add_argument("--speed", choices=["slow", "fast"], default="slow", help="Generation speed.")
    parser.add_argument("--api-url", type=str, help="API URL to post flows (e.g., http://localhost:8000).")
    parser.add_argument("--duration", type=int, default=300, help="Duration to run in seconds (0 for infinite).")
    args = parser.parse_args()

    print(f"Starting traffic simulator in {args.mode} mode, {args.speed} speed...")
    if args.api_url:
        print(f"Posting to {args.api_url}/api/flows")
        
    start_time = time.time()
    
    try:
        while True:
            if args.duration > 0 and (time.time() - start_time) > args.duration:
                print("Simulation duration reached. Exiting.")
                break
                
            is_suspicious = False
            if args.mode == "mixed":
                # Occasional bursts logic could be complex, keeping it simple: 30% chance
                is_suspicious = random.random() < 0.3
                
            record = generate_record(datetime.now(), is_suspicious)
            
            if args.api_url:
                url = args.api_url.rstrip("/") + "/api/flows"
                send_to_api(url, record)
            else:
                print(json.dumps(record))
                
            # Speed control
            if args.speed == "slow":
                time.sleep(2.0)
            else:
                time.sleep(0.2)
                
    except KeyboardInterrupt:
        print("\nSimulator stopped by user.")

if __name__ == "__main__":
    main()
