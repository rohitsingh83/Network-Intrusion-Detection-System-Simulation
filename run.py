#!/usr/bin/env python3
"""
Network IDS Simulation – Master Launch Script
==============================================
One command to set up & run everything:

    python run.py                     # generate data → start backend
    python run.py --train             # generate data → train ML → start backend
    python run.py --generate-data     # force-regenerate the synthetic dataset
    python run.py --port 9000         # custom port

Author: Rohit Singh | IITD Cybersecurity Project
"""

import argparse
import os
import subprocess
import sys

PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# Step 1: Generate Synthetic Dataset
# ---------------------------------------------------------------------------
def generate_data(count=5000, force=False):
    """Run the synthetic dataset generator."""
    csv_path = os.path.join(PROJECT_ROOT, "data", "network_traffic.csv")

    if os.path.exists(csv_path) and not force:
        print(f"[OK] Dataset already exists: {csv_path}")
        return

    print("=" * 50)
    print("  STEP 1 -- Generating Synthetic Network Traffic")
    print("=" * 50)
    gen_script = os.path.join(PROJECT_ROOT, "simulator", "generate_dataset.py")
    subprocess.run(
        [sys.executable, gen_script, "--count", str(count), "--output", csv_path],
        cwd=PROJECT_ROOT,
        check=True,
    )
    print(f"[OK] Dataset saved to {csv_path}\n")


# ---------------------------------------------------------------------------
# Step 2: Train ML Model
# ---------------------------------------------------------------------------
def train_model():
    """Train ML models on the synthetic dataset."""
    print("=" * 50)
    print("  STEP 2 -- Training ML Models")
    print("=" * 50)
    train_script = os.path.join(PROJECT_ROOT, "ml", "train_model.py")
    os.makedirs(os.path.join(PROJECT_ROOT, "models"), exist_ok=True)
    subprocess.run(
        [
            sys.executable,
            train_script,
            "--data-path",
            os.path.join(PROJECT_ROOT, "data", "network_traffic.csv"),
            "--output-dir",
            os.path.join(PROJECT_ROOT, "models"),
        ],
        cwd=PROJECT_ROOT,
        check=True,
    )
    print("[OK] Model training complete\n")


# ---------------------------------------------------------------------------
# Step 3: Start Backend Server
# ---------------------------------------------------------------------------
def start_server(port=8000):
    """Launch the FastAPI backend server."""
    print("=" * 50)
    print("  STEP 3 — Starting IDS Backend Server")
    print("=" * 50)
    print(f"  Server: http://localhost:{port}")
    print(f"  API Docs: http://localhost:{port}/docs")
    print()
    print("┌──────────────────────────────────────────────────┐")
    print("│  NEXT STEPS (run in separate terminals):         │")
    print("│                                                  │")
    print("│  1. Start Frontend:                              │")
    print("│     cd frontend && npm install && npm start      │")
    print("│                                                  │")
    print("│  2. Start Traffic Simulator:                     │")
    print("│     python simulator/traffic_simulator.py \\      │")
    print("│       --mode mixed --speed fast \\                │")
    print("│       --api-url http://localhost:8000             │")
    print("│                                                  │")
    print("│  3. View Dashboard:                              │")
    print("│     http://localhost:3000                         │")
    print("└──────────────────────────────────────────────────┘")
    print()

    try:
        import uvicorn

        uvicorn.run(
            "backend.app:app",
            host="0.0.0.0",
            port=port,
            reload=True,
        )
    except ImportError:
        print("ERROR: uvicorn not installed.")
        print("Run:  pip install -r requirements.txt")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Network IDS Simulation – Setup & Launch",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run.py                      Generate data → start server
  python run.py --train              Generate data → train ML → start server
  python run.py --generate-data      Force-regenerate the dataset
  python run.py --port 9000          Run server on custom port
        """,
    )
    parser.add_argument(
        "--train", action="store_true", help="Train ML models before starting server"
    )
    parser.add_argument(
        "--generate-data",
        action="store_true",
        help="Force-regenerate the synthetic dataset",
    )
    parser.add_argument(
        "--count",
        type=int,
        default=5000,
        help="Number of records to generate (default: 5000)",
    )
    parser.add_argument(
        "--port", type=int, default=8000, help="Port for the FastAPI server"
    )
    args = parser.parse_args()

    os.chdir(PROJECT_ROOT)

    # Step 1 – Dataset
    generate_data(count=args.count, force=args.generate_data)

    # Step 2 – ML Training (optional)
    if args.train:
        train_model()

    # Step 3 – Backend Server
    start_server(port=args.port)
