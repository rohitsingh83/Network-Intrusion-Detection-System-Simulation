import argparse
import csv
import random
import sys
import uuid
import os
from datetime import datetime, timedelta

# RFC 5737 Documentation IPs
IP_PREFIXES = ["192.0.2.", "198.51.100.", "203.0.113."]

def generate_ip():
    """Generate a random RFC 5737 IP address."""
    return f"{random.choice(IP_PREFIXES)}{random.randint(1, 254)}"

def get_scenario_properties(scenario_type):
    """Return traffic properties based on scenario type."""
    if scenario_type == "NORMAL_WEB":
        return {"dest_port": random.choice([80, 443]), "protocol": "TCP", "packet_count": random.randint(10, 500),
                "duration": random.uniform(0.1, 10.0), "failed": random.randint(0, 1), "syn": 1, "rst": random.randint(0, 1)}
    elif scenario_type == "NORMAL_DNS":
        return {"dest_port": 53, "protocol": random.choice(["UDP", "TCP"]), "packet_count": random.randint(2, 10),
                "duration": random.uniform(0.01, 0.5), "failed": 0, "syn": 1 if random.random() > 0.5 else 0, "rst": 0}
    elif scenario_type == "NORMAL_SSH":
        return {"dest_port": 22, "protocol": "TCP", "packet_count": random.randint(50, 1000),
                "duration": random.uniform(1.0, 300.0), "failed": random.randint(0, 2), "syn": 1, "rst": 1}
    elif scenario_type == "NORMAL_EMAIL":
        return {"dest_port": random.choice([25, 587, 993]), "protocol": "TCP", "packet_count": random.randint(20, 200),
                "duration": random.uniform(0.5, 30.0), "failed": 0, "syn": 1, "rst": 1}
    elif scenario_type == "NORMAL_DATABASE":
        return {"dest_port": random.choice([3306, 5432]), "protocol": "TCP", "packet_count": random.randint(100, 5000),
                "duration": random.uniform(5.0, 600.0), "failed": 0, "syn": 1, "rst": 1}
    elif scenario_type == "HIGH_CONNECTION_RATE":
        return {"dest_port": 80, "protocol": "TCP", "packet_count": random.randint(5, 20),
                "duration": random.uniform(0.01, 0.1), "conn_count": random.randint(100, 500), "failed": random.randint(10, 50), "syn": 1, "rst": 1}
    elif scenario_type == "REPEATED_FAILED_CONNECTIONS":
        return {"dest_port": random.choice([22, 3389]), "protocol": "TCP", "packet_count": random.randint(3, 10),
                "duration": random.uniform(0.1, 5.0), "conn_count": random.randint(20, 100), "failed": random.randint(15, 95), "syn": 1, "rst": random.randint(15, 95)}
    elif scenario_type == "MULTI_PORT_PROBING_PATTERN":
        return {"dest_port": random.randint(1, 65535), "protocol": "TCP", "packet_count": random.randint(1, 5),
                "duration": random.uniform(0.001, 0.05), "conn_count": random.randint(50, 200), "failed": random.randint(40, 190), "syn": 1, "rst": random.randint(1, 5)}
    elif scenario_type == "SYN_HEAVY_PATTERN":
        return {"dest_port": 80, "protocol": "TCP", "packet_count": random.randint(100, 1000),
                "duration": random.uniform(0.5, 2.0), "conn_count": 1, "failed": 0, "syn": random.randint(90, 950), "rst": 0}
    elif scenario_type == "UNUSUAL_PORT_ACTIVITY":
        return {"dest_port": random.choice([4444, 8888, 31337]), "protocol": "TCP", "packet_count": random.randint(10, 100),
                "duration": random.uniform(1.0, 10.0), "conn_count": random.randint(1, 5), "failed": 0, "syn": 1, "rst": 0}
    elif scenario_type == "HIGH_TRAFFIC_VOLUME":
        return {"dest_port": 443, "protocol": "TCP", "packet_count": random.randint(10000, 100000),
                "duration": random.uniform(10.0, 100.0), "conn_count": 1, "failed": 0, "syn": 1, "rst": 0, "byte_mult": 1500}
    
    # Default fallback
    return {"dest_port": 80, "protocol": "TCP", "packet_count": 10, "duration": 1.0, "failed": 0, "syn": 1, "rst": 0}

def generate_record(timestamp, is_suspicious=False):
    """Generate a single flow record."""
    if is_suspicious:
        scenario = random.choice([
            "HIGH_CONNECTION_RATE", "REPEATED_FAILED_CONNECTIONS", 
            "MULTI_PORT_PROBING_PATTERN", "SYN_HEAVY_PATTERN", 
            "UNUSUAL_PORT_ACTIVITY", "HIGH_TRAFFIC_VOLUME"
        ])
        label = "SUSPICIOUS"
    else:
        scenario = random.choice([
            "NORMAL_WEB", "NORMAL_DNS", "NORMAL_SSH", 
            "NORMAL_EMAIL", "NORMAL_DATABASE"
        ])
        label = "NORMAL"

    props = get_scenario_properties(scenario)
    
    packet_count = props.get("packet_count")
    byte_count = packet_count * props.get("byte_mult", random.randint(64, 1500))
    duration = props.get("duration")
    conn_count = props.get("conn_count", random.randint(1, 3))
    failed = props.get("failed")
    syn = props.get("syn")
    rst = props.get("rst")

    return {
        "flow_id": str(uuid.uuid4()),
        "timestamp": timestamp.isoformat(),
        "source_ip": generate_ip(),
        "destination_ip": generate_ip(),
        "source_port": random.randint(1024, 65535),
        "destination_port": props["dest_port"],
        "protocol": props["protocol"],
        "packet_count": packet_count,
        "byte_count": byte_count,
        "duration_seconds": round(duration, 4),
        "connection_count": conn_count,
        "failed_connection_count": failed,
        "syn_count": syn,
        "rst_count": rst,
        "average_packet_size": round(byte_count / max(packet_count, 1), 2),
        "label": label,
        "scenario_type": scenario
    }

def main():
    parser = argparse.ArgumentParser(description="Generate synthetic network traffic dataset.")
    parser.add_argument("--count", type=int, default=5000, help="Number of flow records to generate.")
    parser.add_argument("--output", type=str, default="data/network_traffic.csv", help="Output CSV file path.")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for reproducibility.")
    args = parser.parse_args()

    random.seed(args.seed)
    
    os.makedirs(os.path.dirname(args.output), exist_ok=True)
    
    fields = [
        "flow_id", "timestamp", "source_ip", "destination_ip", "source_port", "destination_port", 
        "protocol", "packet_count", "byte_count", "duration_seconds", "connection_count", 
        "failed_connection_count", "syn_count", "rst_count", "average_packet_size", 
        "label", "scenario_type"
    ]

    print(f"Generating {args.count} records to {args.output}...")
    start_time = datetime.now() - timedelta(days=7)
    
    with open(args.output, mode='w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        
        for i in range(args.count):
            is_suspicious = random.random() < 0.3
            record = generate_record(start_time, is_suspicious)
            writer.writerow(record)
            
            # Advance time slightly
            start_time += timedelta(seconds=random.uniform(0.1, 5.0))
            
            if (i + 1) % 500 == 0:
                print(f"Generated {i + 1}/{args.count} records...")

    print("Generation complete.")

if __name__ == "__main__":
    main()
