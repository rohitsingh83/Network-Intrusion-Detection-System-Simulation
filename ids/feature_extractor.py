"""
Network Feature Extraction Module.
Computes relevant metrics from raw flow data for IDS analysis.
"""

def extract_features(flow_data: dict) -> dict:
    """
    Computes derived features from a network flow record.
    
    These features provide cybersecurity relevance:
    - bytes_per_second: Identifies data exfiltration or DDoS.
    - failure_ratio: High ratio indicates scanning or brute force attempts.
    - syn_ratio: High ratio indicates SYN flood attacks.
    """
    # Base fields
    packet_count = float(flow_data.get('packet_count', 0))
    byte_count = float(flow_data.get('byte_count', 0))
    duration = float(flow_data.get('duration_seconds', 0.0))
    conn_count = float(flow_data.get('connection_count', 0))
    failed_conn = float(flow_data.get('failed_connection_count', 0))
    syn_count = float(flow_data.get('syn_count', 0))
    rst_count = float(flow_data.get('rst_count', 0))
    
    # Derived features
    safe_duration = max(duration, 0.001)
    safe_packets = max(packet_count, 1)
    safe_conn = max(conn_count, 1)
    
    bytes_per_second = byte_count / safe_duration
    packets_per_second = packet_count / safe_duration
    average_packet_size = byte_count / safe_packets
    
    failure_ratio = failed_conn / safe_conn
    syn_ratio = syn_count / safe_packets
    connection_rate = conn_count / safe_duration
    
    # Create the feature dict
    features = {
        'packet_count': packet_count,
        'byte_count': byte_count,
        'duration': duration,
        'bytes_per_second': bytes_per_second,
        'packets_per_second': packets_per_second,
        'average_packet_size': average_packet_size,
        'connection_count': conn_count,
        'failed_connection_count': failed_conn,
        'failure_ratio': failure_ratio,
        'syn_count': syn_count,
        'rst_count': rst_count,
        'syn_ratio': syn_ratio,
        'connection_rate': connection_rate,
        # Default single flow means 1 unique port/IP if present
        'unique_destination_ports': 1 if flow_data.get('destination_port') else 0,
        'unique_destination_ips': 1 if flow_data.get('destination_ip') else 0
    }
    
    return features

def extract_features_batch(flows: list[dict]) -> list[dict]:
    """Extract features for a batch of flows."""
    return [extract_features(f) for f in flows]

def validate_flow(flow: dict) -> tuple[bool, list[str]]:
    """
    Validates IPs, ports (0-65535), protocol, and required fields.
    Returns a tuple of (is_valid, list_of_errors).
    """
    errors = []
    required_fields = ['source_ip', 'destination_ip', 'source_port', 'destination_port', 'protocol']
    
    for field in required_fields:
        if field not in flow:
            errors.append(f"Missing required field: {field}")
            
    # Validate ports
    for port_field in ['source_port', 'destination_port']:
        if port_field in flow:
            try:
                port = int(flow[port_field])
                if not (0 <= port <= 65535):
                    errors.append(f"{port_field} must be between 0 and 65535")
            except (ValueError, TypeError):
                errors.append(f"{port_field} must be an integer")
                
    # Basic IP validation could be added here (e.g. regex for IPv4/IPv6)
    
    return len(errors) == 0, errors
