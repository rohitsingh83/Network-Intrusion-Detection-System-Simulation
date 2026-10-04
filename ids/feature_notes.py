"""Short definitions reused by API documentation and dashboard tooltips."""

FEATURE_DESCRIPTIONS = {
    "packet_count": "Packets represented by this flow record; not packet payloads.",
    "byte_count": "Total bytes represented by the flow.",
    "duration_seconds": "Observed flow duration in seconds.",
    "bytes_per_second": "Byte count divided by duration; highlights volume bursts.",
    "packets_per_second": "Packet count divided by duration; highlights packet-rate changes.",
    "average_packet_size": "Mean bytes per packet; useful for distinguishing small control traffic from bulk transfer.",
    "connection_count": "Connections summarized by the record or time-window context.",
    "failed_connection_count": "Connection attempts reported as failed by the synthetic source data.",
    "failure_ratio": "Failed connections divided by connection count; can support authentication or reachability triage.",
    "syn_count": "SYN-flag count from metadata; no packets are generated or captured by this project.",
    "rst_count": "Reset-flag count from metadata.",
    "syn_ratio": "SYN count divided by packet count; a statistical indicator, not proof of a scan or flood.",
    "unique_destination_ports": "Distinct destination ports attributed to a source within the supplied flow/window context.",
    "unique_destination_ips": "Distinct destinations attributed to a source within the supplied flow/window context.",
    "connection_rate": "Connection count divided by duration; used to identify unusually dense activity.",
}
