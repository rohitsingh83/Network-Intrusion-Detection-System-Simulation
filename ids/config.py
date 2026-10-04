"""Project defaults. Tune these values against an approved environment before reuse."""

DEFAULT_RULES = [
    {
        "rule_id": "IDS-001",
        "rule_name": "High Connection Rate",
        "description": "The observed connection rate is above the configured baseline.",
        "severity": "HIGH",
        "threshold": 12.0,
        "enabled": True,
        "config": {},
    },
    {
        "rule_id": "IDS-002",
        "rule_name": "Repeated Failed Connections",
        "description": "Repeated connection failures and a high failure ratio were observed.",
        "severity": "HIGH",
        "threshold": 5.0,
        "enabled": True,
        "config": {"minimum_failure_ratio": 0.45},
    },
    {
        "rule_id": "IDS-003",
        "rule_name": "Destination Port Diversity",
        "description": "A source contacted an unusually broad set of destination ports.",
        "severity": "HIGH",
        "threshold": 12.0,
        "enabled": True,
        "config": {},
    },
    {
        "rule_id": "IDS-004",
        "rule_name": "SYN-Heavy Flow",
        "description": "SYN activity represents an unusually large share of observed packets.",
        "severity": "MEDIUM",
        "threshold": 15.0,
        "enabled": True,
        "config": {"minimum_syn_ratio": 0.70},
    },
    {
        "rule_id": "IDS-005",
        "rule_name": "Unexpected Service-Port Protocol",
        "description": "A management or database service port used an unexpected transport protocol.",
        "severity": "MEDIUM",
        "threshold": 1.0,
        "enabled": True,
        "config": {"ports": [22, 3389, 3306, 5432, 445]},
    },
    {
        "rule_id": "IDS-006",
        "rule_name": "High Traffic Volume",
        "description": "The flow volume or byte rate exceeded the configured limit.",
        "severity": "HIGH",
        "threshold": 2_000_000.0,
        "enabled": True,
        "config": {"bytes_per_second_threshold": 5_000_000.0},
    },
]

SEVERITY_RISK = {
    "INFO": 10,
    "LOW": 30,
    "MEDIUM": 55,
    "HIGH": 75,
    "CRITICAL": 95,
}

SEVERITY_ORDER = {name: index for index, name in enumerate(
    ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
)}

DEFAULT_WEIGHTS_WITH_ML = {"rules": 0.40, "anomaly": 0.30, "ml": 0.30}
DEFAULT_WEIGHTS_WITHOUT_ML = {"rules": 0.60, "anomaly": 0.40}

ALERT_THRESHOLD = 41
RISK_CLASSIFICATIONS = [
    (20, "NORMAL"),
    (40, "LOW RISK"),
    (60, "SUSPICIOUS"),
    (80, "HIGH RISK"),
    (100, "CRITICAL INVESTIGATION"),
]
