"""Local API replay client for generated flow *data* (never network packets)."""

from __future__ import annotations

import argparse
import json
import os
import random
import time
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from uuid import uuid4

from simulator.scenarios import choose_scenario, make_synthetic_flow


def validate_local_api_url(api_url: str) -> str:
    parsed = urlparse(api_url)
    if parsed.scheme not in {"http", "https"} or parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
        raise ValueError("For safety, the simulator only POSTs to localhost/loopback API URLs.")
    return api_url.rstrip("/")


def post_flow(api_url: str, flow: dict, api_key: str | None = None) -> dict:
    url = validate_local_api_url(api_url) + "/api/flows"
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    request = Request(url, data=json.dumps(flow).encode("utf-8"), headers=headers, method="POST")
    try:
        with urlopen(request, timeout=5) as response:
            return json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"IDS API returned HTTP {exc.code}: {body}") from exc
    except URLError as exc:
        raise RuntimeError(f"Cannot reach local IDS API at {url}: {exc.reason}") from exc


def run_simulator(
    mode: str = "mixed",
    speed: str = "slow",
    count: int | None = None,
    api_url: str = "http://127.0.0.1:8000",
    api_key: str | None = None,
    seed: int | None = None,
) -> None:
    api_url = validate_local_api_url(api_url)
    if mode not in {"normal", "mixed"}:
        raise ValueError("mode must be normal or mixed")
    if speed not in {"slow", "fast"}:
        raise ValueError("speed must be slow or fast")
    interval = 1.5 if speed == "slow" else 0.2
    rng = random.Random(seed)
    index = 0
    print("SentinelFlow data simulator started. It creates JSON flow records only; no packets are sent.")
    try:
        while count is None or index < count:
            scenario = choose_scenario(mode, index, rng)
            flow = make_synthetic_flow(
                scenario,
                flow_id=f"SIM-{uuid4().hex[:12].upper()}",
                rng=rng,
            )
            result = post_flow(api_url, flow, api_key=api_key)
            evaluation = result.get("evaluation", {})
            alert = result.get("alert") or {}
            print(
                f"{flow['flow_id']}  {scenario:<32} risk={evaluation.get('risk_score', '?'):>3}  "
                f"alert={alert.get('alert_id', '—')}"
            )
            index += 1
            if count is None or index < count:
                time.sleep(interval)
    except KeyboardInterrupt:
        print("\nSimulator stopped. No packets were sent.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Replay synthetic flow JSON to the local IDS API.")
    parser.add_argument("--mode", choices=["normal", "mixed"], default="mixed")
    parser.add_argument("--speed", choices=["slow", "fast"], default="slow")
    parser.add_argument("--count", type=int, default=None, help="stop after N records; omit for continuous replay")
    parser.add_argument("--api-url", default="http://127.0.0.1:8000")
    parser.add_argument("--api-key", default=os.getenv("IDS_API_KEY"), help="optional key for protected local API")
    parser.add_argument("--seed", type=int, default=None)
    args = parser.parse_args()
    run_simulator(args.mode, args.speed, args.count, args.api_url, args.api_key, args.seed)


if __name__ == "__main__":
    main()
