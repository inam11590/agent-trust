"""Small controlled HTTP benchmark for a local or staging AgentTrust health endpoint."""

import argparse
from concurrent.futures import ThreadPoolExecutor
import statistics
import time
import urllib.request

def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", default="http://127.0.0.1:8000/health/live")
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=10)
    args = parser.parse_args()
    if args.requests < 1 or args.requests > 2000 or args.concurrency < 1 or args.concurrency > 50:
        raise SystemExit("Keep requests in 1..2000 and concurrency in 1..50")
    def one(_):
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(args.url, timeout=5) as response: ok = response.status == 200
        except Exception: ok = False
        return ok, (time.perf_counter() - started) * 1000
    started = time.perf_counter()
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool: results = list(pool.map(one, range(args.requests)))
    elapsed = time.perf_counter() - started; latencies = sorted(value for _, value in results); successes = sum(ok for ok, _ in results)
    percentile = lambda p: latencies[min(len(latencies)-1, int(len(latencies)*p))]
    print(f"requests={args.requests} successes={successes} errors={args.requests-successes}")
    print(f"requests_per_second={args.requests/elapsed:.2f}")
    print(f"latency_ms_mean={statistics.mean(latencies):.2f} p50={percentile(.50):.2f} p95={percentile(.95):.2f} p99={percentile(.99):.2f}")

if __name__ == "__main__": main()
