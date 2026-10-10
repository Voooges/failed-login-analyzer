import argparse
import re
from collections import Counter

parser = argparse.ArgumentParser(
    description="Count SSH failed-password events by IPv4 address."
)
parser.add_argument(
    "--log",
    required=True,
    help="Path to the authentication log"
)
parser.add_argument(
    "--threshold",
    type=int,
    default=5,
    help="Failures needed to flag an IP for review (default: 5)"
)
args = parser.parse_args()

if args.threshold < 1:
    parser.error("Threshold must be at least 1.")

failed_attempts = Counter()

pattern = re.compile(
    r"Failed password for .+? from "
    r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+ ssh2"
)

try:
    with open(args.log, encoding="utf-8") as log:
        for line in log:
            match = pattern.search(line)

            if match:
                ip_address = match.group("ip")
                failed_attempts[ip_address] += 1

except (OSError, UnicodeError) as error:
    print(f"Could not read log file: {error}")
    raise SystemExit(1)

print(f"Analyzing: {args.log}")
print(f"Total failed logins: {sum(failed_attempts.values())}")
print(f"Review threshold: {args.threshold} failures\n")

for ip_address, count in failed_attempts.most_common():
    status = (
        "REVIEW" if count >= args.threshold else "Below threshold"
    )
    print(f"{ip_address}: {count} failed attempts — {status}")

if not failed_attempts:
    print("No matching failed login events found.")
