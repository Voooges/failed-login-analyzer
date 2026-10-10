# Python Failed Login Analyzer

A Python learning project that reads a log file, counts matching SSH
failed-password events by IPv4 address, and flags addresses that reach
a configurable review threshold.

Built and tested in a Kali Linux virtual machine using synthetic logs.

## Features

- Select a log file using command-line arguments
- Extract source addresses using a regular expression
- Count failures using collections.Counter
- Display addresses in descending order of failure count
- Configure the review threshold
- Reject thresholds below 1
- Handle file-reading errors

## Requirements

Python 3. No external Python packages are required.

## Usage

Analyze the mixed sample with a threshold of five:

```bash
python3 analyzer.py --log sample-auth.log --threshold 5
```

Analyze the success-only sample using the default threshold:

```bash
python3 analyzer.py --log tests/success-only/sample-auth.log
```

View help:

```bash
python3 analyzer.py --help
```

## Sample Output

```text
Analyzing: sample-auth.log
Total failed logins: 7
Review threshold: 5 failures

192.0.2.10: 5 failed attempts — REVIEW
192.0.2.20: 1 failed attempts — Below threshold
192.0.2.30: 1 failed attempts — Below threshold
```

REVIEW means the address reached the selected failure threshold.
It does not establish that an attack occurred.

## Verified Tests

| Test | Observed Result |
|---|---|
| Mixed log, threshold 5 | Seven failures; one address flagged |
| Success-only log | Zero matching failures |
| Mixed log, threshold 1 | All three addresses flagged |
| Threshold 0 | Input rejected with a clear message |
| Missing file | File-reading error reported |

Saved output for each test is in the results folder.

## What I Learned

- Processing a text file one line at a time
- Extracting fields with regular expressions
- Counting events by source address
- Adding command-line options with argparse
- Validating input and handling errors
- Testing normal and failure cases
- Saving terminal output with tee

## Limitations

- Recognizes the sample's SSH failed-password message format,
  not every authentication log format.
- Matches IPv4-shaped text but does not validate address octets.
- Does not support IPv6 addresses.
- Counts matching lines across the entire file without time windows.
- Duplicate log entries are counted separately.
- Does not correlate successful logins with preceding failures.
- Does not monitor live logs, block addresses, or prove malicious activity.
- Tested with synthetic logs, not production authentication data.
- Permission and encoding errors are handled in code but have not
  been deliberately tested.

## Learning Context

I built this project with guided assistance and tested its behavior
using fictional authentication events. It is an introductory log
analysis tool, not a production intrusion detection system.
