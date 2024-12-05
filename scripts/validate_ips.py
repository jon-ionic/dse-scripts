"""
Validates that Appflow build runner IPs match the IPs listed in this article:
https://ionic.zendesk.com/hc/en-us/articles/23506994097175-Appflow-IP-Addresses

This workflow is run daily and will fail if a new IP is found.

Update the article along with the IPs in line 17 if needed.
"""

from typing import Union
import subprocess
import json
import time
import re


KNOWN_IPS = ["34.217.204.219", "44.225.146.175", "44.225.206.46"]
BUILD_TYPES = ["android debug", "ios simulator", "web"]
APP_ID = "7beb099c"
COMMIT_SHA = "0005b6ad0988f30aaa1943f88875c6235d809203"


def trigger_build(type: str) -> int:
    result = subprocess.run(
        f"appflow build {type} --app-id={APP_ID} --commit={COMMIT_SHA} --json --detached", 
        shell=True, 
        capture_output=True
    )

    build_id = json.loads(result.stdout)["buildId"]
    return build_id


def check_if_build_is_complete(build_id: int) -> bool:
    result = subprocess.run(
        f"appflow build get --app-id={APP_ID} --build-id={build_id} --json",
        shell=True,
        capture_output=True
    )

    status = json.loads(result.stdout)["buildStatus"]
    if status in ["FAILED", "SUCCESS"]:
        return True

    return False


def get_build_logs(build_id: int) -> str:
    result = subprocess.run(
        f"appflow build logs --app-id={APP_ID} --build-id={build_id}",
        shell=True,
        capture_output=True
    )

    logs = result.stderr.decode("utf-8")
    return logs


def remove_ansi_escape_codes(lines: list[str]) -> list[str]:
    ansi_escape_pattern = r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])'
    return [re.sub(ansi_escape_pattern, '', line) for line in lines]


def parse_ip_address(logs: str) -> Union[str, None]:
    try:
        cleaned_log_lines = remove_ansi_escape_codes(logs.split("\n"))
        log_line = next(
            line for line in cleaned_log_lines
            if line.endswith(" - IP address") and "echo" not in line
        )
        ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        match = re.search(ip_pattern, log_line)
        return match.group(0) if match else None
    except StopIteration:
        return None


def validate_ips_match(build_id_to_ips: dict) -> bool:
    for id, ip in build_id_to_ips.items():
        if ip not in KNOWN_IPS:
            raise ValueError(f"Build {id} was run from {ip}, which is not a known IP.")

    print(f"All IPs match.")
    return True


if __name__ == "__main__":
    build_ids = {trigger_build(t): False for t in BUILD_TYPES}
    print(build_ids)

    while False in build_ids.values():
        build_ids = {build_id: check_if_build_is_complete(build_id) for build_id in build_ids.keys()}
        print(build_ids)
        time.sleep(10)

    build_id_to_ips = {build_id: parse_ip_address(get_build_logs(build_id)) for build_id in build_ids.keys()}
    validate_ips_match(build_id_to_ips)
