import re
import csv
from collections import defaultdict, Counter

# Configuration for suspicious activity threshold
FAILED_LOGIN_THRESHOLD = 10


def parse_log_file(file_path):
    with open(file_path, 'r') as log_file:
        logs = log_file.readlines()
    return logs


def count_requests_per_ip(logs):
    ip_counter = Counter()
    for log in logs:
        match = re.match(r'(\d+\.\d+\.\d+\.\d+)', log)
        if match:
            ip = match.group(1)
            ip_counter[ip] += 1
    return ip_counter


def most_frequent_endpoint(logs):
    endpoint_counter = Counter()
    for log in logs:
        match = re.search(r'\"[A-Z]+\s([^\s]+)\sHTTP', log)
        if match:
            endpoint = match.group(1)
            endpoint_counter[endpoint] += 1
    most_common = endpoint_counter.most_common(1)
    return most_common[0] if most_common else ("N/A", 0)


def detect_suspicious_activity(logs):
    failed_login_counter = defaultdict(int)
    for log in logs:
        if "401" in log or "Invalid credentials" in log:
            match = re.match(r'(\d+\.\d+\.\d+\.\d+)', log)
            if match:
                ip = match.group(1)
                failed_login_counter[ip] += 1
    flagged_ips = {ip: count for ip, count in failed_login_counter.items() if count > FAILED_LOGIN_THRESHOLD}
    return flagged_ips


def save_to_csv(ip_counts, most_accessed, suspicious_ips, output_file):
    with open(output_file, 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)

        # Write Requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])

        # Write Most Accessed Endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([most_accessed[0], most_accessed[1]])

        # Write Suspicious Activity
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])


def main():
    log_file_path = 'sample.log'
    logs = parse_log_file(log_file_path)

    # Analyze logs
    ip_counts = count_requests_per_ip(logs)
    most_accessed = most_frequent_endpoint(logs)
    suspicious_ips = detect_suspicious_activity(logs)

    # Display results
    print("Requests per IP:")
    for ip, count in ip_counts.items():
        print(f"{ip:15} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed[0]} (Accessed {most_accessed[1]} times)")

    print("\nSuspicious Activity Detected:")
    for ip, count in suspicious_ips.items():
        print(f"{ip:15} {count}")

    # Save to CSV
    save_to_csv(ip_counts, most_accessed, suspicious_ips, "log_analysis_results.csv")
    print("\nResults saved to log_analysis_results.csv")


if __name__ == "__main__":
    main()
