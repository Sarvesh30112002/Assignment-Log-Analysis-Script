import re
from collections import defaultdict
import csv

# Function to process the log file
def analyze_logs(file_path, threshold=10):
    # Data structures for analysis
    ip_counts = defaultdict(int)
    endpoint_counts = defaultdict(int)
    failed_logins = defaultdict(int)

    # Read and process the log file
    with open(file_path, 'r') as log_file:
        for line in log_file:
            # Extract IP address
            ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+)', line)
            if ip_match:
                ip = ip_match.group(1)
                ip_counts[ip] += 1

            # Extract endpoint
            endpoint_match = re.search(r'\"[A-Z]+\s(\/[^\s]*)\sHTTP\/', line)
            if endpoint_match:
                endpoint = endpoint_match.group(1)
                endpoint_counts[endpoint] += 1

            # Detect failed login attempts (status 401 or "Invalid credentials")
            if '401' in line or 'Invalid credentials' in line:
                if ip_match:
                    failed_logins[ip] += 1

    # Identify the most accessed endpoint
    most_accessed_endpoint = max(endpoint_counts, key=endpoint_counts.get, default=None)
    most_accessed_count = endpoint_counts[most_accessed_endpoint] if most_accessed_endpoint else 0

    # Detect suspicious IPs
    suspicious_ips = {ip: count for ip, count in failed_logins.items() if count > threshold}

    # Print results
    print("\nRequests per IP:")
    print("IP Address           Request Count")
    for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"{ip:<20} {count}")

    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint} (Accessed {most_accessed_count} times)")

    print("\nSuspicious Activity Detected:")
    print("IP Address           Failed Login Attempts")
    for ip, count in suspicious_ips.items():
        print(f"{ip:<20} {count}")

    # Save results to CSV
    with open('log_analysis_results.csv', 'w', newline='') as csv_file:
        writer = csv.writer(csv_file)

        # Write requests per IP
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True):
            writer.writerow([ip, count])

        # Write most accessed endpoint
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow([most_accessed_endpoint, most_accessed_count])

        # Write suspicious activities
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_ips.items():
            writer.writerow([ip, count])

# Run the script with the sample log file
if __name__ == "__main__":
    log_file_path = "sample.log"  # Replace with your actual log file path
    analyze_logs(log_file_path)
