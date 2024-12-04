import csv
from collections import Counter

LOG_FILE = r"C:\Users\Pandi\Downloads\internsample.log"

def parse_log_file(file_path):
    try:
        with open(file_path, "r") as file:
            return file.readlines()
    except FileNotFoundError:
        print(f"Error: File '{file_path}' not found.")
        exit()

def count_requests_by_ip(log_data):
    ip_counter = Counter()
    for line in log_data:
        ip = line.split()[0]
        ip_counter[ip] += 1
    return ip_counter

def find_most_accessed_endpoint(log_data):
    endpoint_counter = Counter()
    for line in log_data:
        if '"' in line:
            request_part = line.split('"')[1]
            endpoint = request_part.split()[1]
            endpoint_counter[endpoint] += 1
    most_common = endpoint_counter.most_common(1)
    return most_common[0] if most_common else ("N/A", 0)

def detect_suspicious_activity(log_data, threshold=10):
    failed_login_ips = Counter()
    for line in log_data:
        if "401" in line or "Invalid credentials" in line:
            ip = line.split()[0]
            failed_login_ips[ip] += 1
    return {ip: count for ip, count in failed_login_ips.items() if count > threshold}

def save_to_csv(ip_counts, most_accessed_endpoint, suspicious_activity, output_file="log_analysis_results.csv"):
    with open(output_file, "w", newline="") as csv_file:
        writer = csv.writer(csv_file)
        writer.writerow(["IP Address", "Request Count"])
        for ip, count in ip_counts.items():
            writer.writerow([ip, count])
        writer.writerow([])
        writer.writerow(["Most Accessed Endpoint", "Access Count"])
        writer.writerow(most_accessed_endpoint)
        writer.writerow([])
        writer.writerow(["IP Address", "Failed Login Count"])
        for ip, count in suspicious_activity.items():
            writer.writerow([ip, count])

def main():
    log_data = parse_log_file(LOG_FILE)
    ip_counts = count_requests_by_ip(log_data)
    most_accessed_endpoint = find_most_accessed_endpoint(log_data)
    suspicious_activity = detect_suspicious_activity(log_data)
    print("\nRequests Per IP Address:")
    for ip, count in ip_counts.most_common():
        print(f"{ip: <20} {count}")
    print("\nMost Frequently Accessed Endpoint:")
    print(f"{most_accessed_endpoint[0]} (Accessed {most_accessed_endpoint[1]} times)")
    print("\nSuspicious Activity Detected:")
    if suspicious_activity:
        for ip, count in suspicious_activity.items():
            print(f"{ip: <20} {count}")
    else:
        print("No suspicious activity detected.")
    save_to_csv(ip_counts, most_accessed_endpoint, suspicious_activity)
    print("\nResults saved to 'log_analysis_results.csv'.")

if __name__ == "__main__":
    main()
