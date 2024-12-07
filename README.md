# Assignment-Log-Analysis-Script

Log Analysis Script
A Python script designed to process server log files, extract key information, and provide insightful analytics. This project demonstrates skills in file handling, string manipulation, and data analysis, which are crucial for cybersecurity-related programming tasks.

Features
1. Count Requests per IP Address
Parses the log file to extract all IP addresses.
Counts the number of requests made by each IP address.
Displays the results in descending order of request counts.
Example Output:
bash
Copy code
IP Address           Request Count
192.168.1.1          234
203.0.113.5          187
10.0.0.2             92
2. Identify the Most Frequently Accessed Endpoint
Extracts and analyzes endpoints from the log file.
Identifies the endpoint with the highest number of accesses.
Example Output:
bash
Copy code
Most Frequently Accessed Endpoint:
/home (Accessed 403 times)
3. Detect Suspicious Activity
Identifies potential brute force login attempts.
Flags IP addresses with failed login attempts exceeding a configurable threshold (default: 10 attempts).
Example Output:
bash
Copy code
Suspicious Activity Detected:
IP Address           Failed Login Attempts
192.168.1.100        56
203.0.113.34         12
4. Save Results to CSV
Outputs analysis results to a CSV file (log_analysis_results.csv) with the following sections:
Requests per IP: Columns: IP Address, Request Count
Most Accessed Endpoint: Columns: Endpoint, Access Count
Suspicious Activity: Columns: IP Address, Failed Login Count
