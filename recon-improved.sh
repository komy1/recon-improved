#!/bin/bash

# Check if arguments or a file are provided
if [ -z "$1" ]; then
  echo "Usage: $0 <target-domain-or-ip> [<target2> ...] or $0 -f <targets-file>"
  exit 1
fi

# Set output and tools directories
OUTPUT_DIR="/home/kali/Bash-Course/Project-1/output"
mkdir -p "$OUTPUT_DIR"

# Function to log messages
log_message() {
  echo "[$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$OUTPUT_DIR/logs.txt"
}

# Function to log vulnerabilities
log_vulnerability() {
  echo "[VULNERABLE] [$(date +'%Y-%m-%d %H:%M:%S')] $1" | tee -a "$OUTPUT_DIR/vulnerabilities.txt"
}

is_ip() {
  local ip="$1"
  if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
	#its an ip
	return 0;
  else
	#not an ip
	return 1
  fi
}

is_alive() {
  local target="$1"
  log_message "Checking if $target is alive.."

  # nc - ping - nslookup - whois
  # 10.0.2.4
  if is_ip "$target"; then
	#its an ip
	if ! ping -c 2 -W 2 "$target" > /dev/null 2>&1; then
	  log_message "Ping failed for $target"
	  if ! nc -zz -w 2 "$target" 80 && ! nc -z -w 2 "$target" 443; then
		log_message "nc failed $target not rechable Skipping...."
		return 1
	  fi
	fi
  else
	# dns resolution
	if ! nslookup "$target" >/dev/null 2>&1; then
		log_message "DNS resolution failed for $target Skipping..."
		return 1
	fi
  fi
}

# Function to check for HTTP/HTTPS services
check_web_services() {
  local nmap_file="$1"
  if grep -Eq "80/tcp|443/tcp|8080/tcp|8443/tcp|8000/tcp|8081/tcp|8888/tcp|9000/tcp|3000/tcp" "$nmap_file" || \
     grep -qi "Service: http" "$nmap_file" || \
     grep -qi "Service: https" "$nmap_file" || \
     grep -qi "Service: http-alt" "$nmap_file" || \
     grep -qi "Service: ssl/http" "$nmap_file" || \
     grep -qi "Server: " "$nmap_file" || \
     grep -qi "Content-Type: text/html" "$nmap_file"; then
    return 0  # Web services detected
  else
    return 1  # No web services detected
  fi
}

# Function to check for outdated software versions
check_outdated_versions() {
  local nmap_file="$1"
  local target="$2"

  # Check for outdated Apache versions (under 2)
  if grep -q "Apache/2\.[0-1]\." "$nmap_file" || grep -q "Apache/2\.2\." "$nmap_file"; then
    log_vulnerability "Outdated Apache version (under 2.2) detected on $target. Check $nmap_file for details."
  fi

  # Check for outdated OpenSSH versions (under 7.2)
  if grep -q "OpenSSH [1-6]\." "$nmap_file" || grep -q "OpenSSH 7\.[0-1]" "$nmap_file"; then
    log_vulnerability "Outdated OpenSSH version (under 7.2) detected on $target. Check $nmap_file for details."
  fi

  # Check for outdated vsftpd versions (e.g., 2.3.4 is vulnerable)
  if grep -q "vsftpd 2\.3\." "$nmap_file"; then
    log_vulnerability "Outdated vsftpd version (2.3.4) detected on $target. This version is known to be vulnerable. Check $nmap_file for details."
  fi

  # Check for outdated MySQL versions (e.g., 5.0.51a is vulnerable)
  if grep -q "MySQL 5\.0\." "$nmap_file"; then
    log_vulnerability "Outdated MySQL version (5.0.51a) detected on $target. This version is known to be vulnerable. Check $nmap_file for details."
  fi
}

# Function to parse Nikto output for high/critical vulnerabilities
parse_nikto_output() {
  local nikto_file="$1"
  local target="$2"

  # Check for high/critical vulnerabilities in Nikto output
  if grep -q "High" "$nikto_file"; then
    log_vulnerability "High severity vulnerabilities found on $target. Check $nikto_file for details."
  fi
  if grep -q "Critical" "$nikto_file"; then
    log_vulnerability "Critical severity vulnerabilities found on $target. Check $nikto_file for details."
  fi

  # Specific checks for common vulnerabilities
  if grep -q "X-Frame-Options header is not present" "$nikto_file"; then
    log_vulnerability "Missing X-Frame-Options header on $target. This may allow clickjacking attacks. Check $nikto_file for details."
  fi
  if grep -q "X-Content-Type-Options header is not set" "$nikto_file"; then
    log_vulnerability "Missing X-Content-Type-Options header on $target. This may allow MIME type sniffing. Check $nikto_file for details."
  fi
  if grep -q "HTTP TRACE method is active" "$nikto_file"; then
    log_vulnerability "HTTP TRACE method enabled on $target. This may allow Cross-Site Tracing (XST) attacks. Check $nikto_file for details."
  fi
  if grep -q "phpinfo.php" "$nikto_file"; then
    log_vulnerability "phpinfo.php file exposed on $target. This may leak sensitive information. Check $nikto_file for details."
  fi
}

# Function to perform recon on a single target
perform_recon() {
  TARGET=$1
  TARGET_OUTPUT_DIR="$OUTPUT_DIR/$TARGET"
  mkdir -p "$TARGET_OUTPUT_DIR"

  log_message "Starting recon on target: $TARGET"

  if ! is_alive "$TARGET"; then
	log_message "$TARGET dead skipping..."
	return
  fi

  log_message "Running whois..."
  whois "$TARGET" > "$TARGET_OUTPUT_DIR/whois.txt" 2>&1

  echo "----------------------------------------"

  # Perform nmap scan
  log_message "Running nmap on $TARGET"
  nmap -sV -sC -O -T4 -p- "$TARGET" > "$TARGET_OUTPUT_DIR/nmap.txt" 2>&1

  echo "----------------------------------------"

  # Check for outdated software versions
  check_outdated_versions "$TARGET_OUTPUT_DIR/nmap.txt" "$TARGET"

  echo "----------------------------------------"

  # Check for web services
  if check_web_services "$TARGET_OUTPUT_DIR/nmap.txt"; then
    # Perform vulnerability scanning with nikto
    log_message "Performing vulnerability scanning with nikto..."
    nikto -h "$TARGET" > "$TARGET_OUTPUT_DIR/nikto.txt" 2>&1

    # Parse Nikto output for high/critical vulnerabilities
    parse_nikto_output "$TARGET_OUTPUT_DIR/nikto.txt" "$TARGET"
  else
    log_message "No HTTP/HTTPS services detected. Skipping web-specific scans."
  fi

  echo "----------------------------------------"

  log_message "Recon completed for target: $TARGET. Results saved in $TARGET_OUTPUT_DIR/"
}
export -f perform_recon log_message log_vulnerability is_ip is_alive check_web_services check_outdated_versions parse_nikto_output
export OUTPUT_DIR

# Main script logic
if [ "$1" = "-f" ]; then
  # Read targets from file
  if [ ! -f "$2" ]; then
    echo "File $2 not found."
    exit 1
  fi
  parallel --jobs 5 --load 80% perform_recon :::: "$2"
else
  # Read targets from command line arguments
  TARGETS=("$@")
  for TARGET in "${TARGETS[@]}"; do
    perform_recon "$TARGET"
  done
fi

log_message "All targets processed. Recon completed."
