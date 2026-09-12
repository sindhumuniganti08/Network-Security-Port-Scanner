"""
Project 2: Network Security Port Scanner - Interactive CLI Utility
"""

import sys
from backend.scanner import NetworkPortScanner, TOP_20_PORTS, TOP_100_PORTS

def print_banner():
    print("=" * 65)
    print(" 📡 NETWORK SECURITY PORT SCANNER (CLI) ")
    print("=" * 65)

def main():
    print_banner()
    target = input("\nEnter Target Hostname or IP [Default: 127.0.0.1]: ").strip() or "127.0.0.1"
    
    print("\nPort Range Selection:")
    print("1. Top 20 Common Ports (Fast)")
    print("2. Top 100 Common Ports")
    print("3. Custom Port List / Range (e.g., 80,443,8000-8080)")
    
    choice = input("Select option (1-3) [Default: 1]: ").strip() or "1"
    
    ports = TOP_20_PORTS
    if choice == "2":
        ports = TOP_100_PORTS
    elif choice == "3":
        cports = input("Enter custom ports: ").strip()
        try:
            ports = NetworkPortScanner.parse_port_range(cports)
        except Exception as e:
            print(f"❌ Invalid port specification: {e}")
            sys.exit(1)

    print(f"\n🔍 Resolving target '{target}' and scanning {len(ports)} ports...")
    
    scanner = NetworkPortScanner(target, timeout=1.0, max_threads=50)
    
    def progress_bar(completed, total):
        pct = int((completed / total) * 50)
        bar = "█" * pct + "-" * (50 - pct)
        sys.stdout.write(f"\rScanning: [{bar}] {completed}/{total} ports")
        sys.stdout.flush()

    res = scanner.scan_ports(ports, progress_callback=progress_bar)
    print("\n")
    
    if res.get("status") == "error":
        print(f"❌ Scan Failed: {res.get('message')}")
        sys.exit(1)

    print("=" * 65)
    print(f"Target IP:       {res['target_ip']} ({res['target_hostname']})")
    print(f"Total Scanned:   {res['total_scanned']}")
    print(f"Open Ports:      {res['open_count']}")
    print(f"Scan Duration:   {res['scan_duration_sec']}s")
    print("=" * 65)
    
    print(f"{'PORT':<8} {'STATE':<10} {'SERVICE':<15} {'LATENCY':<10} {'BANNER':<20}")
    print("-" * 65)
    for item in res['results']:
        if item['state'] == 'open':
            print(f"{item['port']:<8} \033[92m{item['state'].upper():<10}\033[0m {item['service']:<15} {str(item['latency_ms'])+'ms':<10} {item['banner']:<20}")
        else:
            print(f"{item['port']:<8} \033[91m{item['state'].upper():<10}\033[0m {item['service']:<15} {str(item['latency_ms'])+'ms':<10} {item['banner']:<20}")

if __name__ == "__main__":
    main()
