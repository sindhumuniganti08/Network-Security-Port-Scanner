"""
Project 2: Network Security Port Scanner - Core Engine
Features:
- Hostname resolution & target validation
- Multi-threaded concurrent TCP connect scanning
- Banner grabbing & service fingerprinting
- Port range presets (Top 20, Top 100, Custom)
- Comprehensive error handling & socket timeout controls
"""

import socket
import concurrent.futures
import time
import json
import csv
import io
from typing import Dict, Any, List, Tuple

PORT_SERVICES = {
    21: "FTP", 22: "SSH", 23: "TELNET", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBIND", 135: "MSRPC",
    139: "NETBIOS-SSN", 143: "IMAP", 443: "HTTPS", 445: "MICROSOFT-DS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "ORACLE",
    3306: "MYSQL", 3389: "RDP", 5432: "POSTGRESQL", 5900: "VNC",
    6379: "REDIS", 8000: "HTTP-ALT", 8080: "HTTP-PROXY", 8443: "HTTPS-ALT",
    27017: "MONGODB"
}

TOP_20_PORTS = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1723, 3306, 3389, 5900, 8080]
TOP_100_PORTS = sorted(list(set(TOP_20_PORTS + [
    7, 9, 13, 17, 19, 26, 37, 79, 81, 88, 100, 102, 106, 113, 119, 144, 179, 199, 389, 427, 444, 465, 513, 514, 515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 1025, 1026, 1027, 1028, 1029, 1110, 1433, 1720, 2000, 2001, 2049, 2121, 2717, 3000, 3128, 3306, 3986, 4899, 5000, 5009, 5051, 5060, 5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070, 8000, 8008, 8081, 8443, 8888, 9100, 9999, 10000
])))

class NetworkPortScanner:
    def __init__(self, target: str, timeout: float = 1.0, max_threads: int = 50):
        self.target_input = target
        self.timeout = timeout
        self.max_threads = max_threads
        self.target_ip = ""
        self.target_hostname = ""

    def resolve_target(self) -> Tuple[bool, str]:
        try:
            self.target_ip = socket.gethostbyname(self.target_input)
            try:
                self.target_hostname = socket.gethostbyaddr(self.target_ip)[0]
            except socket.herror:
                self.target_hostname = self.target_input
            return True, f"Resolved {self.target_input} -> {self.target_ip}"
        except socket.gaierror:
            return False, f"Error: Unable to resolve hostname/IP '{self.target_input}'"
        except Exception as e:
            return False, f"Error resolving target: {str(e)}"

    def grab_banner(self, ip: str, port: int) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(1.5)
                s.connect((ip, port))
                if port in [80, 8080, 8000]:
                    s.sendall(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
                else:
                    s.sendall(b"\r\n")
                data = s.recv(1024)
                banner = data.decode('utf-8', errors='ignore').strip()
                first_line = banner.splitlines()[0] if banner else ""
                return first_line[:80]
        except Exception:
            return ""

    def scan_single_port(self, port: int) -> Dict[str, Any]:
        result = {
            "port": port,
            "state": "closed",
            "service": PORT_SERVICES.get(port, "unknown"),
            "banner": "",
            "latency_ms": 0
        }
        start_time = time.time()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                res = s.connect_ex((self.target_ip, port))
                latency = round((time.time() - start_time) * 1000, 2)
                result["latency_ms"] = latency
                
                if res == 0:
                    result["state"] = "open"
                    result["banner"] = self.grab_banner(self.target_ip, port)
                elif res in [11, 10060]:
                    result["state"] = "filtered"
                else:
                    result["state"] = "closed"
        except Exception as e:
            result["state"] = "error"
            result["banner"] = str(e)
            
        return result

    def scan_ports(self, port_list: List[int], progress_callback=None) -> Dict[str, Any]:
        resolved, msg = self.resolve_target()
        if not resolved:
            return {"status": "error", "message": msg, "results": []}

        start_time = time.time()
        results = []
        open_ports_count = 0

        with concurrent.futures.ThreadPoolExecutor(max_workers=min(self.max_threads, len(port_list))) as executor:
            future_to_port = {executor.submit(self.scan_single_port, p): p for p in port_list}
            completed = 0
            total = len(port_list)
            for future in concurrent.futures.as_completed(future_to_port):
                res = future.result()
                results.append(res)
                if res["state"] == "open":
                    open_ports_count += 1
                completed += 1
                if progress_callback:
                    progress_callback(completed, total)

        results.sort(key=lambda x: x["port"])
        duration = round(time.time() - start_time, 2)

        return {
            "status": "success",
            "target": self.target_input,
            "target_ip": self.target_ip,
            "target_hostname": self.target_hostname,
            "total_scanned": total,
            "open_count": open_ports_count,
            "scan_duration_sec": duration,
            "results": results
        }

    @staticmethod
    def parse_port_range(range_str: str) -> List[int]:
        ports = set()
        for part in range_str.split(','):
            part = part.strip()
            if not part:
                continue
            if '-' in part:
                sub = part.split('-')
                start, end = int(sub[0]), int(sub[1])
                ports.update(range(start, min(65535, end + 1)))
            else:
                ports.add(int(part))
        return sorted(list(ports))

    @staticmethod
    def export_json(scan_data: Dict[str, Any]) -> str:
        return json.dumps(scan_data, indent=2)

    @staticmethod
    def export_csv(scan_data: Dict[str, Any]) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Port", "State", "Service", "Latency (ms)", "Banner"])
        for item in scan_data.get("results", []):
            writer.writerow([item["port"], item["state"], item["service"], item["latency_ms"], item["banner"]])
        return output.getvalue()
