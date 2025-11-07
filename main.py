import customtkinter
import ipaddress
import subprocess
import socket
import csv
import threading
import configparser
import sys
from queue import Queue
from getmac import get_mac_address
from datetime import datetime
import urllib.request
import urllib.error
import json

# --- Core Scanning Logic ---

def find_vendor_online(mac_address, api_key):
    """Finds the vendor from macaddress.io API using the provided API key."""
    if not mac_address or mac_address == "N/A":
        return "N/A"
    if not api_key or api_key == "YOUR_API_KEY_HERE":
        return "(No API Key)"
    try:
        url = f"https://api.macaddress.io/v1?apiKey={api_key}&output=json&search={urllib.parse.quote(mac_address)}"
        
        request = urllib.request.Request(url, headers={'User-Agent': 'Python-Network-Scanner'})

        with urllib.request.urlopen(request, timeout=3) as response:
            if response.status == 200:
                data = json.loads(response.read().decode('utf-8'))
                return data.get('vendorDetails', {}).get('companyName', "N/A")
            else:
                return f"(API Error {response.status})"

    except urllib.error.HTTPError as e:
        if e.code == 401:
            return "(Invalid API Key)"
        return f"(HTTP Error {e.code})"
    except (urllib.error.URLError, socket.timeout):
        return "(Network Error)"
    except Exception:
        return "(Error)"

def ping_host(ip_queue, results_queue):
    """Pings IPs from the queue and puts active ones in the results_queue."""
    while not ip_queue.empty():
        ip = ip_queue.get()
        try:
            param = "-n" if sys.platform == "win32" else "-c"
            command = ["ping", param, "1", "-w", "1", str(ip)]
            
            startupinfo = None
            if sys.platform == "win32":
                startupinfo = subprocess.STARTUPINFO()
                startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
                startupinfo.wShowWindow = subprocess.SW_HIDE

            output = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True, startupinfo=startupinfo)
            
            if "unreachable" not in output.lower() and "ttl" in output.lower():
                results_queue.put(str(ip))
        except (subprocess.CalledProcessError, FileNotFoundError):
            pass
        finally:
            ip_queue.task_done()

def get_details(ip, api_key):
    """Gets MAC, hostname, and vendor for a given IP."""
    mac_address = "N/A"
    hostname = "N/A"
    vendor = "N/A"
    try:
        mac = get_mac_address(ip=ip, network_request=True)
        if mac and mac != "00:00:00:00:00:00":
            mac_address = mac.upper()
            vendor = find_vendor_online(mac_address, api_key)
    except Exception:
        pass

    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except (socket.herror, OSError):
        pass

    return {"ip": ip, "mac_address": mac_address, "hostname": hostname, "vendor": vendor}

# --- GUI Application ---

class App(customtkinter.CTk):
    def __init__(self):
        super().__init__()

        # --- Configuration & Setup ---
        self.config = configparser.ConfigParser()
        self.config.read('config.ini')
        
        self.title("Network Scanner")
        self.geometry("950x600")
        customtkinter.set_appearance_mode("System")
        customtkinter.set_default_color_theme("blue")

        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)

        # --- Top Frame for Controls ---
        self.control_frame = customtkinter.CTkFrame(self)
        self.control_frame.grid(row=0, column=0, padx=10, pady=10, sticky="ew")
        self.control_frame.grid_columnconfigure(1, weight=1)

        self.ip_label = customtkinter.CTkLabel(self.control_frame, text="IP Network (CIDR):")
        self.ip_label.grid(row=0, column=0, padx=10, pady=5, sticky="w")
        
        self.ip_entry = customtkinter.CTkEntry(self.control_frame)
        self.ip_entry.grid(row=0, column=1, padx=10, pady=5, sticky="ew")
        self.ip_entry.insert(0, self.config['Settings'].get('IP_NETWORK', '192.168.1.0/24'))

        self.scan_button = customtkinter.CTkButton(self.control_frame, text="Start Scan", command=self.start_scan_thread)
        self.scan_button.grid(row=0, column=2, padx=10, pady=5)

        # --- Results Frame ---
        self.results_frame = customtkinter.CTkFrame(self)
        self.results_frame.grid(row=1, column=0, padx=10, pady=10, sticky="nsew")
        self.results_frame.grid_columnconfigure(0, weight=1)
        self.results_frame.grid_rowconfigure(0, weight=1)

        self.results_textbox = customtkinter.CTkTextbox(self.results_frame, state="disabled", font=("Courier New", 12))
        self.results_textbox.grid(row=0, column=0, sticky="nsew")
        self.reset_results_text()

        # --- Bottom Frame for Status ---
        self.status_frame = customtkinter.CTkFrame(self, height=30)
        self.status_frame.grid(row=2, column=0, padx=10, pady=(0, 10), sticky="ew")
        
        self.status_label = customtkinter.CTkLabel(self.status_frame, text="Ready. Please set your API key in config.ini")
        self.status_label.pack(side="left", padx=10)

        self.progress_bar = customtkinter.CTkProgressBar(self.status_frame)
        self.progress_bar.pack(side="right", padx=10, fill="x", expand=True)
        self.progress_bar.set(0)

        # --- Threading and Queues ---
        self.scan_thread = None
        self.results_queue = Queue()
        self.after(100, self.check_results_queue)

    def reset_results_text(self):
        header = f"{ 'IP Address':<18}{'MAC Address':<20}{'Hostname':<25}{'Vendor'}\n"
        separator = "-" * (18+20+25+20) + "\n"
        self.results_textbox.configure(state="normal")
        self.results_textbox.delete("1.0", "end")
        self.results_textbox.insert("end", header)
        self.results_textbox.insert("end", separator)
        self.results_textbox.configure(state="disabled")

    def add_result_text(self, text):
        self.results_textbox.configure(state="normal")
        self.results_textbox.insert("end", text)
        self.results_textbox.configure(state="disabled")
        self.results_textbox.see("end")

    def update_status(self, text):
        self.status_label.configure(text=text)

    def start_scan_thread(self):
        if self.scan_thread and self.scan_thread.is_alive():
            self.update_status("Scan already in progress.")
            return
            
        self.scan_button.configure(state="disabled", text="Scanning...")
        self.reset_results_text()
        
        self.scan_thread = threading.Thread(target=self.run_scan)
        self.scan_thread.daemon = True
        self.scan_thread.start()

    def check_results_queue(self):
        while not self.results_queue.empty():
            result = self.results_queue.get()
            if isinstance(result, dict):
                line = f"{result['ip']:<18}{result['mac_address']:<20}{result['hostname']:<25}{result['vendor']}\n"
                self.add_result_text(line)
            elif isinstance(result, str):
                if result.startswith("STATUS:"):
                    self.update_status(result.replace("STATUS:", ""))
                elif result.startswith("PROGRESS:"):
                    self.progress_bar.set(float(result.replace("PROGRESS:", "")))
                elif result == "SCAN_COMPLETE":
                    self.scan_button.configure(state="normal", text="Start Scan")
                    self.update_status(f"Scan complete. Results saved to {self.config['Settings'].get('OUTPUT_CSV')}")
                    self.progress_bar.set(1)
        
        self.after(100, self.check_results_queue)

    def run_scan(self):
        ip_network_str = self.ip_entry.get()
        thread_count = self.config['Settings'].getint('THREAD_COUNT', 50)
        output_csv = self.config['Settings'].get('OUTPUT_CSV', 'scan_results.csv')
        api_key = self.config['Settings'].get('API_KEY')

        self.results_queue.put("STATUS:Validating IP range...")
        try:
            network = ipaddress.ip_network(ip_network_str, strict=False)
            all_hosts = list(network.hosts())
        except ValueError:
            self.results_queue.put("STATUS:Error: Invalid IP Network Range.")
            self.results_queue.put("SCAN_COMPLETE")
            return

        self.results_queue.put(f"STATUS:Pinging {len(all_hosts)} hosts...")
        self.results_queue.put("PROGRESS:0.1")
        
        ping_queue = Queue()
        for ip in all_hosts:
            ping_queue.put(ip)
        
        active_hosts_queue = Queue()
        ping_threads = []
        for _ in range(thread_count):
            t = threading.Thread(target=ping_host, args=(ping_queue, active_hosts_queue))
            t.daemon = True
            t.start()
            ping_threads.append(t)
        
        ping_queue.join()
        
        active_hosts = sorted(list(active_hosts_queue.queue), key=ipaddress.IPv4Address)
        self.results_queue.put(f"STATUS:Found {len(active_hosts)} active hosts. Getting details (using online API)...")
        self.results_queue.put("PROGRESS:0.5")

        scan_results_temp = []
        detail_threads = []
        
        def get_details_worker(ip, results_list_ref, key):
            details = get_details(ip, key)
            results_list_ref.append(details)
            
        sorted_ips_for_details = sorted(active_hosts, key=ipaddress.IPv4Address)
        
        for ip in sorted_ips_for_details:
            t = threading.Thread(target=get_details_worker, args=(ip, scan_results_temp, api_key))
            t.daemon = True
            detail_threads.append(t)
            t.start()

        for t in detail_threads:
            t.join()

        scan_results_temp.sort(key=lambda x: ipaddress.ip_address(x['ip']))

        for i, details in enumerate(scan_results_temp):
            self.results_queue.put(details)
            progress = 0.5 + (i + 1) / len(scan_results_temp) * 0.4 if len(scan_results_temp) > 0 else 0.5
            self.results_queue.put(f"PROGRESS:{progress}")

        self.results_queue.put("STATUS:Exporting to CSV...")
        if scan_results_temp:
            with open(output_csv, 'w', newline='', encoding='utf-8') as f:
                fieldnames = ['ip', 'mac_address', 'hostname', 'vendor']
                writer = csv.DictWriter(f, fieldnames=fieldnames)
                writer.writeheader()
                writer.writerows(scan_results_temp)
        
        self.results_queue.put("PROGRESS:1.0")
        self.results_queue.put("SCAN_COMPLETE")

if __name__ == "__main__":
    import urllib.parse
    app = App()
    app.mainloop()