import os
import signal
import sys
import glob
import time
import threading
from scapy.all import sniff, rdpcap, EAP, wrpcap
import psutil

# Global counters and variables
usernames_found = 0
failed_extractions = 0
failed_packets = []
start_time = time.time()
failure_output_file = 'nousernames.pcap'
info_lines = []
output_file_handle = None  # Global file handle for output file

# Function to format elapsed time into days, hours, minutes, and seconds
def format_elapsed_time(seconds):
    days = seconds // 86400
    seconds %= 86400
    hours = seconds // 3600
    seconds %= 3600
    minutes = seconds // 60
    seconds %= 60

    parts = []
    if days > 0:
        parts.append(f"{days}d")
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    parts.append(f"{seconds}s")

    return ", ".join(parts)

# Function to print real-time stats and INFO messages
def display_stats():
    while True:
        elapsed_time = int(time.time() - start_time)
        formatted_time = format_elapsed_time(elapsed_time)
        process = psutil.Process(os.getpid())
        memory_usage = process.memory_info().rss / (1024 * 1024)  # Convert bytes to MB
        cpu_usage = process.cpu_percent(interval=1)  # Get CPU usage percentage

        # Clear the screen and print the stats line
        os.system('clear' if os.name == 'posix' else 'cls')
        print(f"[STATS] Elapsed Time: {formatted_time} | Usernames Collected: {usernames_found} | "
              f"Failures: {failed_extractions} | Memory Usage: {memory_usage:.2f} MB | CPU Usage: {cpu_usage:.2f}%")

        # Print the INFO lines
        for line in info_lines[-10:]:  # Show the last 10 INFO lines
            print(line)

        time.sleep(1)

# Function to print INFO messages
def print_info(message):
    info_lines.append(message)
    if len(info_lines) > 100:  # Limit the list to avoid excessive memory use
        info_lines.pop(0)
    print(message)  # Print immediately for user feedback

# Function to check if the interface is already in monitor mode
def is_monitor_mode(interface):
    try:
        with open(f'/sys/class/net/{interface}/type') as f:
            return f.read().strip() == '802'
    except FileNotFoundError:
        print_info(f"[ERROR] Interface {interface} not found.")
        sys.exit(1)

# Function to enable monitor mode on the specified interface
def enable_monitor_mode(interface):
    if not interface:
        print_info("[ERROR] No interface specified. Use -i to specify an interface.")
        sys.exit(1)
    try:
        if is_monitor_mode(interface):
            print_info(f"[INFO] {interface} is already in monitor mode.")
        else:
            command_prefix = "sudo " if os.geteuid() != 0 else ""
            os.system(f"{command_prefix}ip link set {interface} down")
            os.system(f"{command_prefix}iw {interface} set monitor control")
            os.system(f"{command_prefix}ip link set {interface} up")
            print_info(f"[INFO] Monitor mode enabled on {interface}")
    except Exception as e:
        print_info(f"[ERROR] Failed to enable monitor mode on {interface}: {e}")
        sys.exit(1)

# Function to restore managed mode on the interface
def disable_monitor_mode(interface, skip_restore=False):
    if not interface or skip_restore:
        return
    try:
        command_prefix = "sudo " if os.geteuid() != 0 else ""
        os.system(f"{command_prefix}ip link set {interface} down")
        os.system(f"{command_prefix}iw {interface} set type managed")
        os.system(f"{command_prefix}ip link set {interface} up")
        print_info(f"[INFO] Managed mode restored on {interface}")
    except Exception as e:
        print_info(f"[ERROR] Failed to restore managed mode on {interface}: {e}")

# Function to handle Ctrl-C for a graceful exit
def signal_handler(sig, frame):
    global usernames_found, failed_extractions, failed_packets, failure_output_file, output_file_handle
    print("\n[INFO] Exiting...")

    # Calculate the final elapsed time
    elapsed_time = int(time.time() - start_time)
    formatted_time = format_elapsed_time(elapsed_time)

    print(f"\n[FINAL STATS] Elapsed Time: {formatted_time}")
    print(f"[FINAL STATS] Usernames found: {usernames_found}")
    print(f"[FINAL STATS] EAP Response packets without usernames: {failed_extractions}")
    
    if args.save_failures and failed_packets:
        wrpcap(failure_output_file, failed_packets)
        failed_packets.clear()  # Clear memory after saving
        print(f"[INFO] Non-username packets saved to '{failure_output_file}'")

    if output_file_handle:
        output_file_handle.close()

    if not args.skip_restore and is_monitor_mode(interface):
        user_input = input("[PROMPT] Restore managed mode on exit? (y/n): ").strip().lower()
        if user_input == 'y':
            disable_monitor_mode(interface)
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

# Function to parse EAP Identity packets and extract usernames
def packet_handler(packet):
    global usernames_found, failed_extractions, failed_packets, output_file_handle
    if packet.haslayer(EAP):
        eap_layer = packet.getlayer(EAP)
        if eap_layer.code == 2:  # EAP-Response
            try:
                identity = eap_layer.identity.decode()
                if identity:
                    usernames_found += 1
                    print_info(f"[USERNAME] Found: {identity}")
                    if output_file_handle:
                        output_file_handle.write(identity + '\n')
                else:
                    failed_extractions += 1
                    if args.save_failures:
                        failed_packets.append(packet)
            except AttributeError:
                failed_extractions += 1
                if args.save_failures:
                    failed_packets.append(packet)

# Function to sniff packets live from an interface
def sniff_packets(interface, essid_filter=None):
    print_info(f"[INFO] Sniffing on interface {interface}...")
    print_info("[INFO] Press Ctrl-C to exit.")
    if essid_filter:
        print_info(f"[INFO] Filtering for ESSID: {essid_filter}")
    
    def packet_filter(packet):
        # Filter based on ESSID if specified
        return not essid_filter or (packet.haslayer(EAP) and essid_filter in str(packet))

    sniff(iface=interface, prn=packet_handler, store=0, stop_filter=lambda x: False, lfilter=packet_filter)

# Function to read and analyze PCAP files with wildcard support
def read_pcap_files(pcap_pattern):
    files = glob.glob(pcap_pattern)
    if not files:
        print_info(f"[ERROR] No PCAP files found matching the pattern: {pcap_pattern}")
        sys.exit(1)

    for pcap_file in files:
        print_info(f"[INFO] Reading packets from {pcap_file}...")
        packets = rdpcap(pcap_file)
        filtered_packets = [pkt for pkt in packets if pkt.haslayer(EAP) and pkt[EAP].code == 2]  # Filter for EAP-Response packets
        for packet in filtered_packets:
            packet_handler(packet)

# Command-line argument parsing
if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="WPA2 Enterprise Recon Utility")
    parser.add_argument("-i", "--interface", help="WiFi interface to use")
    parser.add_argument("-e", "--essid", help="Filter for a specific ESSID")
    parser.add_argument("-o", "--output-file", help="File to dump usernames")
    parser.add_argument("-p", "--pcap", help="PCAP file or pattern (supports wildcards, e.g., '*.pcap')")
    parser.add_argument("--skip-restore", action="store_true", help="Skip restoring managed mode on the interface after exit")
    parser.add_argument("-f", "--save-failures", nargs='?', const='nousernames.pcap', help="Save non-username EAP Response packets to the specified file (default: 'nousernames.pcap')")
    args = parser.parse_args()

    if args.output_file:
        output_file_handle = open(args.output_file, 'a')

    interface = args.interface

    # Start the real-time statistics display in a separate thread
    stats_thread = threading.Thread(target=display_stats, daemon=True)
    stats_thread.start()

    if args.pcap:
        # Read from the provided PCAP file or pattern with wildcard support
        read_pcap_files(args.pcap)
    else:
        # If --interface is not provided when live sniffing is required, show usage and exit
        if not args.interface:
            print_info("[ERROR] Interface not specified. Use -i to specify an interface for live sniffing.")
            parser.print_help()
            sys.exit(1)

        # Enable monitor mode on the interface
        enable_monitor_mode(interface)

        try:
            # Start sniffing packets
            sniff_packets(interface, args.essid)
        except Exception as e:
            print_info(f"[ERROR] An error occurred: {e}")
        finally:
            # Restore the interface to managed mode unless skipped
            disable_monitor_mode(interface, skip_restore=args.skip_restore)

