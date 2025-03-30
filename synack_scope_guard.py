# Developed by THYemre
import argparse
import signal
import sys
import os
import platform
import socket
import re
from scapy.all import sniff, IP, Raw

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    RESET = '\033[0m'

def parse_arguments():
    parser = argparse.ArgumentParser(description="Capture traffic to specified hostnames, resolving them to IPs.")
    parser.add_argument('-f', '--file', type=str, required=True, help="Path to a text file containing the list of hostnames.")
    parser.add_argument('-e', '--exclude', type=str, help="Path to a text file containing the list of IP addresses to exclude.")
    parser.add_argument('-k', '--kill', action='store_true', help="Enable kill switch to shut down the network adapter after packet capture.")
    parser.add_argument('-g', '--generate', type=str, help="Generate ip_list.txt from hostnames in the given file.")
    parser.add_argument('-c', '--count', type=int, default=5, help="The number of packet matches before triggering the kill switch (default: 5).")
    return parser.parse_args()

def read_hostnames_from_file(file_path):
    with open(file_path, 'r') as f:
        hostnames = f.readlines()
    return [hostname.strip() for hostname in hostnames]

def resolve_hostnames_to_ips(hostnames):
    ip_list = []
    wildcard_patterns = []
    for hostname in hostnames:
        if '*' in hostname:
            pattern = hostname.replace('.', r'\.').replace('*', r'.*')
            wildcard_patterns.append(re.compile(pattern))
        else:
            try:
                ip = socket.gethostbyname(hostname)
                ip_list.append(ip)
                print(f"Resolved {hostname} to {ip}")
            except socket.gaierror:
                print(f"Could not resolve {hostname}")
    return ip_list, wildcard_patterns

def reverse_dns_lookup(ip):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except (socket.herror, socket.gaierror):
        return None

def read_ips_from_file(file_path):
    with open(file_path, 'r') as f:
        ips = f.readlines()
    return {ip.strip() for ip in ips}

def packet_callback(packet, target_ips, exclude_ips, wildcard_patterns, packet_count, kill_switch_triggered, user_kill_switch_count):
    if packet.haslayer(IP):
        dst_ip = packet[IP].dst
        hostname = reverse_dns_lookup(dst_ip)
        
        if hostname:
            print(f"{Colors.CYAN}Packet captured to {dst_ip} ({hostname}){Colors.RESET}")
        else:
            print(f"{Colors.CYAN}Packet captured to {dst_ip} (No hostname found){Colors.RESET}")
        
        for pattern in wildcard_patterns:
            if pattern.match(hostname):
                print(f"{Colors.RED}<REGEX MATCH !!>{Colors.RESET} Hostname {hostname} matches the pattern {pattern.pattern}")
                print(f"{Colors.RED}Wildcard matched!{Colors.RESET}")
                packet_count[dst_ip] = packet_count.get(dst_ip, 0) + 1
                print(f"{Colors.GREEN}Packet count for {dst_ip}: {packet_count[dst_ip]}{Colors.RESET}")
                
                if packet_count[dst_ip] >= user_kill_switch_count and not kill_switch_triggered[0]:
                    print(f"{Colors.RED}Kill switch triggered after {user_kill_switch_count} packets to {hostname}.{Colors.RESET}")
                    kill_switch_triggered[0] = True
                    kill_switch()
                break

        if dst_ip in target_ips and dst_ip not in exclude_ips:
            if packet_count[dst_ip] % 100 == 0:
                print(f"{Colors.CYAN}Packet count for {dst_ip}: {packet_count[dst_ip]}{Colors.RESET} - {Colors.GREEN}Captured Packet: {packet.summary()}{Colors.RESET}")
                if packet.haslayer(Raw):
                    payload = bytes(packet[Raw].load)
                    print(f"{Colors.MAGENTA}Payload (first 100 bytes): {payload[:100]}{Colors.RESET}")
                else:
                    print(f"{Colors.YELLOW}No raw payload available.{Colors.RESET}")

def kill_switch():
    os_type = platform.system()
    if os_type == 'Linux':
        try:
            interface = "eth0"
            os.system(f"sudo ifconfig {interface} down")
            print(f"{Colors.RED}[*] Network interface {interface} has been disabled.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}Error disabling network interface: {e}{Colors.RESET}")

    elif os_type == 'Windows':
        try:
            adapter_name = "Ethernet"
            os.system(f"netsh interface set interface \"{adapter_name}\" disable")
            print(f"{Colors.RED}[*] Network interface {adapter_name} has been disabled.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}Error disabling network adapter: {e}{Colors.RESET}")

    elif os_type == 'Darwin':
        try:
            interface = "en0"
            os.system(f"sudo ifconfig {interface} down")
            print(f"{Colors.RED}[*] Network interface {interface} has been disabled.{Colors.RESET}")
        except Exception as e:
            print(f"{Colors.RED}Error disabling network interface: {e}{Colors.RESET}")

    else:
        print(f"{Colors.RED}[*] Unsupported OS for kill switch operation.{Colors.RESET}")

def signal_handler(sig, frame, sniff_thread):
    print(f"{Colors.YELLOW}\n[*] Exiting...{Colors.RESET}")
    sniff_thread.stop()

def generate_ip_list(hostnames_file):
    hostnames = read_hostnames_from_file(hostnames_file)
    ip_list, _ = resolve_hostnames_to_ips(hostnames)
    
    with open('ip_list.txt', 'w') as f:
        for ip in ip_list:
            f.write(ip + '\n')
    print(f"{Colors.GREEN}Generated ip_list.txt with the following IPs: {', '.join(ip_list)}{Colors.RESET}")

def main():
    args = parse_arguments()
    
    if args.generate:
        generate_ip_list(args.generate)
        return
    
    sniff_thread = None
    signal.signal(signal.SIGINT, lambda sig, frame: signal_handler(sig, frame, sniff_thread))

    hostnames = read_hostnames_from_file(args.file)
    target_ips, wildcard_patterns = resolve_hostnames_to_ips(hostnames)

    exclude_ips = set()
    if args.exclude:
        exclude_ips = read_ips_from_file(args.exclude)

    packet_count = {ip: 0 for ip in target_ips}
    kill_switch_triggered = [False]

    target_ips_display = target_ips[:10]
    if len(target_ips) > 10:
        target_ips_display.append("...")

    print(f"{Colors.GREEN}[*] Capturing all traffic to IPs: {', '.join(target_ips_display)}{Colors.RESET}...")
    print(f"{Colors.YELLOW}[*] Excluding traffic to IPs: {', '.join(exclude_ips)}{Colors.RESET}...")

    sniff_thread = sniff(filter=f"host {' or '.join(target_ips)}", prn=lambda packet: packet_callback(packet, target_ips, exclude_ips, wildcard_patterns, packet_count, kill_switch_triggered, args.count), store=0)

if __name__ == '__main__':
    main()
