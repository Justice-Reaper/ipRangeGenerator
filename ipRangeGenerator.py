#!/usr/bin/python3

from pwn import *
import sys
import argparse

def generate_ip_range(start_ip, end_ip):
    def ip_to_number(ip):
        parts = list(map(int, ip.split('.')))
        return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
    
    def number_to_ip(num):
        return f"{(num >> 24) & 0xFF}.{(num >> 16) & 0xFF}.{(num >> 8) & 0xFF}.{num & 0xFF}"
    
    start_num = ip_to_number(start_ip)
    end_num = ip_to_number(end_ip)
    
    if start_num > end_num:
        print("[!] Error: Start IP cannot be greater than End IP")
        sys.exit(1)
    
    total_ips = end_num - start_num + 1
    
    for ip_num in range(start_num, end_num + 1):
        yield number_to_ip(ip_num) + '\n'

def generate_ips_cidr(cidr_network):
    try:
        ip, mask = cidr_network.split('/')
        mask = int(mask)
    except:
        print("[!] Error: Invalid CIDR format. Use: IP/MASK (e.g., 192.168.1.0/24)")
        sys.exit(1)
    
    if mask < 0 or mask > 32:
        print("[!] Error: Mask must be between 0 and 32")
        sys.exit(1)
    
    def ip_to_number(ip):
        parts = list(map(int, ip.split('.')))
        return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
    
    def number_to_ip(num):
        return f"{(num >> 24) & 0xFF}.{(num >> 16) & 0xFF}.{(num >> 8) & 0xFF}.{num & 0xFF}"
    
    ip_num = ip_to_number(ip)
    mask_num = (0xFFFFFFFF << (32 - mask)) & 0xFFFFFFFF
    network_ip = ip_num & mask_num
    broadcast_ip = network_ip | (~mask_num & 0xFFFFFFFF)
    
    if mask >= 31:
        start = network_ip
        end = broadcast_ip
    else:
        start = network_ip + 1
        end = broadcast_ip - 1
    
    total_ips = end - start + 1
    
    if total_ips <= 0:
        print("[!] Error: The specified range contains no valid IPs")
        sys.exit(1)
    
    for current_ip in range(start, end + 1):
        yield number_to_ip(current_ip) + '\n'

def validate_ip(ip):
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not 0 <= int(part) <= 255:
                return False
        return True
    except:
        return False

def main():
    parser = argparse.ArgumentParser()
    
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-lr', '--lower-range', dest='ip_start', help='Start IP of range (e.g., 192.168.1.1)')
    group.add_argument('-cidr', help='CIDR notation (e.g., 192.168.1.0/24)')
    
    parser.add_argument('-ur', '--upper-range', dest='ip_end', help='End IP of range (e.g., 192.168.1.100)')
    parser.add_argument('-o', '--output', help='Output filename (optional)')
    
    args = parser.parse_args()
    
    output_file = args.output if args.output else "generated_ips.txt"
    
    if args.ip_start:
        if not args.ip_end:
            print("[!] Error: When using -lr, you must also use -ur")
            sys.exit(1)
        
        ip_start = args.ip_start
        ip_end = args.ip_end
        
        if not validate_ip(ip_start):
            print(f"[!] Error: Invalid start IP: {ip_start}")
            sys.exit(1)
        
        if not validate_ip(ip_end):
            print(f"[!] Error: Invalid end IP: {ip_end}")
            sys.exit(1)
        
        print(f"[+] Generating IPs from {ip_start} to {ip_end}")
        print(f"[+] Output file: {output_file}")
        
        def calculate_total_ips(ip1, ip2):
            def ip_to_number(ip):
                parts = list(map(int, ip.split('.')))
                return (parts[0] << 24) + (parts[1] << 16) + (parts[2] << 8) + parts[3]
            
            num1 = ip_to_number(ip1)
            num2 = ip_to_number(ip2)
            return abs(num2 - num1) + 1
        
        total_ips = calculate_total_ips(ip_start, ip_end)
        generator = generate_ip_range(ip_start, ip_end)
        
    else:
        cidr_network = args.cidr
        
        print(f"[+] Generating IPs for network {cidr_network}")
        print(f"[+] Output file: {output_file}")
        
        ip, mask = cidr_network.split('/')
        mask = int(mask)
        
        if not validate_ip(ip):
            print(f"[!] Error: Invalid network IP: {ip}")
            sys.exit(1)
        
        if mask == 32:
            total_ips = 1
        elif mask == 31:
            total_ips = 2
        else:
            total_ips = (2 ** (32 - mask)) - 2
        
        generator = generate_ips_cidr(cidr_network)
    
    counter = 0
    
    p1 = log.progress("Generating IPs")
    p1.status(f"Starting generation of {total_ips:,} IPs")
    
    p2 = log.progress("Progress")
    
    with open(output_file, 'w') as f:
        for ip in generator:
            f.write(ip)
            counter += 1
            
            if total_ips > 1000:
                if counter % max(1000, total_ips // 100) == 0:
                    percentage = (counter * 100) // total_ips
                    p2.status(f"{percentage}% - {counter:,}/{total_ips:,} IPs")
            else:
                percentage = (counter * 100) // total_ips
                p2.status(f"{percentage}% - {counter:,}/{total_ips:,} IPs")
    
    p1.success(f"Completed! {counter:,} IPs generated in {output_file}")
    p2.success("100%")

if __name__ == "__main__":
    main()
