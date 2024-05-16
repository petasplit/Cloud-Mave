#!/usr/bin/env python3
import argparse
import asyncio
import socket
import socks
import requests
import datetime
import binascii
import re
import subprocess
import os
import json
import colorama
from colorama import Fore, Style
import dns.resolver  # Importing dns.resolver for DNS resolution
import collections

collections.Callable = collections.abc.Callable

# Initialize colorama
colorama.init()

# Utility functions
def print_out(data, end='\n'):
    datetimestr = str(datetime.datetime.strftime(datetime.datetime.now(), '%H:%M:%S'))
    print(Style.NORMAL + "[" + datetimestr + "] " + re.sub(' +', ' ', data) + Style.RESET_ALL, ' ', end=end)

def resolve_ip(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        return None

def ip_in_subnetwork(ip_address, subnetwork):
    (ip_integer, version1) = ip_to_integer(ip_address)
    (ip_lower, ip_upper, version2) = subnetwork_to_ip_range(subnetwork)

    if version1 != version2:
        raise ValueError("incompatible IP versions")

    return (ip_lower <= ip_integer <= ip_upper)

def ip_to_integer(ip_address):
    for version in (socket.AF_INET, socket.AF_INET6):
        try:
            ip_hex = socket.inet_pton(version, ip_address)
            ip_integer = int(binascii.hexlify(ip_hex), 16)
            return ip_integer, 4 if version == socket.AF_INET else 6
        except:
            pass

    raise ValueError("invalid IP address")

def subnetwork_to_ip_range(subnetwork):
    try:
        fragments = subnetwork.split('/')
        network_prefix = fragments[0]
        netmask_len = int(fragments[1])

        for version in (socket.AF_INET, socket.AF_INET6):
            ip_len = 32 if version == socket.AF_INET else 128

            try:
                suffix_mask = (1 << (ip_len - netmask_len)) - 1
                netmask = ((1 << ip_len) - 1) - suffix_mask
                ip_hex = socket.inet_pton(version, network_prefix)
                ip_lower = int(binascii.hexlify(ip_hex), 16) & netmask
                ip_upper = ip_lower + suffix_mask

                return (ip_lower, ip_upper, 4 if version == socket.AF_INET else 6)
            except:
                pass
    except:
        pass

    raise ValueError("invalid subnetwork")

# Functions to interact with external services
async def dnsdumpster(target):
    print_out(Fore.CYAN + "Testing for misconfigured DNS using DNSDumpster...")

    # Placeholder for DNSDumpster code. Add actual API call if available.

async def crt_sh_search(target):
    print_out(Fore.CYAN + "Searching Certificate Transparency logs for subdomains...")
    
    url = f"https://crt.sh/?q=%25.{target}&output=json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            certs = response.json()
            for cert in certs:
                subdomain = cert['name_value']
                print_out(Style.BRIGHT + Fore.WHITE + "[CRT.SH] " + Fore.GREEN + f"Subdomain: {subdomain}")
    except Exception as e:
        print_out(Fore.RED + "Error searching CRT.SH logs: " + str(e))

async def dns_lookup(domain):
    print_out(Fore.CYAN + f"Performing DNS lookup for domain: {domain}...")
    
    try:
        answers = dns.resolver.query(domain, 'A')
        for ip in answers:
            print_out(Style.BRIGHT + Fore.WHITE + "[DNS LOOKUP] " + Fore.GREEN + f"{domain} resolves to {ip}")
    except Exception as e:
        print_out(Fore.RED + f"Error performing DNS lookup for {domain}: {str(e)}")

async def cname_lookup(domain):
    print_out(Fore.CYAN + f"Performing CNAME lookup for domain: {domain}...")
    
    try:
        answers = dns.resolver.query(domain, 'CNAME')
        for cname in answers:
            print_out(Style.BRIGHT + Fore.WHITE + "[CNAME LOOKUP] " + Fore.GREEN + f"{domain} has CNAME record: {cname}")
    except Exception as e:
        print_out(Fore.RED + f"Error performing CNAME lookup for {domain}: {str(e)}")

async def mx_lookup(domain):
    print_out(Fore.CYAN + f"Performing MX lookup for domain: {domain}...")
    
    try:
        answers = dns.resolver.query(domain, 'MX')
        for mx in answers:
            print_out(Style.BRIGHT + Fore.WHITE + "[MX LOOKUP] " + Fore.GREEN + f"{domain} has MX record: {mx}")
    except Exception as e:
        print_out(Fore.RED + f"Error performing MX lookup for {domain}: {str(e)}")

async def reverse_ip_lookup(target):
    print_out(Fore.CYAN + f"Performing reverse IP lookup for domain: {target}...")
    
    try:
        result = socket.gethostbyaddr(target)
        print_out(Style.BRIGHT + Fore.WHITE + "[REVERSE IP LOOKUP] " + Fore.GREEN + f"IP: {target} - Hostname: {result[0]}")
    except Exception as e:
        print_out(Fore.RED + f"Error performing reverse IP lookup for {target}: {str(e)}")

async def main():
    parser = argparse.ArgumentParser(description="CloudFail Enhanced")
    parser.add_argument('--target', metavar='TARGET', type=str, help='The target URL of the website')
    parser.add_argument('--tor', action='store_true', help='Enable TOR routing')
    parser.add_argument('--update', action='store_true', help='Update the databases')

    args = parser.parse_args()

    if args.tor:
        print_out(Fore.CYAN + "Enabling TOR routing...")
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
        socket.socket = socks.socksocket
        try:
            r = requests.get("http://ipinfo.io/ip")
            print_out(Fore.WHITE + "New IP Address: " + r.text.strip())
        except Exception as e:
            print_out(Fore.RED + "Error connecting to TOR: " + str(e))
            return

    if args.update:
        update()

    if args.target:
        print_out(Fore.CYAN + f"Analyzing {args.target}")

        await dnsdumpster(args.target)
        await crt_sh_search(args.target)
        await dns_lookup(args.target)
        await cname_lookup(args.target)
        await mx_lookup(args.target)
        await reverse_ip_lookup(args.target)
    else:
        print_out(Fore.RED + "No target specified")
        return

if __name__ == "__main__":
    asyncio.run(main())
