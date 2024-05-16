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
import dns.resolver
import crtsh
import dnsdumpster

# Initialize colorama
colorama.init()

# Utility functions
def print_out(data, end='\n'):
    datetimestr = str(datetime.datetime.strftime(datetime.datetime.now(), '%H:%M:%S'))
    print(Style.NORMAL + "[" + datetimestr + "] " + re.sub(' +', ' ', data) + Style.RESET_ALL, ' ', end=end)

def resolve_ip(hostname):
    try:
        answers = dns.resolver.resolve(hostname, 'A')
        ip_address = answers[0].address
        return ip_address
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
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

async def dnsdumpster_search(target):
    print_out(Fore.CYAN + "Searching for subdomains using DNSDumpster...")

    try:
        res = dnsdumpster.DNSDumpsterAPI(False).search(target)
        subdomains = res['dns_records']['host']
        for subdomain in subdomains:
            print_out(Style.BRIGHT + Fore.WHITE + "[SUBDOMAIN] " + Fore.GREEN + subdomain['domain'])
            await dns_lookup(subdomain['domain'])
    except Exception as e:
        print_out(Fore.RED + "Error searching DNSDumpster: " + str(e))

async def crtsh_search(target):
    print_out(Fore.CYAN + "Searching Certificate Transparency logs for subdomains...")

    try:
        c = crtsh.Crtsh()
        results = c.search(target)
        for result in results:
            subdomain = result['name_value']
            print_out(Style.BRIGHT + Fore.WHITE + "[CT LOG] " + Fore.GREEN + f"Subdomain: {subdomain}")
            await dns_lookup(subdomain)
    except Exception as e:
        print_out(Fore.RED + "Error searching crt.sh: " + str(e))

async def dns_lookup(domain):
    try:
        answers = dns.resolver.resolve(domain, 'A')
        for ip in answers:
            print_out(Style.BRIGHT + Fore.WHITE + "[DNS LOOKUP] " + Fore.GREEN + domain + " resolves to " + str(ip))
    except Exception as e:
        print_out(Fore.RED + f"Error looking up DNS for {domain}: " + str(e))

async def reverse_dns_lookup(ip):
    try:
        result = socket.gethostbyaddr(ip)
        print_out(Style.BRIGHT + Fore.WHITE + "[REVERSE DNS] " + Fore.GREEN + f"IP: {ip} - Hostname: {result[0]}")
    except socket.herror:
        pass

async def http_headers_analysis(target):
    print_out(Fore.CYAN + "Analyzing HTTP headers for real IP...")

    try:
        response = requests.get(f"http://{target}", timeout=10)
        for header, value in response.headers.items():
            if "server" in header.lower() or "via" in header.lower() or "x-forwarded-for" in header.lower():
                print_out(Style.BRIGHT + Fore.WHITE + "[HTTP HEADER] " + Fore.GREEN + f"{header}: {value}")
    except Exception as e:
        print_out(Fore.RED + "Error analyzing HTTP headers: " + str(e))

async def main():
    parser = argparse.ArgumentParser(description="DNS Recon Tool")
    parser.add_argument('--target', metavar='TARGET', type=str, help='The target URL of the website')
    parser.add_argument('--tor', action='store_true', help='Enable TOR routing')

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

    if args.target:
        print_out(Fore.CYAN + f"Analyzing {args.target}")

        await dnsdumpster_search(args.target)
        await crtsh_search(args.target)
        await reverse_dns_lookup(resolve_ip(args.target))
        await http_headers_analysis(args.target)
        await dns_lookup(args.target)
        await mx_records(args.target)
        await cname_records(args.target)
        await ip_history(args.target)
    else:
        print_out(Fore.RED + "No target specified")
        return

async def mx_records(domain):
    print_out(Fore.CYAN + f"Fetching MX records for {domain}")

    try:
        answers = dns.resolver.resolve(domain, 'MX')
        for rdata in answers:
            print_out(Style.BRIGHT + Fore.WHITE + "[MX RECORD] " + Fore.GREEN + f"{domain} => {rdata.exchange}")
    except Exception as e:
        print_out(Fore.RED + f"Error fetching MX records for {domain}: " + str(e))

async def cname_records(domain):
    print_out(Fore.CYAN + f"Fetching CNAME records for {domain}")

    try:
        answers = dns.resolver.resolve(domain, 'CNAME')
        for rdata in answers:
            print_out(Style.BRIGHT + Fore.WHITE + "[CNAME RECORD] " + Fore.GREEN + f"{domain} => {rdata.target}")
except Exception as e:
print_out(Fore.RED + f"Error fetching CNAME records for {domain}: " + str(e))

async def ip_history(domain):
print_out(Fore.CYAN + f"Fetching IP address history for {domain}")

# Placeholder for IP address history retrieval

if name == "main":
asyncio.run(main())
