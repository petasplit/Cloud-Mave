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
from shodan import Shodan
from censys.search import CensysHosts
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

async def shodan_search(target, shodan_api_key):
    print_out(Fore.CYAN + "Searching for the target in Shodan...")

    api = Shodan(shodan_api_key)
    try:
        result = api.search(f'hostname:{target}')
        for service in result['matches']:
            print_out(Style.BRIGHT + Fore.WHITE + "[SHODAN] " + Fore.GREEN + f"IP: {service['ip_str']} - {service['port']} - {service['org']}")
    except Exception as e:
        print_out(Fore.RED + "Error using Shodan: " + str(e))

async def censys_search(target, censys_api_id, censys_api_secret):
    print_out(Fore.CYAN + "Searching for the target in Censys...")

    h = CensysHosts(censys_api_id, censys_api_secret)
    try:
        results = h.search(target)
        for result in results():
            for service in result["services"]:
                print_out(Style.BRIGHT + Fore.WHITE + "[CENSYS] " + Fore.GREEN + f"IP: {service['ip']} - {service['port']} - {service['service_name']}")
    except Exception as e:
        print_out(Fore.RED + "Error using Censys: " + str(e))

def dnssec_check(domain):
    print_out(Fore.CYAN + "Checking for DNSSEC...")

    try:
        answers = dns.resolver.resolve(domain, 'DNSKEY')
        if answers.rrset:
            print_out(Style.BRIGHT + Fore.WHITE + "[DNSSEC] " + Fore.GREEN + "DNSSEC is enabled")
    except dns.resolver.NoAnswer:
        print_out(Style.BRIGHT + Fore.WHITE + "[DNSSEC] " + Fore.RED + "No DNSSEC records found")
    except Exception as e:
        print_out(Fore.RED + "Error checking DNSSEC: " + str(e))

def wildcard_check(domain):
    print_out(Fore.CYAN + "Checking for wildcard DNS...")

    try:
        answers = dns.resolver.resolve(f'nonexistent.{domain}', 'A')
        if answers:
            print_out(Style.BRIGHT + Fore.WHITE + "[WILDCARD] " + Fore.RED + "Wildcard DNS is enabled")
    except dns.resolver.NXDOMAIN:
        print_out(Style.BRIGHT + Fore.WHITE + "[WILDCARD] " + Fore.GREEN + "No wildcard DNS records found")
    except Exception as e:
        print_out(Fore.RED + "Error checking wildcard DNS: " + str(e))

async def subdomain_scan(target):
    print_out(Fore.CYAN + "Scanning for subdomains using Sublist3r...")

    try:
        result = subprocess.run(['sublist3r', '-d', target, '-o', 'subdomains.txt'], capture_output=True, text=True)
        if result.returncode != 0:
            print_out(Fore.RED + "Error running Sublist3r: " + result.stderr)
            return

        with open('subdomains.txt', 'r') as file:
            subdomains = file.read().splitlines()

        for subdomain in subdomains:
            try:
                answers = dns.resolver.resolve(subdomain)
                for ip in answers:
                    if not inCloudFlare(str(ip)):
                        print_out(Style.BRIGHT + Fore.WHITE + "[SUBDOMAIN] " + Fore.GREEN + subdomain + " resolves to " + str(ip))
                    else:
                        print_out(Style.BRIGHT + Fore.WHITE + "[SUBDOMAIN] " + Fore.RED + subdomain + " is behind Cloudflare")
            except Exception:
                pass

        os.remove('subdomains.txt')
    except FileNotFoundError:
        print_out(Fore.RED + "Sublist3r not found. Please install it.")

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

async def certificate_transparency_scan(target):
    print_out(Fore.CYAN + "Searching Certificate Transparency logs for subdomains...")

    url = f"https://crt.sh/?q=%25.{target}&output=json"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            certs = response.json()
            for cert in certs:
                subdomain = cert['name_value']
                print_out(Style.BRIGHT + Fore.WHITE + "[CT LOG] " + Fore.GREEN + f"Subdomain: {subdomain}")
                # Inside the loop where subdomains are printed
print(Style.BRIGHT + "[CT LOG] Subdomain:", subdomain)
try:
    ip_address = resolve_ip(subdomain)
    if ip_address:
        print("- IP address:", ip_address)
    else:
        print("- IP address: Not found")
except Exception as e:
    print(f"Error resolving IP for {subdomain}: {e}")
    print("- IP address: Not found")

else:
    print("- IP address: Not found")
                await dns_lookup(subdomain)
        else:
            print_out(Fore.RED + "Error retrieving CT logs")
    except Exception as e:
        print_out(Fore.RED + "Error searching CT logs: " + str(e))

async def dns_lookup(domain):
    try:
        answers = dns.resolver.resolve(domain)
        for ip in answers:
            if not inCloudFlare(str(ip)):
                print_out(Style.BRIGHT + Fore.WHITE + "[DNS LOOKUP] " + Fore.GREEN + domain + " resolves to " + str(ip))
            else:
                print_out(Style.BRIGHT + Fore.WHITE + "[DNS LOOKUP] " + Fore.RED + domain + " is behind Cloudflare")
    except Exception:
        pass

def inCloudFlare(ip):
    cloudflare_ranges = [
        "173.245.48.0/20",
        "103.21.244.0/22",
        "103.22.200.0/22",
        "103.31.4.0/22",
        "141.101.64.0/18",
        "108.162.192.0/18",
        "190.93.240.0/20",
        "188.114.96.0/20",
        "197.234.240.0/22",
        "198.41.128.0/17",
        "162.158.0.0/15",
        "104.16.0.0/12",
        "172.64.0.0/13",
        "131.0.72.0/22"
    ]

    for subnet in cloudflare_ranges:
        if ip_in_subnetwork(ip, subnet):
            return True
    return False

def update():
    print_out(Fore.CYAN + "Updating databases...")

    # Update CloudFlare subnet database
    cf_subnet_url = "https://www.cloudflare.com/ips-v4"
    cf_subnet_file = "data/cf-subnet.txt"
    r = requests.get(cf_subnet_url, stream=True)
    with open(cf_subnet_file, 'wb') as f:
        for chunk in r.iter_content(4000):
            f.write(chunk)
    print_out(Fore.CYAN + "CloudFlare subnet database updated")

    # Update Crimeflare database
    crimeflare_url = "https://cf.ozeliurs.com/ipout"
    crimeflare_file = "data/ipout"
    r = requests.get(crimeflare_url, stream=True)
    with open(crimeflare_file, 'wb') as f:
        for chunk in r.iter_content(4000):
            f.write(chunk)
    print_out(Fore.CYAN + "Crimeflare database updated")

# Main function
async def main():
    parser = argparse.ArgumentParser(description="CloudFail Enhanced")
    parser.add_argument('--target', metavar='TARGET', type=str, help='The target URL of the website')
    parser.add_argument('--tor', action='store_true', help='Enable TOR routing')
    parser.add_argument('--update', action='store_true', help='Update the databases')
    parser.add_argument('--shodan-api-key', metavar='SHODAN_API_KEY', type=str, required=True, help='Shodan API key')
    parser.add_argument('--censys-api-id', metavar='CENSYS_API_ID', type=str, required=True, help='Censys API ID')
    parser.add_argument('--censys-api-secret', metavar='CENSYS_API_SECRET', type=str, required=True, help='Censys API Secret')

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
        await shodan_search(args.target, args.shodan_api_key)
        await censys_search(args.target, args.censys_api_id, args.censys_api_secret)
        dnssec_check(args.target)
        wildcard_check(args.target)
        await subdomain_scan(args.target)
        await reverse_dns_lookup(args.target)
        await http_headers_analysis(args.target)
        await certificate_transparency_scan(args.target)
    else:
        print_out(Fore.RED + "No target specified")
        return

if __name__ == "__main__":
    asyncio.run(main())
