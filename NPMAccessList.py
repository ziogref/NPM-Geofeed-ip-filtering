#!/usr/bin/env python3

import requests
import csv
import io
import json
import logging
import ipaddress
import sys
import os
import re
import socket
import concurrent.futures

# ==========================================
# CONFIGURATION CONSTANTS
# ==========================================

# Base Directory
BASE_DIR = "/boot/config/NPMAccessList"

# Sub-directories
CONFIG_DIR = os.path.join(BASE_DIR, "Config")
CACHE_DIR = os.path.join(BASE_DIR, "Cache")

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==========================================
# HELPERS
# ==========================================

def load_config(filename):
    """Loads a JSON config file from the config directory."""
    path = os.path.join(CONFIG_DIR, filename)
    if not os.path.exists(path):
        logger.warning(f"Config file not found: {path}")
        return None
    try:
        with open(path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        logger.error(f"Error decoding JSON in {filename}: {e}")
        return None
    except Exception as e:
        logger.error(f"Error reading {filename}: {e}")
        return None

def send_ntfy_msg(ntfy_config, message, title):
    """Standalone function to send NTFY messages with Title and Tags."""
    if not ntfy_config or not ntfy_config.get('enabled', False):
        return

    try:
        url = f"{ntfy_config['url']}/{ntfy_config['topic']}"
        headers = {
            "Title": f"NPM | {title}",
            "Tags": "warning"
        }
        
        if ntfy_config.get('token'):
            headers["Authorization"] = f"Bearer {ntfy_config['token']}"
        
        resp = requests.post(url, data=message.encode('utf-8'), headers=headers)
        if resp.status_code != 200:
            logger.warning(f"NTFY failed. Code: {resp.status_code}, Resp: {resp.text}")
    except Exception as e:
        logger.error(f"Failed to send NTFY notification: {e}")

def get_content_with_fallback(name, url, ntfy_config=None):
    """
    Downloads content from URL. 
    If successful -> saves to cache -> returns content.
    If failed -> sends NTFY -> loads from cache -> returns content.
    """
    if not os.path.exists(CACHE_DIR):
        try:
            os.makedirs(CACHE_DIR)
        except OSError as e:
            logger.error(f"Could not create cache directory {CACHE_DIR}: {e}")

    safe_name = "".join([c for c in name if c.isalpha() or c.isdigit() or c in (' ', '-', '_')]).strip().replace(" ", "_")
    cache_path = os.path.join(CACHE_DIR, f"{safe_name}.cache")

    try:
        response = requests.get(url, timeout=20)
        response.raise_for_status()
        content = response.text
        
        with open(cache_path, 'w', encoding='utf-8') as f:
            f.write(content)
        return content

    except Exception as e:
        raw_error = str(e)
        logger.error(f"Failed to fetch {name}: {raw_error}")
        
        clean_error = "Connection Failed"
        if "Name or service not known" in raw_error: clean_error = "DNS Error"
        elif "404" in raw_error: clean_error = "HTTP 404"
        elif "500" in raw_error: clean_error = "HTTP 500"
        
        if ntfy_config and ntfy_config.get('enabled', False):
            ntfy_msg = f"{name} | {clean_error} | Using last known data"
            send_ntfy_msg(ntfy_config, ntfy_msg, title="Download Failed")

        if os.path.exists(cache_path):
            logger.warning(f"Falling back to cached file for {name}...")
            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception:
                return None
        else:
            return None

# ==========================================
# ASN Scanner
# ==========================================

def fetch_ripe_data(asn, ntfy_config=None):
    """Fetches prefixes for an ASN using RIPE API (With caching)."""
    url = f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={asn}"
    content = get_content_with_fallback(f"RIPE_{asn}", url, ntfy_config)
    
    if not content:
        return []

    try:
        data = json.loads(content)
        prefixes = []
        if 'data' in data and 'prefixes' in data['data']:
            for item in data['data']['prefixes']:
                prefix = item['prefix']
                if ":" not in prefix: # IPv4 Only for now
                    prefixes.append(prefix)
        return prefixes
    except Exception as e:
        logger.error(f"Error parsing RIPE data for {asn}: {e}")
        return []

def scan_cidr_for_hostname(cidr, rules_for_this_asn):
    """
    Worker function: Checks the gateway of a CIDR against regex rules.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        
        # Determine Gateway IP (First Usable)
        if network.num_addresses > 1:
            gateway_ip = network.network_address + 1
        else:
            gateway_ip = network.network_address

        # Reverse DNS Lookup
        hostname, _, _ = socket.gethostbyaddr(str(gateway_ip))
        hostname_str = str(hostname).lower()

        # Check against the rules configured for THIS ASN
        for tag, pattern in rules_for_this_asn:
            if re.search(pattern, hostname_str, re.IGNORECASE):
                return (cidr, tag, hostname_str)
        
        return None
    except Exception:
        return None

# ==========================================
# NPM LOGIC
# ==========================================

class NpmManager:
    def __init__(self, url, username, password):
        self.url = url.rstrip('/')
        self.username = username
        self.password = password
        self.token = None
        self.session = requests.Session()

    def login(self):
        endpoint = f"{self.url}/api/tokens"
        try:
            response = self.session.post(endpoint, json={
                "identity": self.username,
                "secret": self.password
            })
            response.raise_for_status()
            self.token = response.json()['token']
            logger.info("Successfully authenticated with Nginx Proxy Manager.")
        except Exception as e:
            logger.error(f"Failed to login to NPM: {e}")
            raise

    def get_headers(self):
        return {"Authorization": f"Bearer {self.token}"}

    def get_access_list_id(self, name):
        endpoint = f"{self.url}/api/nginx/access-lists"
        response = self.session.get(endpoint, headers=self.get_headers())
        response.raise_for_status()
        for item in response.json():
            if item['name'] == name:
                return item['id'], item
        return None, None

    def update_access_list(self, name, ips, source_map=None, ntfy_config=None):
        list_id, existing_data = self.get_access_list_id(name)
        
        if list_id:
            try:
                # Check for changes
                endpoint = f"{self.url}/api/nginx/access-lists/{list_id}"
                resp = self.session.get(endpoint, headers=self.get_headers(), params={"expand": "clients"})
                resp.raise_for_status()
                full_data = resp.json()
                
                raw_clients = full_data.get('clients', [])
                current_ips = set()
                for c in raw_clients:
                    try:
                        net = ipaddress.ip_network(c['address'], strict=False)
                        current_ips.add(str(net))
                    except ValueError:
                        current_ips.add(c['address'])

                new_ips = set(ips)
                
                if current_ips == new_ips:
                    logger.info(f"NO CHANGES: Access List '{name}' is up-to-date.")
                    return
                
                added = new_ips - current_ips
                removed = current_ips - new_ips
                
                logger.info(f"CHANGES: {len(added)} to add, {len(removed)} to remove.")

                # Optional: Send NTFY on change
                if ntfy_config and ntfy_config.get('enabled', False) and (added or removed):
                    msg_lines = []
                    if added:
                        msg_lines.append(f"Added {len(added)} IPs")
                    if removed:
                        msg_lines.append(f"Removed {len(removed)} IPs")
                    send_ntfy_msg(ntfy_config, ", ".join(msg_lines), title="IP Access List Updated")

            except Exception as check_e:
                logger.warning(f"Could not verify existing IPs ({check_e}), forcing update.")

        # Prepare Payload
        clients = [{"address": ip, "directive": "allow"} for ip in ips]
            
        payload = {
            "name": name,
            "satisfy_any": True, 
            "pass_auth": False,
            "items": [],
            "clients": clients
        }

        try:
            if list_id:
                logger.info(f"Updating Access List ID: {list_id} with {len(clients)} IPs...")
                endpoint = f"{self.url}/api/nginx/access-lists/{list_id}"
                resp = self.session.put(endpoint, headers=self.get_headers(), json=payload)
            else:
                logger.info(f"Creating new Access List: {name} with {len(clients)} IPs...")
                endpoint = f"{self.url}/api/nginx/access-lists"
                resp = self.session.post(endpoint, headers=self.get_headers(), json=payload)
                
            if resp.status_code in [200, 201]:
                logger.info(f"SUCCESS: Access List '{name}' updated.")
            else:
                logger.error(f"Failed to update NPM. Status: {resp.status_code} Resp: {resp.text}")
                
        except Exception as e:
             logger.error(f"Exception during update: {e}")

def fetch_ips(ntfy_config=None):
    """Collects IPs from all configured sources."""
    collected_ips = {} 

    # 1. Geofeed Sources
    geofeed_config = load_config("Geofeed.config")
    if geofeed_config and geofeed_config.get('enabled', False):
        sources = geofeed_config.get('isp_sources', [])
        for source_entry in sources:
            # Handle both list and tuple formats from JSON (JSON uses lists)
            if len(source_entry) >= 4:
                name, url, filter_country, filter_region = source_entry[:4]
            elif len(source_entry) == 3:
                name, url, filter_country = source_entry[:3]
                filter_region = None
            else:
                logger.warning(f"Invalid Geofeed entry: {source_entry}")
                continue

            logger.info(f"Processing Geofeed: {name}...")
            csv_text = get_content_with_fallback(name, url, ntfy_config)
            
            if csv_text:
                try:
                    reader = csv.reader(io.StringIO(csv_text))
                    count = 0
                    for row in reader:
                        if len(row) < 3 or row[0].startswith('#'): continue
                        
                        ip, country, region = row[0].strip(), row[1].strip(), row[2].strip()

                        if filter_country and country != filter_country: continue
                        if filter_region and region != filter_region: continue
                        
                        try:
                            net = ipaddress.ip_network(ip, strict=False)
                            collected_ips[str(net)] = name 
                            count += 1
                        except ValueError: continue
                    logger.info(f"  -> Added {count} ranges")
                except Exception as e:
                    logger.error(f"Error parsing CSV {name}: {e}")

    # 2. ASN Search Logic
    search_config = load_config("ASNSearch.config")
    if search_config and search_config.get('enabled', False):
        search_rules = search_config.get('search_rules', [])
        scanner_threads = search_config.get('scanner_threads', 20)
        scanner_timeout = search_config.get('scanner_timeout', 2.0)
        
        if search_rules:
            logger.info("Processing ASN Scanner Rules...")
            
            # Organize rules by ASN
            asn_map = {}
            for rule in search_rules:
                if len(rule) < 3: continue
                asn, tag, pattern = rule
                if asn not in asn_map: asn_map[asn] = []
                asn_map[asn].append((tag, pattern))
                
            socket.setdefaulttimeout(scanner_timeout)
            
            for asn, rules in asn_map.items():
                prefixes = fetch_ripe_data(asn, ntfy_config)
                logger.info(f"  -> Scanning {asn} ({len(prefixes)} prefixes) with {len(rules)} rules...")
                
                found_count = 0
                with concurrent.futures.ThreadPoolExecutor(max_workers=scanner_threads) as executor:
                    future_to_cidr = {executor.submit(scan_cidr_for_hostname, cidr, rules): cidr for cidr in prefixes}
                    
                    for future in concurrent.futures.as_completed(future_to_cidr):
                        result = future.result()
                        if result:
                            cidr, tag, host = result
                            collected_ips[cidr] = tag
                            found_count += 1
                
                logger.info(f"  -> Finished {asn}. Found {found_count} matching subnets.")

    # 3. JSON Files (e.g., Google)
    json_files_config = load_config("jsonFiles.config")
    if json_files_config and json_files_config.get('enabled', False):
        logger.info("Processing JSON Sources...")
        json_items = json_files_config.get('items', [])
        
        for item in json_items:
            name = item.get('name', 'Unknown JSON')
            url = item.get('url')
            if not url: continue
            
            content = get_content_with_fallback(name, url, ntfy_config)
            if content:
                try:
                    data = json.loads(content)
                    count = 0
                    
                    # Logic for Google-style JSON (prefixes -> ipv4Prefix)
                    if isinstance(data, dict) and 'prefixes' in data:
                        for p in data.get('prefixes', []):
                            ip = p.get('ipv4Prefix') or p.get('ipv6Prefix')
                            if ip:
                                collected_ips[ip] = name
                                count += 1
                                
                    # Logic for simple IP list JSON (["1.2.3.4", "5.6.7.8"])
                    elif isinstance(data, list):
                        for ip in data:
                            try:
                                ipaddress.ip_network(ip, strict=False) # Validate
                                collected_ips[ip] = name
                                count += 1
                            except ValueError: pass
                            
                    logger.info(f"  -> Added {count} ranges from {name}")
                except Exception as e:
                    logger.error(f"Error parsing JSON {name}: {e}")

    # 4. Manual IP Ranges
    manual_config = load_config("ManualIPRanges.config")
    if manual_config and manual_config.get('enabled', False):
        logger.info("Processing Manual IP Ranges...")
        for ip in manual_config.get('manual_ip_ranges', []):
            collected_ips[ip] = "Manual Config"
    
    return collected_ips

# ==========================================
# MAIN EXECUTION
# ==========================================

if __name__ == "__main__":
    if not os.path.exists(CONFIG_DIR):
        logger.error(f"Config directory not found: {CONFIG_DIR}")
        logger.info("Please create the directory and populate the .config files.")
        sys.exit(1)

    # Load Mandatory NPM Config
    npm_config = load_config("NPM.config")
    if not npm_config:
        logger.error("Failed to load NPM.config. Exiting.")
        sys.exit(1)
        
    NPM_URL = npm_config.get('npm_url')
    NPM_USER = npm_config.get('npm_user')
    NPM_PASS = npm_config.get('npm_pass')
    ACCESS_LIST_NAME = npm_config.get('access_list_name', "Allowed_ISPs")

    if not all([NPM_URL, NPM_USER, NPM_PASS]):
        logger.error("Error: Missing required NPM fields in NPM.config")
        sys.exit(1)

    # Load Optional NTFY Config
    ntfy_config = load_config("NTFY.config")
    
    logger.info("Starting IP fetch and scan process...")
    ip_source_map = fetch_ips(ntfy_config)
    
    if not ip_source_map:
        logger.warning("No IPs found! Aborting update.")
        sys.exit(0)
        
    unique_ips_list = list(ip_source_map.keys())
    logger.info(f"Total unique IP ranges to import: {len(unique_ips_list)}")

    try:
        npm = NpmManager(NPM_URL, NPM_USER, NPM_PASS)
        npm.login()
        npm.update_access_list(ACCESS_LIST_NAME, unique_ips_list, source_map=ip_source_map, ntfy_config=ntfy_config)
    except Exception as e:
        logger.error(f"Script failed: {e}")