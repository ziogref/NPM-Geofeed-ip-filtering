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
STATE_FILE = os.path.join(CACHE_DIR, "state.json")

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

def load_state():
    """Loads the previous run's IP-to-Source map."""
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        logger.error(f"Failed to load state file: {e}")
        return {}

def save_state(data):
    """Saves the current IP-to-Source map to file."""
    try:
        if not os.path.exists(CACHE_DIR):
            os.makedirs(CACHE_DIR)
        with open(STATE_FILE, 'w', encoding='utf-8') as f:
            json.dump(data, f)
    except Exception as e:
        logger.error(f"Failed to save state file: {e}")

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
        
        # Requests defaults to latin-1, so we encode to utf-8
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

def is_ip_version_enabled(network_obj, ipv4_enabled, ipv6_enabled):
    """Checks if the IP version of the network object is enabled in config."""
    if network_obj.version == 4 and ipv4_enabled:
        return True
    if network_obj.version == 6 and ipv6_enabled:
        return True
    return False

# ==========================================
# ASN Scanner
# ==========================================

def fetch_ripe_data(asn, ntfy_config=None, ipv4_enabled=True, ipv6_enabled=True):
    """Fetches prefixes for an ASN using RIPE API and filters by IP version."""
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
                try:
                    net = ipaddress.ip_network(prefix, strict=False)
                    if is_ip_version_enabled(net, ipv4_enabled, ipv6_enabled):
                        prefixes.append(prefix)
                except ValueError:
                    continue
        return prefixes
    except Exception as e:
        logger.error(f"Error parsing RIPE data for {asn}: {e}")
        return []

def scan_cidr_for_hostname(cidr, rules_for_this_asn):
    """
    Worker function: Checks the gateway of a CIDR against regex rules.
    Works for both IPv4 and IPv6 (Gateway assumed to be Network + 1).
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
        # Socket errors, DNS errors, or no PTR record found
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

    def _build_version_breakdown(self, ip_list, source_map, source_default="Unknown"):
        """
        Helper to tally IPs by Source and Version.
        Returns a dictionary: { SourceName: {'v4': count, 'v6': count} }
        """
        tally = {}
        for ip in ip_list:
            src = source_map.get(ip, source_default)
            if src not in tally: 
                tally[src] = {'v4': 0, 'v6': 0}
            
            try:
                ver = ipaddress.ip_network(ip, strict=False).version
                if ver == 4:
                    tally[src]['v4'] += 1
                elif ver == 6:
                    tally[src]['v6'] += 1
            except ValueError:
                pass
        return tally

    def generate_diff_report(self, added_ips, removed_ips, new_source_map, old_source_map):
        """Creates a formatted string detailing changes by source and version."""
        lines = []
        
        if added_ips:
            lines.append("Allowed (Added):")
            tally = self._build_version_breakdown(added_ips, new_source_map, "Unknown")
            
            for src, counts in sorted(tally.items()):
                parts = []
                if counts['v4'] > 0: parts.append(f"{counts['v4']} IPv4")
                if counts['v6'] > 0: parts.append(f"{counts['v6']} IPv6")
                lines.append(f"  + {src}: {', '.join(parts)}")

        if removed_ips:
            if lines: lines.append("") # Spacer
            lines.append("Blocked (Removed):")
            # Use old state to find where it came from
            tally = self._build_version_breakdown(removed_ips, old_source_map, "Unknown/Manual")
            
            for src, counts in sorted(tally.items()):
                parts = []
                if counts['v4'] > 0: parts.append(f"{counts['v4']} IPv4")
                if counts['v6'] > 0: parts.append(f"{counts['v6']} IPv6")
                lines.append(f"  - {src}: {', '.join(parts)}")
                
        return "\n".join(lines)

    def update_access_list(self, name, new_ips_list, new_source_map=None, old_source_map=None, ntfy_config=None):
        list_id, existing_data = self.get_access_list_id(name)
        
        # Calculate Differences
        current_ips = set()
        if list_id:
            try:
                endpoint = f"{self.url}/api/nginx/access-lists/{list_id}"
                resp = self.session.get(endpoint, headers=self.get_headers(), params={"expand": "clients"})
                resp.raise_for_status()
                full_data = resp.json()
                
                raw_clients = full_data.get('clients', [])
                for c in raw_clients:
                    try:
                        net = ipaddress.ip_network(c['address'], strict=False)
                        current_ips.add(str(net))
                    except ValueError:
                        current_ips.add(c['address'])
            except Exception as check_e:
                logger.warning(f"Could not verify existing IPs ({check_e}), forcing full update.")

        new_ips_set = set(new_ips_list)
        
        if current_ips == new_ips_set:
            logger.info(f"NO CHANGES: Access List '{name}' is up-to-date.")
            # Even if no changes to NPM, we ensure our state file is current
            save_state(new_source_map) 
            return

        added = new_ips_set - current_ips
        removed = current_ips - new_ips_set
        
        logger.info(f"CHANGES DETECTED: {len(added)} to add, {len(removed)} to remove.")

        # Prepare Payload
        clients = [{"address": ip, "directive": "allow"} for ip in new_ips_list]
            
        payload = {
            "name": name,
            "satisfy_any": True, 
            "pass_auth": False,
            "items": [],
            "clients": clients
        }

        try:
            # Perform Update
            if list_id:
                logger.info(f"Updating Access List ID: {list_id}...")
                endpoint = f"{self.url}/api/nginx/access-lists/{list_id}"
                resp = self.session.put(endpoint, headers=self.get_headers(), json=payload)
            else:
                logger.info(f"Creating new Access List: {name}...")
                endpoint = f"{self.url}/api/nginx/access-lists"
                resp = self.session.post(endpoint, headers=self.get_headers(), json=payload)
                
            if resp.status_code in [200, 201]:
                logger.info(f"SUCCESS: Access List '{name}' updated.")
                
                # Save the new state map only on success
                save_state(new_source_map)
                
                # Generate Report and Notify
                if ntfy_config and ntfy_config.get('enabled', False):
                    report = self.generate_diff_report(added, removed, new_source_map, old_source_map)
                    logger.info("Detailed Report:\n" + report)
                    send_ntfy_msg(ntfy_config, report, title="IP Access List Updated")
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
        ipv4_on = geofeed_config.get('ipv4', True)
        ipv6_on = geofeed_config.get('ipv6', True)
        
        sources = geofeed_config.get('isp_sources', [])
        for source_entry in sources:
            if len(source_entry) >= 4:
                name, url, filter_country, filter_region = source_entry[:4]
            elif len(source_entry) == 3:
                name, url, filter_country = source_entry[:3]
                filter_region = None
            else:
                continue

            logger.info(f"Processing Geofeed: {name} (IPv4={ipv4_on}, IPv6={ipv6_on})...")
            csv_text = get_content_with_fallback(name, url, ntfy_config)
            
            if csv_text:
                count_v4 = 0
                count_v6 = 0
                try:
                    reader = csv.reader(io.StringIO(csv_text))
                    for row in reader:
                        if len(row) < 3 or row[0].startswith('#'): continue
                        ip, country, region = row[0].strip(), row[1].strip(), row[2].strip()
                        if filter_country and country != filter_country: continue
                        if filter_region and region != filter_region: continue
                        
                        try:
                            net = ipaddress.ip_network(ip, strict=False)
                            if is_ip_version_enabled(net, ipv4_on, ipv6_on):
                                collected_ips[str(net)] = name 
                                if net.version == 4: count_v4 += 1
                                else: count_v6 += 1
                        except ValueError: continue
                    
                    if count_v4 > 0: logger.info(f"  -> Added {count_v4} IPv4 Ranges")
                    if count_v6 > 0: logger.info(f"  -> Added {count_v6} IPv6 Ranges")
                    
                except Exception as e:
                    logger.error(f"Error parsing CSV {name}: {e}")

    # 2. ASN Search Logic
    search_config = load_config("ASNSearch.config")
    if search_config and search_config.get('enabled', False):
        ipv4_on = search_config.get('ipv4', True)
        ipv6_on = search_config.get('ipv6', True)
        search_rules = search_config.get('search_rules', [])
        scanner_threads = search_config.get('scanner_threads', 20)
        scanner_timeout = search_config.get('scanner_timeout', 2.0)
        
        if search_rules:
            logger.info(f"Processing ASN Scanner Rules (IPv4={ipv4_on}, IPv6={ipv6_on})...")
            logger.info("NOTE: This process scans live gateways and may take some time depending on the number of prefixes. Please be patient.")
            
            asn_map = {}
            for rule in search_rules:
                if len(rule) < 3: continue
                asn, tag, pattern = rule
                if asn not in asn_map: asn_map[asn] = []
                asn_map[asn].append((tag, pattern))
                
            socket.setdefaulttimeout(scanner_timeout)
            
            for asn, rules in asn_map.items():
                prefixes = fetch_ripe_data(asn, ntfy_config, ipv4_enabled=ipv4_on, ipv6_enabled=ipv6_on)
                logger.info(f"  -> Scanning {asn} ({len(prefixes)} prefixes)...")
                
                found_v4 = 0
                found_v6 = 0
                
                with concurrent.futures.ThreadPoolExecutor(max_workers=scanner_threads) as executor:
                    future_to_cidr = {executor.submit(scan_cidr_for_hostname, cidr, rules): cidr for cidr in prefixes}
                    for future in concurrent.futures.as_completed(future_to_cidr):
                        result = future.result()
                        if result:
                            cidr, tag, host = result
                            collected_ips[cidr] = tag
                            try:
                                net = ipaddress.ip_network(cidr, strict=False)
                                if net.version == 4: found_v4 += 1
                                else: found_v6 += 1
                            except ValueError: pass
                
                if found_v4 > 0: logger.info(f"  -> Finished {asn}. Found {found_v4} IPv4 subnets.")
                if found_v6 > 0: logger.info(f"  -> Finished {asn}. Found {found_v6} IPv6 subnets.")
    
    # 3. JSON Files
    json_files_config = load_config("jsonFiles.config")
    if json_files_config and json_files_config.get('enabled', False):
        ipv4_on = json_files_config.get('ipv4', True)
        ipv6_on = json_files_config.get('ipv6', True)
        logger.info(f"Processing JSON Sources (IPv4={ipv4_on}, IPv6={ipv6_on})...")
        
        json_items = json_files_config.get('items', [])
        for item in json_items:
            name = item.get('name', 'Unknown JSON')
            url = item.get('url')
            if not url: continue
            content = get_content_with_fallback(name, url, ntfy_config)
            
            count_v4 = 0
            count_v6 = 0
            if content:
                try:
                    data = json.loads(content)
                    
                    # Google Style (keys: ipv4Prefix, ipv6Prefix)
                    if isinstance(data, dict) and 'prefixes' in data:
                        for p in data.get('prefixes', []):
                            if ipv4_on and 'ipv4Prefix' in p:
                                collected_ips[p['ipv4Prefix']] = name
                                count_v4 += 1
                            if ipv6_on and 'ipv6Prefix' in p:
                                collected_ips[p['ipv6Prefix']] = name
                                count_v6 += 1
                                
                    # Flat List Style (list of strings)
                    elif isinstance(data, list):
                        for ip in data:
                            try:
                                net = ipaddress.ip_network(ip, strict=False)
                                if is_ip_version_enabled(net, ipv4_on, ipv6_on):
                                    collected_ips[ip] = name
                                    if net.version == 4: count_v4 += 1
                                    else: count_v6 += 1
                            except ValueError: pass
                except Exception as e:
                    logger.error(f"Error parsing JSON {name}: {e}")
            
            if count_v4 > 0: logger.info(f"  -> Added {count_v4} IPv4 Ranges from {name}")
            if count_v6 > 0: logger.info(f"  -> Added {count_v6} IPv6 Ranges from {name}")

    # 4. Manual IP Ranges
    manual_config = load_config("ManualIPRanges.config")
    if manual_config and manual_config.get('enabled', False):
        ipv4_on = manual_config.get('ipv4', True)
        ipv6_on = manual_config.get('ipv6', True)
        logger.info(f"Processing Manual IP Ranges (IPv4={ipv4_on}, IPv6={ipv6_on})...")
        
        count_v4 = 0
        count_v6 = 0
        for ip in manual_config.get('manual_ip_ranges', []):
            try:
                net = ipaddress.ip_network(ip, strict=False)
                if is_ip_version_enabled(net, ipv4_on, ipv6_on):
                    collected_ips[ip] = "Manual Config"
                    if net.version == 4: count_v4 += 1
                    else: count_v6 += 1
            except ValueError:
                logger.warning(f"Invalid Manual IP: {ip}")
        
        if count_v4 > 0: logger.info(f"  -> Added {count_v4} IPv4 Ranges")
        if count_v6 > 0: logger.info(f"  -> Added {count_v6} IPv6 Ranges")
    
    return collected_ips

# ==========================================
# MAIN EXECUTION
# ==========================================

if __name__ == "__main__":
    if not os.path.exists(CONFIG_DIR):
        logger.error(f"Config directory not found: {CONFIG_DIR}")
        sys.exit(1)

    npm_config = load_config("NPM.config")
    if not npm_config:
        logger.error("Failed to load NPM.config. Exiting.")
        sys.exit(1)
        
    NPM_URL = npm_config.get('npm_url')
    NPM_USER = npm_config.get('npm_user')
    NPM_PASS = npm_config.get('npm_pass')
    ACCESS_LIST_NAME = npm_config.get('access_list_name', "Allowed_ISPs")

    if not all([NPM_URL, NPM_USER, NPM_PASS]):
        logger.error("Error: Missing required NPM fields.")
        sys.exit(1)

    ntfy_config = load_config("NTFY.config")
    
    logger.info("Starting IP fetch and scan process...")
    
    # Load previous state (History of who owned which IP)
    previous_state_map = load_state()
    
    # Fetch current data
    ip_source_map = fetch_ips(ntfy_config)
    
    if not ip_source_map:
        logger.warning("No IPs found! Aborting update.")
        sys.exit(0)
        
    unique_ips_list = list(ip_source_map.keys())
    logger.info(f"Total unique IP ranges to import: {len(unique_ips_list)}")

    try:
        npm = NpmManager(NPM_URL, NPM_USER, NPM_PASS)
        npm.login()
        npm.update_access_list(
            name=ACCESS_LIST_NAME, 
            new_ips_list=unique_ips_list, 
            new_source_map=ip_source_map, 
            old_source_map=previous_state_map, 
            ntfy_config=ntfy_config
        )
    except Exception as e:
        logger.error(f"Script failed: {e}")