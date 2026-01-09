#!/usr/bin/env python3

import requests
import csv
import io
import json
import logging
import ipaddress
import sys
import os
import re  # Added for error string parsing

# ==========================================
# CONFIGURATION
# ==========================================

# Path to your secrets file
CONFIG_FILE = "/boot/config/npm_secrets.json" 

# Directory to store cached geofeed files (Persistent on Unraid)
CACHE_DIR = "/boot/config/npm_cache"

# Name of the Access List in NPM to create/update
ACCESS_LIST_NAME = "Allowed_ISPs"

# Enable NTFY Notifications (True/False)
ENABLE_NTFY = True

# Your Source List (CSV based sources)
# Format: ("Name", "URL", "CountryCode", "RegionCode")
ISP_SOURCES = [
    ("Launtel", "https://residential.launtel.net.au/geofeed.csv", "AU", "AU-TAS"),
    ("Telstra.TAS", "https://geofeed.tools.telstra.net/geofeed.csv", "AU", "AU-TAS"),
    ("Telstra.VIC", "https://geofeed.tools.telstra.net/geofeed.csv", "AU", "AU-VIC"), 
    ("AussieBroadBand", "https://speed.aussiebroadband.com.au/abb-geo.csv", "AU", "AU-VIC"),
    ("Leaptel.TAS", "https://www.xi.com.au/geo/RFC8805.csv", "AU", "AU-TAS"),
    ("Flip Connect", "https://flipconnect.com.au/api/csv/flip-au-geo-feed-20240626.csv", "AU", "AU-VIC"),
    ("Leaptel.QLD", "https://www.xi.com.au/geo/RFC8805.csv", "AU", "AU-QLD"),
]

# Google IP Ranges URL (JSON format)
GOOGLE_IP_URL = "https://www.gstatic.com/ipranges/goog.json"

# Manual IP Ranges to always allow
MANUAL_IP_RANGES = [
     "100.64.0.0/10",
     "10.0.0.0/8",
     "192.168.100.0/24",
     "192.168.167.0/24",
     "192.168.7.0/24",
]

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# ==========================================
# HELPERS
# ==========================================

def send_ntfy_msg(ntfy_config, message, title):
    """Standalone function to send NTFY messages with Title and Tags."""
    if not ntfy_config:
        return

    try:
        url = f"{ntfy_config['url']}/{ntfy_config['topic']}"
        headers = {
            "Title": f"NPM | {title}",
            "Tags": "warning"  # 'warning' tag applied to ALL messages
        }
        
        if ntfy_config.get('token'):
            headers["Authorization"] = f"Bearer {ntfy_config['token']}"
        
        # logger.info(f"Sending NTFY: {title}")
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
    # Ensure cache directory exists
    if not os.path.exists(CACHE_DIR):
        try:
            os.makedirs(CACHE_DIR)
        except OSError as e:
            logger.error(f"Could not create cache directory {CACHE_DIR}: {e}")

    # Create a safe filename
    safe_name = "".join([c for c in name if c.isalpha() or c.isdigit() or c in (' ', '-', '_')]).strip().replace(" ", "_")
    cache_path = os.path.join(CACHE_DIR, f"{safe_name}.cache")

    try:
        # Attempt Download
        response = requests.get(url, timeout=15)
        response.raise_for_status()
        
        content = response.text
        
        # Save to cache
        with open(cache_path, 'w', encoding='utf-8') as f:
            f.write(content)
            
        return content

    except Exception as e:
        raw_error = str(e)
        logger.error(f"Failed to fetch {name}: {raw_error}")
        
        # --- Simplify Error Message for NTFY ---
        clean_error = "Connection Failed" # Default
        
        # Check for DNS Resolution errors
        # Matches: "Failed to resolve 'hostname'" inside the messy exception text
        dns_match = re.search(r"Failed to resolve '([^']+)'", raw_error)
        
        if dns_match:
            clean_error = f"Failed to resolve {dns_match.group(1)}"
        elif "Name or service not known" in raw_error:
            clean_error = "DNS Error: Name unknown"
        elif "404" in raw_error:
            clean_error = "HTTP 404 (Not Found)"
        elif "500" in raw_error:
            clean_error = "HTTP 500 (Server Error)"
        elif "502" in raw_error or "503" in raw_error:
            clean_error = "HTTP Server Error"
        elif "ConnectTimeout" in raw_error:
            clean_error = "Connection Timeout"
        elif "Connection refused" in raw_error:
             clean_error = "Connection Refused"
        
        # Notify about the failure
        if ntfy_config:
            ntfy_msg = f"{name} | {clean_error} | Using last known geofeed file"
            send_ntfy_msg(ntfy_config, ntfy_msg, title="Geofeed Download Failed")

        # Fallback to cache
        if os.path.exists(cache_path):
            logger.warning(f"Falling back to cached file for {name}...")
            try:
                with open(cache_path, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception as cache_e:
                logger.error(f"Failed to read cache for {name}: {cache_e}")
                return None
        else:
            logger.error(f"No cached file found for {name}. Skipping source.")
            return None

# ==========================================
# LOGIC
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
            data = response.json()
            self.token = data['token']
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
        lists = response.json()
        
        for item in lists:
            if item['name'] == name:
                return item['id'], item
        return None, None

    def update_access_list(self, name, ips, source_map=None, ntfy_config=None):
        list_id, existing_data = self.get_access_list_id(name)
        
        # --- CHECK FOR CHANGES BEFORE UPDATING ---
        if list_id:
            try:
                endpoint = f"{self.url}/api/nginx/access-lists/{list_id}"
                resp = self.session.get(endpoint, headers=self.get_headers(), params={"expand": "clients"})
                resp.raise_for_status()
                full_data = resp.json()
                
                raw_clients = full_data.get('clients', [])
                logger.info(f"Existing Access List ID {list_id} found. Fetched {len(raw_clients)} existing clients.")

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
                
                logger.info(f"CHANGES DETECTED: {len(added)} IPs to add, {len(removed)} IPs to remove.")

                if added:
                    logger.info("--- IPs Identifying for ADDITION ---")
                    for ip in sorted(added):
                        src = source_map.get(ip, 'Unknown') if source_map else 'Unknown'
                        logger.info(f" [+] {ip} (Source: {src})")

                if removed:
                    logger.info("--- IPs Identifying for REMOVAL ---")
                    for ip in sorted(removed):
                        logger.info(f" [-] {ip}")
                
                if ntfy_config and (added or removed):
                    # Determine Dynamic Title based on action
                    if added and removed:
                        msg_title = "IPs Added & Removed"
                    elif added:
                        msg_title = "IPs Added"
                    else:
                        msg_title = "IPs Removed"

                    msg_lines = []
                    if added:
                        msg_lines.append("Address Added:")
                        for ip in sorted(added):
                            src = source_map.get(ip, 'Unknown') if source_map else 'Unknown'
                            msg_lines.append(f"+ {ip} ({src})")
                    if removed:
                        if added: msg_lines.append("") # Spacer
                        msg_lines.append("Address Removed:")
                        for ip in sorted(removed):
                            msg_lines.append(f"- {ip}")
                    
                    send_ntfy_msg(ntfy_config, "\n".join(msg_lines), title=msg_title)

            except Exception as check_e:
                logger.warning(f"Could not verify existing IPs (Error: {check_e}), forcing update.")

        # --- PREPARE PAYLOAD ---
        clients = []
        for ip in ips:
            clients.append({
                "address": ip,
                "directive": "allow"
            })
            
        payload = {
            "name": name,
            "satisfy_any": True, 
            "pass_auth": False,
            "items": [],
            "clients": clients
        }

        logger.info(f"Preparing to send {len(clients)} IPs to NPM...")

        try:
            if list_id:
                logger.info(f"Updating existing Access List ID: {list_id}")
                logger.info("Sending update to NPM... this can take up to 60 seconds, please wait.")
                endpoint = f"{self.url}/api/nginx/access-lists/{list_id}"
                resp = self.session.put(endpoint, headers=self.get_headers(), json=payload)
            else:
                logger.info(f"Creating new Access List: {name}")
                endpoint = f"{self.url}/api/nginx/access-lists"
                resp = self.session.post(endpoint, headers=self.get_headers(), json=payload)
                
            if resp.status_code in [200, 201]:
                logger.info(f"SUCCESS: Updated Access List '{name}' with {len(ips)} IPs.")
            else:
                logger.error(f"Failed to update NPM. Status: {resp.status_code} Response: {resp.text}")
                
        except Exception as e:
             logger.error(f"Exception during update: {e}")

def fetch_ips(ntfy_config=None):
    """Download IPs and return a dictionary of {IP: Source_Name}."""
    collected_ips = {} 

    # 1. Fetch CSV Sources
    for source_entry in ISP_SOURCES:
        # Safe Unpacking
        if len(source_entry) == 4:
            name, url, filter_country, filter_region = source_entry
        elif len(source_entry) == 3:
            name, url, filter_country = source_entry
            filter_region = None 
        else:
            logger.warning(f"Skipping malformed source entry: {source_entry}")
            continue

        logger.info(f"Processing {name}...")
        
        # Fetch with caching, fallback, and ntfy error alerts
        csv_text = get_content_with_fallback(name, url, ntfy_config)
        
        if not csv_text:
            continue 

        try:
            f = io.StringIO(csv_text)
            reader = csv.reader(f)
            
            count = 0
            for row in reader:
                if len(row) < 3: continue
                if row[0].startswith('#'): continue

                ip_prefix = row[0].strip()
                country = row[1].strip()
                region = row[2].strip()

                if filter_country and country != filter_country: continue
                if filter_region and region != filter_region: continue
                
                try:
                    net = ipaddress.ip_network(ip_prefix, strict=False)
                    collected_ips[str(net)] = name 
                    count += 1
                except ValueError:
                    continue
            
            logger.info(f"  - Found {count} ranges for {name}")

        except Exception as e:
            logger.error(f"Error parsing CSV for {name}: {e}")

    # 2. Fetch Google IPs (JSON)
    logger.info("Processing Google IP Ranges...")
    google_json_text = get_content_with_fallback("Google_Services", GOOGLE_IP_URL, ntfy_config)
    
    if google_json_text:
        try:
            data = json.loads(google_json_text)
            
            google_count = 0
            prefixes = data.get('prefixes', [])
            
            for item in prefixes:
                ip_prefix = item.get('ipv4Prefix') or item.get('ipv6Prefix')
                if ip_prefix:
                    try:
                        net = ipaddress.ip_network(ip_prefix, strict=False)
                        collected_ips[str(net)] = "Google"
                        google_count += 1
                    except ValueError:
                        continue
            
            logger.info(f"  - Added {google_count} Google IP ranges")
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing Google JSON: {e}")

    # 3. Add Manual IPs
    logger.info("Processing Manual IP Ranges...")
    for ip in MANUAL_IP_RANGES:
        try:
            net = ipaddress.ip_network(ip.strip(), strict=False)
            collected_ips[str(net)] = "Manual Config"
        except ValueError as e:
            logger.error(f"Invalid manual IP format '{ip}': {e}")
    
    return collected_ips

# ==========================================
# MAIN EXECUTION
# ==========================================

if __name__ == "__main__":
    ntfy_settings = None
    
    try:
        logger.info(f"Loading configuration from {CONFIG_FILE}...")
        with open(CONFIG_FILE, 'r') as f:
            config = json.load(f)
            
        NPM_URL = config.get('npm_url')
        NPM_USER = config.get('npm_user')
        NPM_PASS = config.get('npm_pass')
        
        if not all([NPM_URL, NPM_USER, NPM_PASS]):
            logger.error("Error: Missing required NPM fields in config file.")
            sys.exit(1)

        if ENABLE_NTFY:
            ntfy_url = config.get('ntfy_url')
            ntfy_topic = config.get('ntfy_topic')
            ntfy_token = config.get('ntfy_token') 
            
            if ntfy_url and ntfy_topic:
                ntfy_settings = {
                    'url': ntfy_url.rstrip('/'),
                    'topic': ntfy_topic,
                    'token': ntfy_token
                }
            else:
                logger.warning("NTFY enabled but missing details in secrets.")

    except Exception as e:
        logger.error(f"Configuration Error: {e}")
        sys.exit(1)

    logger.info("Starting IP fetch process...")
    
    # Pass ntfy_settings to fetch_ips for error notifications
    ip_source_map = fetch_ips(ntfy_settings)
    
    if not ip_source_map:
        logger.warning("No IPs found! Aborting update.")
        exit()
        
    unique_ips_list = list(ip_source_map.keys())
    logger.info(f"Total unique IP ranges to import: {len(unique_ips_list)}")

    try:
        npm = NpmManager(NPM_URL, NPM_USER, NPM_PASS)
        npm.login()
        npm.update_access_list(ACCESS_LIST_NAME, unique_ips_list, source_map=ip_source_map, ntfy_config=ntfy_settings)
    except Exception as e:
        logger.error(f"Script failed: {e}")