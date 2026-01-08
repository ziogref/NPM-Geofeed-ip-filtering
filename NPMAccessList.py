#!/usr/bin/env python3

import requests
import csv
import io
import json
import logging
import ipaddress
import sys

# ==========================================
# CONFIGURATION
# ==========================================

# Path to your secrets file
# On Unraid, the flash drive is mounted at /boot
# Example: "/boot/config/npm_secrets.json"
CONFIG_FILE = "/boot/config/npm_secrets.json" 

# Name of the Access List in NPM to create/update
ACCESS_LIST_NAME = "Allowed_ISPs"

# Your Source List (CSV based sources)
ISP_SOURCES = [
    ("Launtel", "https://residential.launtel.net.au/geofeed.csv", "AU", "AU-TAS"),
    ("Telstra.TAS", "https://geofeed.tools.telstra.net/geofeed.csv", "AU", "AU-TAS"),
    ("Telstra.VIC", "https://geofeed.tools.telstra.net/geofeed.csv", "AU", "AU-VIC"), 
    ("AussieBroadBand", "https://speed.aussiebroadband.com.au/abb-geo.csv", "AU", "AU-VIC"),
    ("Vocus.Dodo.Iprimus", "https://geofeed.tools.telstra.net/geofeed.csv", "AU", "AU-TAS"),
    ("Leaptel.TAS", "https://www.xi.com.au/geo/RFC8805.csv", "AU", "AU-TAS"),
    ("Leaptel.QLD", "https://www.xi.com.au/geo/RFC8805.csv", "AU", "AU- QLD"),
    # To do list
    # Check Vocus, Dodo and iPrimus use Telstra geofeed data
    # Optus
    # Flip Internet (Angela Walker)
    # Launtel CGNAT ipranges

]

# Google IP Ranges URL (JSON format)
# This includes all Google services including Google Home/Assistant
GOOGLE_IP_URL = "https://www.gstatic.com/ipranges/goog.json"

# Logging Configuration
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

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
        """Authenticate with NPM and get a bearer token."""
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
        """Find the ID of an access list by name."""
        endpoint = f"{self.url}/api/nginx/access-lists"
        response = self.session.get(endpoint, headers=self.get_headers())
        response.raise_for_status()
        lists = response.json()
        
        for item in lists:
            if item['name'] == name:
                return item['id'], item
        return None, None

    def update_access_list(self, name, ips):
        """Create or Update the access list with new IPs."""
        list_id, existing_data = self.get_access_list_id(name)
        
        # --- CHECK FOR CHANGES BEFORE UPDATING ---
        if list_id:
            try:
                # Fetch full details of the existing list to get clients
                # explicit expansion ensures 'clients' list is returned
                endpoint = f"{self.url}/api/nginx/access-lists/{list_id}"
                resp = self.session.get(endpoint, headers=self.get_headers(), params={"expand": "clients"})
                resp.raise_for_status()
                full_data = resp.json()
                
                # Debug raw count
                raw_clients = full_data.get('clients', [])
                logger.info(f"Existing Access List ID {list_id} found. Fetched {len(raw_clients)} existing clients from API.")

                # Extract and Normalize existing IPs for robust comparison
                current_ips = set()
                for c in raw_clients:
                    try:
                        # Normalize just like we do for the new list
                        # This handles "1.2.3.4" vs "1.2.3.4/32" mismatches
                        net = ipaddress.ip_network(c['address'], strict=False)
                        current_ips.add(str(net))
                    except ValueError:
                        # If NPM has garbage data, we keep the raw string to be safe
                        current_ips.add(c['address'])

                new_ips = set(ips)
                
                # Comparison Logic
                if current_ips == new_ips:
                    logger.info(f"NO CHANGES: Access List '{name}' is already up-to-date with {len(new_ips)} IPs. Skipping update.")
                    return
                
                # Calculate stats for the log
                added = new_ips - current_ips
                removed = current_ips - new_ips
                
                logger.info(f"CHANGES DETECTED: {len(added)} IPs to add, {len(removed)} IPs to remove.")
                
            except Exception as check_e:
                logger.warning(f"Could not verify existing IPs (Error: {check_e}), forcing update.")

        # --- FIXED PAYLOAD STRUCTURE ---
        # 'items' is for Users/Passwords
        # 'clients' is for IP Addresses
        
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
            "items": [],        # Must be empty array if no auth users
            "clients": clients  # This is where IPs go
        }

        # --- DEBUG OUTPUT ---
        logger.info(f"Preparing to send {len(clients)} IPs to NPM...")
        # --------------------

        try:
            if list_id:
                logger.info(f"Updating existing Access List ID: {list_id}")
                endpoint = f"{self.url}/api/nginx/access-lists/{list_id}"
                resp = self.session.put(endpoint, headers=self.get_headers(), json=payload)
            else:
                logger.info(f"Creating new Access List: {name}")
                endpoint = f"{self.url}/api/nginx/access-lists"
                resp = self.session.post(endpoint, headers=self.get_headers(), json=payload)
                
            if resp.status_code in [200, 201]:
                logger.info(f"SUCCESS: Updated Access List '{name}' with {len(ips)} IPs.")
            else:
                logger.error(f"Failed to update NPM. Status: {resp.status_code}")
                logger.error(f"Response: {resp.text}")
                
        except Exception as e:
             logger.error(f"Exception during update: {e}")

def fetch_ips():
    """Download and filter IPs from sources."""
    collected_ips = set()

    # 1. Fetch CSV Sources
    for name, url, filter_country, filter_region in ISP_SOURCES:
        logger.info(f"Processing {name}...")
        try:
            response = requests.get(url, timeout=10)
            response.raise_for_status()
            
            f = io.StringIO(response.text)
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
                    # Normalize the IP network string
                    net = ipaddress.ip_network(ip_prefix, strict=False)
                    collected_ips.add(str(net))
                    count += 1
                except ValueError:
                    continue
            
            logger.info(f"  - Found {count} matching ranges for {name}")

        except Exception as e:
            logger.error(f"Error processing {name}: {e}")

    # 2. Fetch Google IPs (JSON)
    logger.info("Processing Google IP Ranges...")
    try:
        response = requests.get(GOOGLE_IP_URL, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        google_count = 0
        prefixes = data.get('prefixes', [])
        
        for item in prefixes:
            # Google publishes both ipv4Prefix and ipv6Prefix keys
            # We check for both and add whichever exists
            ip_prefix = item.get('ipv4Prefix') or item.get('ipv6Prefix')
            
            if ip_prefix:
                try:
                    # Normalize the IP network string
                    net = ipaddress.ip_network(ip_prefix, strict=False)
                    collected_ips.add(str(net))
                    google_count += 1
                except ValueError:
                    continue
        
        logger.info(f"  - Added {google_count} Google IP ranges")

    except Exception as e:
        logger.error(f"Error processing Google IPs: {e}")
    
    return list(collected_ips)

# ==========================================
# MAIN EXECUTION
# ==========================================

if __name__ == "__main__":
    try:
        # Load Configuration from external file
        logger.info(f"Loading configuration from {CONFIG_FILE}...")
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = json.load(f)
                
            NPM_URL = config.get('npm_url')
            NPM_USER = config.get('npm_user')
            NPM_PASS = config.get('npm_pass')
            
            if not all([NPM_URL, NPM_USER, NPM_PASS]):
                logger.error("Error: Missing required fields (npm_url, npm_user, npm_pass) in config file.")
                sys.exit(1)
                
        except FileNotFoundError:
            logger.error(f"Error: Configuration file '{CONFIG_FILE}' not found.")
            sys.exit(1)
        except json.JSONDecodeError:
            logger.error(f"Error: Failed to parse '{CONFIG_FILE}'. Check JSON formatting.")
            sys.exit(1)

        logger.info("Starting IP fetch process...")
        unique_ips = fetch_ips()
        
        if not unique_ips:
            logger.warning("No IPs found! Aborting update.")
            exit()
            
        logger.info(f"Total unique IP ranges to import: {len(unique_ips)}")

        npm = NpmManager(NPM_URL, NPM_USER, NPM_PASS)
        npm.login()
        npm.update_access_list(ACCESS_LIST_NAME, unique_ips)

    except Exception as e:
        logger.error(f"Script failed: {e}")