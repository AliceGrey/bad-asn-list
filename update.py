#!/usr/bin/env python3
import csv
import json
import os
import time
import urllib.request
import urllib.error

asns = []
asn_list = []
ASN_FILE = 'bad-asn-list.csv'
ASN_JSON = 'bad-asn-list.json'
NEW_ASN_FILE = 'bad-asn-list.csv.1'
ASN_NUMBERS_FILE = 'only number.txt'
NEW_NAUGHTY_ASNS_FILE = 'newNaughtyAsns.txt'

def import_csv(file_path):
    """Import ASNs from a CSV file"""
    with open(file_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            asn = int(row['ASN'])
            if asn not in asns:
                asns.append(asn)
                asn_list.append({
                    'ASN': asn,
                    'Entity': row['Entity']
                })

def lookup_asn_hackertarget(asn_number):
    """Look up ASN information using HackerTarget API"""
    try:
        url = f'https://api.hackertarget.com/aslookup/?q=AS{asn_number}'
        with urllib.request.urlopen(url, timeout=10) as response:
            data = response.read().decode('utf-8').strip()
        
        if data and not data.startswith('error'):
            lines = data.split('\n')
            if lines:
                parts = lines[0].split(',')
                if len(parts) >= 4:
                    return parts[3].strip().strip('"')
                elif len(parts) >= 2:
                    return ','.join(parts[1:]).strip().strip('"')
        
        return f"ASN {asn_number}"
    
    except urllib.error.HTTPError as e:
        print(f"HTTP Error looking up ASN {asn_number}: {e.code}")
        return f"ASN {asn_number} - Lookup Failed"
    except urllib.error.URLError as e:
        print(f"URL Error looking up ASN {asn_number}: {e.reason}")
        return f"ASN {asn_number} - Lookup Failed"
    except Exception as e:
        print(f"Error looking up ASN {asn_number}: {e}")
        return f"ASN {asn_number} - Lookup Failed"

def process_new_naughty_asns():
    """Read new ASNs from file, look them up if needed, and add to list"""
    if not os.path.exists(NEW_NAUGHTY_ASNS_FILE):
        print(f"No {NEW_NAUGHTY_ASNS_FILE} file found, skipping...")
        return
    
    print(f"Processing new naughty ASNs from {NEW_NAUGHTY_ASNS_FILE}...")
    
    with open(NEW_NAUGHTY_ASNS_FILE, 'r') as f:
        new_asns = [line.strip() for line in f if line.strip()]
    
    added_count = 0
    for asn_str in new_asns:
        try:
            asn_number = int(asn_str)
            
            if asn_number in asns:
                print(f"ASN {asn_number} already exists, skipping...")
                continue
            
            print(f"Looking up ASN {asn_number}...")
            entity = lookup_asn_hackertarget(asn_number)
            
            asns.append(asn_number)
            asn_list.append({'ASN': asn_number, 'Entity': entity})
            
            print(f"Added ASN {asn_number}: {entity}")
            added_count += 1
            
            time.sleep(1)  # Be nice to the API
            
        except ValueError:
            print(f"Invalid ASN number: {asn_str}")
    
    print(f"Added {added_count} new ASNs")

def write_output_files():
    """Write all output files"""
    # Write JSON
    with open(ASN_JSON, 'w') as f:
        json.dump(asn_list, f, indent=2)
    
    # Write CSV
    with open(ASN_FILE, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=['ASN', 'Entity'])
        writer.writeheader()
        writer.writerows(asn_list)
    
    # Write numbers file
    with open(ASN_NUMBERS_FILE, 'w') as f:
        f.write('\n'.join(str(a['ASN']) for a in asn_list) + '\n')
    
    print('Wrote new CSV, JSON, and numbers file')

def start():
    global asn_list
    
    # Load existing CSV
    original_count = 0
    if os.path.exists(ASN_FILE):
        with open(ASN_FILE, 'r') as f:
            original_count = sum(1 for line in f) - 1  # Subtract header
        import_csv(ASN_FILE)
    
    # Process new naughty ASNs
    process_new_naughty_asns()
    
    # Process additional CSV file if it exists
    if os.path.exists(NEW_ASN_FILE):
        import_csv(NEW_ASN_FILE)
    
    # Sort and write
    asn_list = sorted(asn_list, key=lambda x: x['ASN'])
    
    print(f'Original CSV Length: {original_count}')
    print(f'New CSV Length: {len(asn_list)}')
    
    write_output_files()

if __name__ == '__main__':
    start()
