#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Mar 29 22:26:59 2025

@author: jesus_delarosa_cyber
"""


import requests
import os

def update_malicious_csv():
    """Update malicious URLs from URLhaus"""
    CSV_URL = "https://urlhaus.abuse.ch/downloads/text/"
    OUTPUT_FILE = "malicious.csv"
    
    try:
        print("Downloading latest malicious URLs from URLhaus...")
        response = requests.get(CSV_URL, timeout=30)
        response.raise_for_status()
        
        # Process new URLs (skip first 8 header rows)
        new_urls = {line.strip() for line in response.text.splitlines()[8:] if line.strip()}
        
        # Load existing URLs
        existing_urls = set()
        if os.path.exists(OUTPUT_FILE):
            with open(OUTPUT_FILE, 'r') as f:
                existing_urls = {line.strip() for line in f if line.strip()}
        
        # Merge and save
        added_count = len(new_urls - existing_urls)
        if added_count > 0:
            with open(OUTPUT_FILE, 'w') as f:
                for url in existing_urls.union(new_urls):
                    f.write(f"{url}\n")
            print(f"Added {added_count} new malicious URLs (Total: {len(existing_urls.union(new_urls))}")
        else:
            print("No new malicious URLs found")
            
    except Exception as e:
        print(f"Error updating malicious URLs: {str(e)}")

if __name__ == "__main__":
    update_malicious_csv()