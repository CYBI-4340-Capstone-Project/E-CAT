#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Sat Mar 29 22:26:59 2025

@author: jesus_delarosa_cyber
"""

import pandas as pd
from url_feature_extractor import url_detect_feature_extract

def extract_training_features(legit_csv, malicious_csv, output_file):
    """Process datasets and extract features for training"""
    print("\nExtracting features from datasets...")
    try:
        # Load datasets
        legit_df = pd.read_csv(legit_csv)
        malicious_df = pd.read_csv(malicious_csv, skiprows=8, header=None, names=['url'])
        
        print(f"Found {len(legit_df)} legitimate and {len(malicious_df)} malicious URLs")
        
        # Extract features
        print("Processing legitimate URLs...")
        legit_features = [url_detect_feature_extract(url) for url in legit_df['url']]
        
        print("Processing malicious URLs...")
        malicious_features = [url_detect_feature_extract(url) for url in malicious_df['url']]
        
        # Create DataFrames
        feature_columns = list(url_detect_feature_extract("https://example.com").keys())
        legit_df = pd.DataFrame(legit_features, columns=feature_columns)
        malicious_df = pd.DataFrame(malicious_features, columns=feature_columns)
        
        # Add labels and combine
        legit_df['label'] = 0
        malicious_df['label'] = 1
        combined_df = pd.concat([legit_df, malicious_df], ignore_index=True)
        
        # Save to parquet
        combined_df.to_parquet(output_file)
        print(f"\nSuccessfully extracted {len(combined_df)} samples")
        print(f"Features saved to {output_file}")
        
    except Exception as e:
        print(f"\nFeature extraction failed: {str(e)}")

if __name__ == "__main__":
    extract_training_features(
        legit_csv='legit.csv',
        malicious_csv='malicious.csv',
        output_file='training_features.parquet'
    )