import pandas as pd
import os
import pyarrow as pa
import pyarrow.parquet as pq
from myFunc import FEATURE_TYPES, zeroVarRead

# Define a mapping for standardizing labels
LABEL_MAPPING = {
    'benign': 'benign',
    'Benign': 'benign',
    'BENIGN': 'benign',
    'DoS': 'dos',
    'dos': 'dos',
    'DoS Hulk': 'dos',
    'DoS GoldenEye': 'dos',
    'DoS slowloris': 'dos',
    'DoS Slowhttptest': 'dos',
    'DDoS': 'ddos',
    'ddos': 'ddos',
    'Reconnaissance': 'reconnaissance',
    'reconnaissance': 'reconnaissance',
    'PortScan': 'portscan',
    'xss': 'xss',
    'password': 'password',
    'injection': 'injection',
    'scanning': 'scanning',
    'backdoor': 'backdoor',
    'ransomware': 'ransomware',
    'mitm': 'mitm',
    'FTP-Patator': 'ftp-patator',
    'SSH-Patator': 'ssh-patator',
    'Bot': 'bot',
    'Web Attack  Brute Force': 'web-attack-brute-force',
    'Web Attack  XSS': 'web-attack-xss',
    'Web Attack  Sql Injection': 'web-attack-sql-injection',
    'Infiltration': 'infiltration',
    'Heartbleed': 'heartbleed',
    'Exploits': 'exploits',
    'Fuzzers': 'fuzzers',
    'Generic': 'generic',
    'Shellcode': 'shellcode',
    'Analysis': 'analysis',
    'Backdoor': 'backdoor',
    'Worms': 'worms',
    'Backdoors': 'backdoors',
    'Theft': 'theft'
}

def process_and_save(file_path, zero_var_features, combined_file, first_file):
    """
    Process a CSV file and save it to a Parquet file.
    """
    df = pd.read_csv(file_path, dtype=FEATURE_TYPES)

    # Drop zero variance features
    df.drop(columns=[col for col in zero_var_features if col in df.columns], errors='ignore', inplace=True)

    # Drop rows with NaN in essential columns
    df.dropna(subset=['Label'], inplace=True)

    # Standardize labels
    df['Label'] = df['Label'].str.strip().str.lower().map(LABEL_MAPPING).fillna(df['Label'])

    # Save to Parquet file
    df.to_parquet(combined_file, engine='pyarrow', index=False, compression='snappy', append=not first_file)

def combine_datasets(input_files, combined_file):
    """
    Combine multiple datasets into one efficient Parquet file.
    """
    # Remove combined file if it already exists
    if os.path.exists(combined_file):
        print(f"Removing existing combined file: {combined_file}")
        os.remove(combined_file)

    for idx, file_path in enumerate(input_files, start=1):
        print(f"Processing {file_path}")
        zero_var_features = zeroVarRead(idx)
        process_and_save(file_path, zero_var_features, combined_file, first_file=(idx == 1))

    print(f"Combined dataset saved to {combined_file}")

# Example usage
input_files = [
    './dataset/final/NB15_CIC.csv',
    './dataset/final/CIC-IDS_CIC.csv',
    './dataset/final/ToN-IoT_CIC.csv',
    './dataset/final/BoT-IoT_CIC.csv'
]

combined_file = './dataset/final/combined_dataset.parquet'
combine_datasets(input_files, combined_file)