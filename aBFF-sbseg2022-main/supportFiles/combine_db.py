import pandas as pd
import os
from myFunc import FEATURE_TYPES, zeroVarRead, zeroVarWrite

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

def process_and_append(file_path, zero_var_features, writer, chunk_size=50000):
    """
    Process a single CSV file in chunks and append it to the combined dataset.
    """
    chunk_iter = pd.read_csv(
        file_path,
        dtype=FEATURE_TYPES,
        chunksize=chunk_size
    )

    for chunk in chunk_iter:
        # Drop zero variance features and unnecessary ID columns early
        chunk.drop(columns=[col for col in zero_var_features if col in chunk.columns], errors='ignore', inplace=True)

        # Drop rows with NaN in essential columns
        chunk.dropna(subset=['Label'], inplace=True)

        # Standardize labels
        chunk['Label'] = chunk['Label'].str.strip().str.lower().map(LABEL_MAPPING).fillna(chunk['Label'])

        # Write or append data
        chunk.to_csv(writer, mode='a', header=writer.tell()==0, index=False)

def combine_datasets(input_files, combined_file):
    """
    Combine multiple datasets into one efficient CSV file.
    """

    # Remove combined file if it already exists
    if os.path.exists(combined_file):
        print(f"Removing existing combined file: {combined_file}")
        os.remove(combined_file)

    with open(combined_file, 'w') as writer:
        for idx, file_path in enumerate(input_files, start=1):
            print(f"Processing {file_path}")
            # Load zero variance features for the current dataset type
            zero_var_features = zeroVarRead(idx)
            process_and_append(file_path, zero_var_features, writer)

    print(f"Combined dataset saved to {combined_file}")


# Example usage
input_files = [
    './dataset/final/NB15_CIC.csv',
    './dataset/final/CIC-IDS_CIC.csv',
    './dataset/final/ToN-IoT_CIC.csv',
    './dataset/final/BoT-IoT_CIC.csv'
]

combined_file = './dataset/final/combined_dataset.csv'
combine_datasets(input_files, combined_file)