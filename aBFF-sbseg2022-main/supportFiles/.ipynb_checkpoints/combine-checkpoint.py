import pandas as pd
import os
from myFunc import FEATURE_TYPES, zeroVarRead

def process_and_append(file_path, zero_var_features, combined_file, chunk_size=50000):
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

        # Optional: Convert Label to lower case for consistency
        chunk['Label'] = chunk['Label'].str.strip().str.lower()

        # Append to the combined dataset
        chunk.to_parquet(combined_file, engine='pyarrow', index=False, compression='snappy', append=True)


def combine_datasets(input_files, combined_file):
    """
    Combine multiple datasets into one efficient Parquet file.
    """

    # Remove combined file if it already exists
    if os.path.exists(combined_file):
        os.remove(combined_file)

    for file_path in input_files:
        print(f"Processing {file_path}")
            # Load zero variance features (assuming from first dataset)
        x = 1
        zero_var_features = zeroVarRead(x)
        x += 1
        process_and_append(file_path, zero_var_features, combined_file)

    print(f"Combined dataset saved to {combined_file}")


# Example usage
input_files = [
    './dataset/final/BoT-IoT_CIC.csv',
    './dataset/final/CIC-IDS_CIC.csv',
    './dataset/final/NB15_CIC.csv',
    './dataset/final/ToN-IoT_CIC.csv'
]

combined_file = './dataset/final/combined_dataset.parquet'
combine_datasets(input_files, combined_file)
