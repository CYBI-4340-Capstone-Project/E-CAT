import pandas as pd
from sklearn.preprocessing import StandardScaler

def preprocess_data(input_csv, output_csv):
    """
    Preprocesses the data by scaling numerical features.
    """
    df = pd.read_csv(input_csv)
    scaler = StandardScaler()
    numerical_features = df.select_dtypes(include=['int64', 'float64']).columns
    df[numerical_features] = scaler.fit_transform(df[numerical_features])
    df.to_csv(output_csv, index=False)
    print(f"Preprocessed data saved to {output_csv}")

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Preprocess extracted features.")
    parser.add_argument("-i", "--input", required=True, help="Input CSV file")
    parser.add_argument("-o", "--output", required=True, help="Output CSV file")
    args = parser.parse_args()

    preprocess_data(args.input, args.output)