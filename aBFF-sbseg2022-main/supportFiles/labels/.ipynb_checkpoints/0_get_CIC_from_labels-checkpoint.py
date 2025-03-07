#----------------------------------------------------------------------------------------
#
#                                      CIC_labels.py
#
#
#
# Discription:
# Format CIC label files for subsequent use
#-----------------------------------------------------------------------------------------

import os
import pandas as pd
import codecs
import warnings

warnings.filterwarnings('ignore')

def _to_utf8(filename: str, encoding="latin1", blocksize=1048576):
    tmpfilename = filename + ".tmp"
    with codecs.open(filename, "r", encoding) as source:
        with codecs.open(tmpfilename, "w", "utf-8") as target:
            while True:
                contents = source.read(blocksize)
                if not contents:
                    break
                target.write(contents)
    os.remove(filename)
    # Replace the original file
    os.rename(tmpfilename, filename)

def _renaming_class_label(df: pd.DataFrame):
    labels = {"Web Attack \x96 Brute Force": "Web Attack-Brute Force",
              "Web Attack \x96 XSS": "Web Attack-XSS",
              "Web Attack \x96 Sql Injection": "Web Attack-Sql Injection"}

    for old_label, new_label in labels.items():
        df.Label.replace(old_label, new_label, inplace=True)

def process_thursday_file():
    filepath = "./"
    dataset_path = "./"
    
    # File to process
    file_name = "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
    full_path = os.path.join(filepath, file_name)
    
    # Convert to UTF-8
    _to_utf8(full_path)
    
    # Read dataset
    df = pd.read_csv(full_path, skipinitialspace=True, on_bad_lines='skip')
    
    # Show number of NaN rows
    print("Removing {} rows that contain only NaN values...".format(df[df.isna().all(axis=1)].shape[0]))
    
    # Remove NaN rows
    df = df[~df.isna().all(axis=1)]
    
    # Renaming labels
    _renaming_class_label(df)
    
    # Save to csv
    output_file = os.path.join(dataset_path, file_name)
    print(f"Saving {output_file} to {dataset_path}")
    df.to_csv(output_file, index=False, header=True)

def combine_dataset():
    DIR_PATH = "./"
    FILE_NAMES = ["Monday-WorkingHours.pcap_ISCX.csv",
                  "Tuesday-WorkingHours.pcap_ISCX.csv",
                  "Wednesday-workingHours.pcap_ISCX.csv",
                  "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv",
                  "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
                  "Friday-WorkingHours-Morning.pcap_ISCX.csv",
                  "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
                  "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"]
    
    # Read and concatenate all files
    df = [pd.read_csv(os.path.join(DIR_PATH, f), skipinitialspace=True) for f in FILE_NAMES]
    df = pd.concat(df, ignore_index=True)
    
    # Show label counts
    print(df.Label.value_counts())
    
    # Save combined dataset to csv
    output_file = os.path.join(DIR_PATH, "TrafficLabelling.csv")
    print(f"Saving {output_file} to {DIR_PATH}")
   _csv(output_file, index=False)

if __name__ == "__main__":
    process_thursday_file()
    combine_dataset()