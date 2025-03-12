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
import shutil
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
    os.rename(tmpfilename, filename)

def _renaming_class_label(df: pd.DataFrame):
    labels = {"Web Attack \x96 Brute Force": "Web Attack-Brute Force",
              "Web Attack \x96 XSS": "Web Attack-XSS",
              "Web Attack \x96 Sql Injection": "Web Attack-Sql Injection"}
    df.Label.replace(labels, inplace=True)

def process_thursday_file():
    filepath = "./labels"
    file_name = "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
    full_path = os.path.join(filepath, file_name)
    _to_utf8(full_path)
    df = pd.read_csv(full_path, skipinitialspace=True, on_bad_lines='skip')
    print(f"Removing {df[df.isna().all(axis=1)].shape[0]} rows that contain only NaN values...")
    df = df[~df.isna().all(axis=1)]
    _renaming_class_label(df)
    output_file = os.path.join(filepath, file_name)
    print(f"Saving {output_file} to {filepath}")
    df.to_csv(output_file, index=False, header=True)

def main():
    filepath = "./labels/"
    dataset_path = "./dataset/"
    os.makedirs(dataset_path, exist_ok=True)
    
    # Process Friday files
    friday_files = [
        "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv",
        "Friday-WorkingHours-Afternoon-PortScan.pcap_ISCX.csv",
        "Friday-WorkingHours-Morning.pcap_ISCX.csv"
    ]
    friday_dfs = [pd.read_csv(filepath + f, sep=',') for f in friday_files]
    friday_combined = pd.concat(friday_dfs, ignore_index=True)
    friday_combined.to_csv(dataset_path + "Friday-WorkingHours_CIC.csv", index=False, header=True)
    
    # Copy files for Monday, Tuesday, Wednesday
    for day in ["Monday", "Tuesday", "Wednesday"]:
        shutil.copy(filepath + f"{day}-WorkingHours.pcap_ISCX.csv", dataset_path + f"{day}-WorkingHours_CIC.csv")
    
    # Process and merge Thursday files
    thursday_files = [
        "Thursday-WorkingHours-Afternoon-Infilteration.pcap_ISCX.csv",
        "Thursday-WorkingHours-Morning-WebAttacks.pcap_ISCX.csv"
    ]
    full_path = os.path.join(filepath, thursday_files[1])
    _to_utf8(full_path)
    thursday_dfs = [pd.read_csv(filepath + f, sep=',') for f in thursday_files]
    thursday_combined = pd.concat(thursday_dfs, ignore_index=True)
    thursday_combined.to_csv(dataset_path + "Thursday-WorkingHours_CIC.csv", index=False, header=True)
    
if __name__ == "__main__":
    #process_thursday_file()
    main()
