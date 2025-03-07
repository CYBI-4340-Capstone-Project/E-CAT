#----------------------------------------------------------------------------------------
#
#                                      CIC_labels.py
#
#
#
# Discription:
# Format CIC label files for subsequent use
#-----------------------------------------------------------------------------------------
import pandas as pd

def main():
    # Load the dataset
    file_path = "./dataset/BoT-IoT_CIC.csv"  # Replace with the correct path
    df = pd.read_csv(file_path, low_memory=False)
    
    # Check for HTML content
    html_rows = df[df.astype(str).apply(lambda x: x.str.contains("<!DOCTYPE html>", na=False)).any(axis=1)]
    
    # Display the affected rows
    print(html_rows)

    
if __name__ == "__main__":
    #process_thursday_file()
    main()
