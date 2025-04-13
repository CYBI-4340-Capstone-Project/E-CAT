import os
import sys
import pandas as pd
import numpy as np
import logging
from datetime import datetime
from pathlib import Path
import json

# Configure logging
log_dir = os.path.join("logs", datetime.now().strftime('%Y-%m-%d'))
os.makedirs(log_dir, exist_ok=True)  # Ensure the directory exists

log_file = os.path.join(log_dir, datetime.now().strftime('preprocess.log'))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=log_file,
    filemode='a'  # Append to the log file if it exists
)

class Preprocessor:
    def __init__(self, base_path=None):
        self.base_path = base_path or str(Path(__file__).parent)
        self.data_path = os.path.join(self.base_path, "Databases")
        
    def ports_as_int(self, x):
        """Convert port numbers to integers (handles hex strings)"""
        try:
            if isinstance(x, str):
                return int(x, 16) if '0x' in x.lower() else int(x)
            return int(x)
        except (ValueError, TypeError):
            return np.nan

    def proto_num(self, proto):
        """Convert protocol names to standard numbers"""
        trad = {"tcp":6, "udp":17, "ipv4":4, "icmp":1, "igmp":2, "ggp": 3, "ip": 0, 
                "egp": 8, "pup": 12, "hmp": 20, "xns-idp": 22, "rdp": 27, "ipv6": 41, 
                "ipv6-frag": 44, "ipv6-route": 43, "rvd": 66, "ipv6-opts": 60, "l2tp": 1701}
        try:
            if isinstance(proto, str):
                return trad.get(proto.lower(), np.nan)
            return int(proto)
        except (ValueError, TypeError):
            return np.nan

    def flow_id(self, dataframe):
        """Generate unique flow identifiers"""
        return (
            dataframe['dst_ip'].astype(str) + '-' + 
            dataframe['dst_port'].astype(str) + '-' +
            dataframe['src_ip'].astype(str) + '-' + 
            dataframe['src_port'].astype(str) + '-' +
            dataframe['protocol'].astype(str)
        )

    def load_dataset(self, user_id, pcap_name): # NOT IN USE JUST OVERWRITING AS OF RN
        """
        Check if preprocessed file exists and load it.
        Returns:
            - DataFrame if file exists
            - None if processing needed
        """
        output_dir = os.path.join(self.data_path, str(user_id), pcap_name)
        final_path = os.path.join(output_dir, f"{pcap_name}_final.csv")
        
        if os.path.exists(final_path):
            logging.info(f"Loading existing preprocessed file: {final_path}")
            return final_path
        return None

    def to_cic(self, user_id, pcap_name):
        input_dir = os.path.join(self.data_path, str(user_id), pcap_name)
        output_file = os.path.join(input_dir, f"{pcap_name}_CIC.csv")
        ALL_ID = ['timestamp', 'flow_ID', 'src_port', 'src_ip', 'dst_ip', 'dst_port']
        
        # Load CIC data (unchanged)
        cic_df = pd.read_csv(os.path.join(input_dir, "cic.csv"))
        cic_df.rename(columns={
            'Src IP': 'src_ip',
            'Src Port': 'src_port',
            'Dst IP': 'dst_ip',
            'Dst Port': 'dst_port',
            'Protocol': 'protocol',
            'Timestamp': 'timestamp',
            'Flow ID': 'flow_ID'
        }, inplace=True)
        
        # Load Tshark data instead of Argus
        tshark_df = pd.read_csv(
            os.path.join(input_dir, "tshark.csv"),
            usecols=['ip.src', 'ip.dst', 'tcp.srcport', 'tcp.dstport', 'udp.srcport', 'udp.dstport', 'ip.proto'],
            converters={
                'ip.proto': self.proto_num,
                'tcp.srcport': self.ports_as_int,
                'tcp.dstport': self.ports_as_int,
                'udp.srcport': self.ports_as_int,
                'udp.dstport': self.ports_as_int
            }
        )
        
        # Combine port columns (tshark separates TCP/UDP ports)
        tshark_df['src_port'] = tshark_df['tcp.srcport'].fillna(tshark_df['udp.srcport'])
        tshark_df['dst_port'] = tshark_df['tcp.dstport'].fillna(tshark_df['udp.dstport'])
        
        # Clean up
        tshark_df = tshark_df.rename(columns={
            'ip.src': 'src_ip',
            'ip.dst': 'dst_ip',
            'ip.proto': 'protocol'
        })[['src_ip', 'dst_ip', 'src_port', 'dst_port', 'protocol']]
        
        # Merge with CIC data (rest of the method remains the same)
        cic_df = cic_df.merge(
            tshark_df,
            on=['src_ip', 'dst_ip', 'src_port', 'dst_port'],
            how='left',
            suffixes=('_cic', '_tshark')
        )
        
        # Use tshark protocol where CIC is missing/incorrect
        cic_df['protocol'] = cic_df['protocol_tshark'].fillna(cic_df['protocol_cic'])
        
        # Clean up
        flowCount = cic_df.shape[0]
        logging.info('Flow count: {0}'.format(flowCount))
            # Drop full NaN lines
        cic_df.drop(cic_df[cic_df.isna().all(axis=1)].index, axis = 0, inplace = True)
        #logging.info(pcap_name, "Removed {0} lines of full NaN values".format(flowCount-cic_df.shape[0]))
        flowCount = cic_df.shape[0]
        logging.info("Flow count after dropping full NaN lines: {0}".format(flowCount))
        
        # Drop ID NaN lines
        cic_df.drop(cic_df[cic_df[ALL_ID].isna().any(axis=1)].index, axis = 0, inplace = True)
        #logging.info(pcap_name,"Removed {0} lines of NaN ID values".format(flowCount-cic_df.shape[0]))
        flowCount = cic_df.shape[0]
        logging.info("Flow count after dropping ID NaN lines: {0}".format(flowCount))
        
        # Drop infinity valued feature lines
        cic_df.drop(cic_df[(cic_df == np.inf).any(axis=1)].index, axis = 0, inplace = True)
        #logging.info(pcap_name,"Removed {0} lines with infinity valued features".format(flowCount-cic_df.shape[0]))
        flowCount = cic_df.shape[0]
        logging.info("Flow count after dropping infinity valued feature lines: {0}".format(flowCount))

        cic_df.fillna(0, inplace=True)
        cic_df["dst_port"] = cic_df["dst_port"].apply(float)
        cic_df = cic_df.astype({"dst_port":"int32"})

        #cic_df.dropna(subset=['protocol'], inplace=True)
        #cic_df['flow_id'] = self.flow_id(cic_df)

        cic_df.to_csv(output_file, index=False)
        
        logging.info(f"Saved preprocessed data to {output_file}")
        return output_file
    
    def build_dataset(self, user_id, pcap_name):
        """
        Final processing step before prediction.
        Returns cleaned DataFrame ready for model input.
        """
        input_file = os.path.join(
            self.data_path, str(user_id), pcap_name, 
            f"{pcap_name}_CIC.csv"
        )
        output_file = os.path.join(
            self.data_path, str(user_id), pcap_name, 
            f"{pcap_name}_final.csv")
        
        if not os.path.exists(input_file):
            raise FileNotFoundError(f"Preprocessed file not found: {input_file}")
        
        # Load the dtypes from training.json
        with open("training.json", "r") as f:
            training_config = json.load(f)
            dtypes = training_config["dtypes"]
        
        df = pd.read_csv(input_file)
        
        # Basic cleaning
        df.dropna(how='all', inplace=True)
        df.drop_duplicates(inplace=True)
        
        # Handle infinite values
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df[numeric_cols] = df[numeric_cols].replace([np.inf, -np.inf], np.nan)
        df.dropna(how='any', subset=numeric_cols, inplace=True)
        
        # Rename columns: lowercase, replace spaces with underscores
        df.columns = df.columns.str.strip().str.lower().str.replace(" ", "_").str.replace("/", "_")

        df.replace(-1, 0, inplace=True)
        df["fwd_seg_size_min"] = df["fwd_seg_size_min"].clip(lower=0)  # Set min values to 0
        df["fwd_iat_min"] = df["fwd_iat_min"].clip(lower=0)
        df["init_fwd_win_byts"] = df["init_fwd_win_byts"].clip(lower=0)
        df["init_bwd_win_byts"] = df["init_bwd_win_byts"].clip(lower=0)
        
        # Apply dtypes for consistent data types
        for col, dtype in dtypes.items():
            if col in df.columns:
                try:
                    df[col] = df[col].astype(dtype)
                except ValueError:
                    logging.warning(f"Could not convert {col} to {dtype}, replacing errors with NaN")
                    df[col] = pd.to_numeric(df[col], errors='coerce')
        
        # Ensure proper types for specific columns
        if 'dst_port' in df.columns:
            df['dst_port'] = df['dst_port'].apply(self.ports_as_int)
        if 'protocol' in df.columns:
            df['protocol'] = df['protocol'].apply(self.proto_num)
        df.rename(columns={
            'label': 'Label'
        }, inplace=True)
        if 'Label' in df.columns:
            df['Label'] = df['Label'].replace("No Label", "BENIGN")
        df.drop(columns={
            'protocol_cic',
            'protocol_tshark', # Remove redundant columns
        }, inplace=True, errors='ignore')
        # Final clean-up before saving

        df.to_csv(output_file, index=False)

        logging.info(f"Saved final data to {output_file}")
        return output_file

def main():
    import argparse
    parser = argparse.ArgumentParser(description='PCAP Preprocessor')
    parser.add_argument('user_id', help='User ID')
    parser.add_argument('pcap_name', help='PCAP name (without extension)') # full path ./Databases/1/1/1_final.csv
    args = parser.parse_args()
    
    processor = Preprocessor()
    
    # Step 1: Check for existing processed file
    existing_data = processor.load_dataset(args.user_id, args.pcap_name)
    if existing_data is not None:
        print("Found existing processed data")
        return
    logging.info(f'Starting to_cic function with {args.user_id} user id and {args.pcap_name} pcap name')
    # Step 2: Create CIC-formatted file
    cic_path = processor.to_cic(args.user_id, args.pcap_name)
    
    logging.info(f'Starting build_dataset function with {args.user_id} user id and {args.pcap_name} pcap name')
    # Step 3: Build final dataset
    final_df = processor.build_dataset(args.user_id, args.pcap_name)
    logging.info(f"Final dataset shape: {final_df.shape}")

if __name__ == '__main__':
    main()