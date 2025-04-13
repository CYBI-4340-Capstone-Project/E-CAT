import os
import subprocess
import shutil
import logging
from datetime import datetime
from pathlib import Path

# Configure logging
log_dir = os.path.join("logs", datetime.now().strftime('%Y-%m-%d'))
os.makedirs(log_dir, exist_ok=True)  # Ensure the directory exists

log_file = os.path.join(log_dir, datetime.now().strftime('extract_feat.log'))

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    filename=log_file,
    filemode='a'  # Append to the log file if it exists
)

class FeatureExtractor:
    def __init__(self, base_path=None):
        self.base_path = base_path or str(Path(__file__).parent)
        self.data_path = os.path.join(self.base_path, "Databases")
        self.cic_path = os.path.join(self.data_path, "CICFlowMeter-3.0", "bin")

    def process_pcap(self, pcap_path, user_id=None):
        """Main function to process a single PCAP file"""
        try:
            # Create user-specific directory if provided
            if user_id:
                output_dir = os.path.join(self.data_path, str(user_id), os.path.splitext(os.path.basename(pcap_path))[0])
            else:
                output_dir = os.path.join(self.data_path, os.path.splitext(os.path.basename(pcap_path))[0])
            
            os.makedirs(output_dir, exist_ok=True)
            file_name = os.path.splitext(os.path.basename(pcap_path))[0]

            # 1. Tshark processing (replaces Argus)
            self._run_tshark(pcap_path, output_dir, file_name)
            
            # 2. CICFlowMeter processing
            self._run_cicflowmeter(pcap_path, output_dir, file_name)
            
            logging.info(f"Successfully processed {pcap_path} for {user_id}")
            return {
                'status': 'success',
                'output_dir': output_dir,
                'tshark_csv': os.path.join(output_dir, 'tshark.csv'),  # Changed from argus.csv
                'cic_csv': os.path.join(output_dir, 'cic.csv')
            }
        except Exception as e:
            logging.error(f"Failed to process {pcap_path} for {user_id}: {str(e)}")
            return {'status': 'error', 'message': str(e)}

    def _run_tshark(self, pcap_path, output_dir, file_name):
            """Convert PCAP to CSV using tshark with comprehensive protocol support"""
            tshark_csv = os.path.join(output_dir, 'tshark.csv')
            
            # Fields to extract (matches what preprocess.py expects)
            fields = [
                'frame.time',          # Timestamp
                'ip.src',              # Source IP
                'ip.dst',              # Destination IP
                'tcp.srcport',         # TCP source port
                'tcp.dstport',         # TCP destination port
                'udp.srcport',         # UDP source port
                'udp.dstport',         # UDP destination port
                'icmp.type',           # ICMP type
                'icmp.code',           # ICMP code
                'ip.proto',            # Protocol number
                '_ws.col.Protocol'     # Protocol name
            ]

            # Build tshark command
            cmd = [
                'tshark',
                '-r', pcap_path,               # Input file
                '-T', 'fields',                # Output type
                '-E', 'header=y',              # Include headers
                '-E', 'separator=,',           # CSV separator
                '-E', 'quote=d',               # Quote style
                '-E', 'occurrence=f'           # Field occurrence
            ]

            # Add fields to command
            for field in fields:
                cmd.extend(['-e', field])

            # Run tshark and write to CSV
            with open(tshark_csv, 'w') as f:
                subprocess.run(cmd, check=True, stdout=f, stderr=subprocess.PIPE)

            logging.info(f"Tshark output saved to {tshark_csv}")

    def _run_cicflowmeter(self, pcap_path, output_dir, file_name):
        """Process PCAP with CICFlowMeter"""
        # Prepare CICFlowMeter directories
        cic_input = os.path.join(self.cic_path, "data", "in")
        cic_output = os.path.join(self.cic_path, "data", "out")
        os.makedirs(cic_input, exist_ok=True)
        os.makedirs(cic_output, exist_ok=True)
        
        # Create backup of original PCAP in same directory
        og_pcap_path = os.path.join(os.path.dirname(pcap_path), f"{file_name}_OG.pcap")
        
        shutil.copy2(pcap_path, og_pcap_path)  # Copy instead of move
        # Rewrite PCAP for CICFlowMeter
        subprocess.run([
            'sudo', 'tcprewrite', '--dlt=enet',
            '--infile', og_pcap_path,  # Use the copied original
            '--outfile', pcap_path
        ], check=True, stderr=subprocess.PIPE)
        
        # Move to CICFlowMeter input
        shutil.move(pcap_path, os.path.join(cic_input, f"{file_name}.pcap"))
        
        # Run CICFlowMeter
        subprocess.run([
            './CICFlowMeter'
        ], cwd=self.cic_path, check=True, stderr=subprocess.PIPE)
        
        # Move and clean up results
        result_file = os.path.join(cic_output, f"{file_name}_ISCX.csv")
        #logging.info("result_file: ", result_file)
        if os.path.exists(result_file):
            shutil.move(result_file, os.path.join(output_dir, "cic.csv"))
        
        # Clean up input file
        os.remove(os.path.join(cic_input, f"{file_name}.pcap"))

def main():
    import argparse
    
    parser = argparse.ArgumentParser(description='PCAP Feature Extractor')
    parser.add_argument('pcap_path', help='Path to PCAP file or directory')
    parser.add_argument('--user-id', help='User ID for organized storage')
    args = parser.parse_args()
    
    extractor = FeatureExtractor()
    
    # Process single file or directory
    if os.path.isfile(args.pcap_path) and args.pcap_path.endswith('.pcap'):
        extractor.process_pcap(args.pcap_path, args.user_id)
    elif os.path.isdir(args.pcap_path):
        for file in os.listdir(args.pcap_path):
            if file.endswith('.pcap'):
                extractor.process_pcap(os.path.join(args.pcap_path, file), args.user_id)
    else:
        logging.error("Invalid input path - must be a PCAP file or directory")

if __name__ == '__main__':
    main()