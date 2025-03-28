import os
import capture # capture_traffic, pload_pcap, get_external_ip_from_hostname
import argparse
import logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def main(flask_url, interface='Ethernet', output='1.pcap', duration=60):
        # Ensure the ./data directory exists
    output_path = "./Databases/"
    if not os.path.exists(output_path):
        logging.info(f"Directory {output_path} does not exist. Creating it...")
        os.makedirs(output_path)

    # List all .pcap files in the ./data/ directory
    pcap_files = [f for f in os.listdir(output_path) if f.endswith('.pcap')]

    # Check if the output file name already exists
    if output in pcap_files:
        logging.warning(f"The output pcap file name '{output}' already exists in the ./data/ directory. Skipping capturing to upload the file(s) in Databases directory...")
    else: 
        capture.capture_traffic(interface, output, duration)

    # Step 1: Capture network traffic
    capture.capture_traffic(interface, output, duration)

    capture.upload_pcap(flask_url)

    # Step 2: have it wait for a response from the server on results of pcaps sent
    # Work in progress
if __name__ == "__main__":
    if os.name == 'nt':
        logging.warning('This script for windows requires to either be ran from administrative prompt or have Wireshark installed with tshark added to PATH.')

    parser = argparse.ArgumentParser(description="Capture network traffic.")
    parser.add_argument("-i", "--interface", default='Ethernet', help="Interface to capture traffic on") # Wi-Fi, if you have virtual switch may have to add manually
    parser.add_argument("-o", "--output", default="1.pcap", help="Output pcap file")
    parser.add_argument("-d", "--duration", type=int, default=60, help="Capture duration in seconds")
    args = parser.parse_args()
    # Ensure the ./data directory exists
    output_path = "./Databases/"
    if not os.path.exists(output_path):
        logging.info(f"Directory {output_path} does not exist. Creating it...")
        os.makedirs(output_path)

    # List all .pcap files in the ./data/ directory
    pcap_files = [f for f in os.listdir(output_path) if f.endswith('.pcap')]

    # Check if the output file name already exists
    if args.output in pcap_files:
        logging.warning(f"The output pcap file name '{args.output}' already exists in the ./Databases/ directory. Skipping capturing to upload the file(s)...")
    else:               
        # Get the external IP address from hostname
        #external_ip = get_external_ip_from_hostname("E-CAT.com")  # Replace with your actual hostname or IP address
        # if external_ip != '192.168.1.1':
        #     # Example usage (replace with your actual endpoint)
        #     flask_url = f"http://{external_ip}/network-classifier/upload"  # Construct the Flask URL
        # else:
        #     flask_url = f"http://34.68.236.49/network-classifier/upload"  # Construct the Flask URL`
        flask_url = f"http://35.238.20.82/network-classifier/upload"
        main(flask_url, args.interface, args.output, args.duration)