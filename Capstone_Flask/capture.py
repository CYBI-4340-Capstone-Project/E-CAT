import socket
import signal
import logging
import os
import argparse
import subprocess
import time
import requests
# Configure logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

def upload_pcap(flask_url):
    """
    Uploads all .pcap files in the ./Databases/ directory to a Flask endpoint.
    """
    output_path = "./Databases/"
    try:
        # List all .pcap files in the ./Databases/ directory
        pcap_files = [f for f in os.listdir(output_path) if f.endswith('.pcap')]
        if not pcap_files:
            logging.info("No .pcap files found in the ./Databases/ directory.")
            return

        # Upload each .pcap file
        for pcap_file in pcap_files:
            full_output_file = os.path.join(output_path, pcap_file)
            logging.info(f"Uploading {full_output_file} to {flask_url}...")
            with open(full_output_file, 'rb') as f:
                files = {'file': (pcap_file, f)}
                response = requests.post(flask_url, files=files)

            if response.status_code == 200:
                logging.info(f"Successfully uploaded {pcap_file} to {flask_url}")
            else:
                logging.error(f"Failed to upload {pcap_file} to {flask_url}. Status code: {response.status_code}, Response: {response.text}")
    except Exception as e:
        logging.error(f"An unexpected error occurred during file upload: {e}")

def get_external_ip_from_hostname(hostname):
    """Attempting to retrieve the external IP address from a hostname using DNS lookup."""
    try:
        ip_address = socket.gethostbyname(hostname)
        logging.info(f"Resolved IP address for {hostname}: {ip_address}")
        return ip_address
    except socket.gaierror as e:
        logging.error(f"Error resolving hostname {hostname}: {e}")
        return None

def capture_traffic(interface, output_file, capture_duration):
    """
    Captures network traffic for a specified duration and saves it to a pcap file.
    Tries Pyshark first, then falls back to Pktmon if Pyshark is unavailable or fails.
    """
    output_path = "./Databases/"
    full_output_file = os.path.join(output_path, output_file)
    if os.name == 'nt':
        import pyshark
        logging.info("Windows detected - Using Pyshark for packet capture.")
        # Try Pyshark first
        try:
            logging.info(f"Attempting to capture traffic using Pyshark on {interface} for {capture_duration} seconds...")
            tshark_path = "C:\\Program Files\\Wireshark\\tshark.exe"  # Default path to tshark on Windows
            capture = pyshark.LiveCapture(
                interface=interface,
                output_file=full_output_file,
                tshark_path=tshark_path
            )
            capture.sniff(timeout=capture_duration)
            capture.close()
            logging.info(f"Captured {len(capture)} packets using Pyshark. Saved to {full_output_file}")
            return  # Exit the function if Pyshark succeeds
        except FileNotFoundError:
            logging.error("Pyshark (tshark) not found. Ensure Wireshark is installed with tshark and is added to PATH.")
        except Exception as e:
            logging.error(f"Pyshark failed: {e}")

        # Fallback to Pktmon
        try:
            logging.info("Attempting to capture traffic using Pktmon...")
            etl_file = full_output_file.replace(".pcap", ".etl")

            # Start Pktmon capture
            start_command = f"pktmon start --etw -c --pkt-size 0 -s 1024 -f {etl_file}"
            subprocess.run(start_command, shell=True, check=True)
            logging.info("Pktmon capture started.")

            # Wait for the capture duration
            time.sleep(capture_duration)

            # Stop Pktmon capture
            subprocess.run("pktmon stop", shell=True, check=True)
            logging.info("Pktmon capture stopped.")

            # Convert ETL to PCAPNG
            convert_command = f"pktmon pcapng {etl_file} -o {full_output_file}"
            subprocess.run(convert_command, shell=True, check=True)
            logging.info(f"Converted {etl_file} to {full_output_file}")
            os.remove(etl_file)  # Remove the ETL file
        except subprocess.CalledProcessError as e:
            logging.error(f"Pktmon error: {e}")
            logging.error("Ensure the script is run in an administrative prompt.")
        except Exception as e:
            logging.error(f"An unexpected error occurred with Pktmon: {e}")

        # If both methods fail
        logging.error("Failed to capture traffic using both Pyshark and Pktmon. Either install Wireshark and add tshark to PATH, or run the script in an administrative prompt.")
    else:  # macOS/Linux
        logging.info("Linux/macOS detected - Using tcpdump")
        if interface == "Wi-Fi": 
            interface = "en0"
        elif interface == "Ethernet":
            interface = "eth0"
        try:
            # Run tcpdump to capture traffic
            command = f"sudo tcpdump -i {interface} -w {full_output_file}"
            process = subprocess.Popen(command, shell=True, preexec_fn=os.setpgrp)
            process.wait(timeout=capture_duration)
            logging.info(f"Traffic captured and saved to {output_file}")
        except subprocess.TimeoutExpired:
            # Ensure the tcpdump process is terminated if it exceeds the time
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            logging.warning("Traffic capture timed out, process terminated.")
        except Exception as e:
            logging.error(f"Error capturing traffic on Linux/macOS: {e}")

if __name__ == "__main__":

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

    # List all .pcap files in the ./Databases/ directory
    pcap_files = [f for f in os.listdir(output_path) if f.endswith('.pcap')]

    # Check if the output file name already exists
    if args.output in pcap_files:
        logging.warning(f"The output pcap file name '{args.output}' already exists in the ./Databases/ directory. Skipping capturing to upload the file(s)...")
    else: 
        capture_traffic(args.interface, args.output, args.duration)

        # Get the external IP address from hostname
    #external_ip = get_external_ip_from_hostname("capstone4340-server")

    # if external_ip != '192.168.1.1':
    #     # Example usage (replace with your actual endpoint)
    #     flask_url = f"http://{external_ip}/network-classifier/upload"  # Construct the Flask URL
    # else:
    #     flask_url = f"http://34.68.236.49/network-classifier/upload"  # Construct the Flask URL
    flask_url = f"http://35.225.47.66/network-classifier/upload"
    upload_pcap(flask_url)