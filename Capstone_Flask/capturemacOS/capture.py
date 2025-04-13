import os
import sys
import platform
import subprocess
import logging
import ctypes  # Windows admin check
import argparse
from time import sleep
import tkinter as tk
from tkinter import ttk, messagebox
import platform
import signal
import shutil
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
def append_to_textbox(text, output_text):
    """Append text to the output_text widget"""
    output_text.config(state="normal")
    output_text.insert("end", text + "\n")
    output_text.see("end") # Scroll to the end
    output_text.config(state="disabled")

# Add this near the top with other utility functions
def get_app_directory():
    """Get the directory where the executable is located"""
    if getattr(sys, 'frozen', False):
        # Running as compiled executable
        return os.path.dirname(sys.executable)
    else:
        # Running as script
        return os.path.dirname(os.path.abspath(__file__))

def create_gui():
    """Create a simple GUI for capture settings"""
    root = tk.Tk()
    root.title("Network Traffic Capture")
    root.geometry("500x600")

    # Interface selection
    ttk.Label(root, text="Network Interface:").pack(pady=5)
    interface_var = tk.StringVar(value="Ethernet")
    interfaces = get_available_interfaces()  # New function to detect interfaces
    interface_menu = ttk.Combobox(root, textvariable=interface_var, values=interfaces)
    interface_menu.pack(pady=5)

    # Output filename
    ttk.Label(root, text="Output Filename:").pack(pady=5)
    output_var = tk.StringVar(value="1.pcap")
    ttk.Entry(root, textvariable=output_var).pack(pady=5)

    # Duration
    ttk.Label(root, text="Duration (seconds):").pack(pady=5)
    duration_var = tk.IntVar(value=60)
    ttk.Spinbox(root, from_=1, to=3600, textvariable=duration_var).pack(pady=5)
    
    # Status Label
    status_label = ttk.Label(root, text="Status: Ready", foreground="blue")
    status_label.pack(pady=10)

    # Textbox for live updates
    output_text = tk.Text(root, height=10, width=60, state="disabled", wrap="word")
    output_text.pack(pady=10)

    # Progress Bar
    progress_bar = ttk.Progressbar(root, orient="horizontal", length=300, mode="determinate")
    progress_bar.pack(pady=10)

    def start_capture():
        """Handle the capture button click"""
        interface = interface_var.get()
        append_to_textbox(f"Interface: {interface}", output_text)
        output = output_var.get()
        append_to_textbox(f"Output Name: {output}", output_text)
        duration = duration_var.get()
        append_to_textbox(f"Duration: {duration}", output_text)

        if not output.endswith('.pcap'):
            output += '.pcap'
        
        # Use the new directory function
        app_dir = get_app_directory()
        data_dir = os.path.join(app_dir, "Data")
        output_path = os.path.join(data_dir, output)
        
        try:
            logging.info(f"Creating directory: {data_dir}")
            os.makedirs(data_dir, exist_ok=True)
            append_to_textbox(f"Output Data Directory created: {data_dir}", output_text)
        except Exception as e:
            logging.error(f"Failed to create directory: {e}")
            append_to_textbox(f"Failed to create directory: {e}", output_text)
            return

        # Update status and progress bar
        status_label.config(text="Status: Capturing...", foreground="orange")
        progress_bar["maximum"] = duration
        progress_bar["value"] = 0

        def update_progress(): 
            """Update the progress bar during capture"""
            for i in range(duration): 
                sleep(1) # Simulate progress (1 second per step)
                progress_bar["value"] = i + 1
                root.update_idletasks() # Update the GUI

            # Capture complete
            status_label.config(text="Status: Capture Complete", foreground="green")
            progress_bar["value"] = duration

        # Run the capture and progress update in a separate thread
        import threading
        capture_thread = threading.Thread(target=lambda: capture_traffic(interface, output_path, duration, output_text))
        progress_thread = threading.Thread(target=update_progress)

        capture_thread.start()
        progress_thread.start()

    # Capture button
    capture_button = ttk.Button(root, text="Start Capture", command=start_capture)
    capture_button.pack(pady=20)

    root.mainloop()

def get_available_interfaces():
    """Try to detect available network interfaces"""
    system = platform.system()
    interfaces = ["Ethernet", "Wi-Fi"]  # Defaults
    
    try:
        if system == "Windows":
            # Windows interface detection
            result = subprocess.run(["netsh", "interface", "show", "interface"], 
                                  capture_output=True, text=True)
            interfaces = [line.split()[3] for line in result.stdout.splitlines() 
                         if "Connected" in line or "Disconnected" in line]
        elif system in ["Linux", "Darwin"]:
            # Linux/macOS interface detection
            result = subprocess.run(["ifconfig", "-a"], capture_output=True, text=True)
            interfaces = [line.split(':')[0] for line in result.stdout.splitlines() 
                         if not line.startswith(' ') and ':' in line]
    except:
        pass  # Fall back to defaults if detection fails
    
    return interfaces if interfaces else ["Ethernet", "Wi-Fi"]

def is_admin_windows():
    """Check if running as admin on Windows"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin_windows():
    """Relaunch as admin on Windows"""
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, " ".join(sys.argv), None, 1
    )
    sys.exit()

def request_sudo_mac(output_text):
    """Request sudo on macOS using osascript for GUI password prompt"""
    try:
        # Use osascript to prompt for the password
        cmd = """osascript -e 'do shell script "echo SUDO_PASSWORD_REQUESTED" with administrator privileges'"""
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            return True  # User authenticated successfully
        append_to_textbox(f"User was not authenticated successfully", output_text)
        return False
    except Exception as e:
        logging.error(f"sudo access failed: {e}")
        append_to_textbox(f"sudo access failed: {e}", output_text)
        return False

def capture_with_tshark(interface, output_file, duration, output_text):
    """Try tshark first (works without admin)"""
    try:
        cmd = f"tshark -i {interface} -a duration:{duration} -w {output_file}"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        
        # Read output line by line
        for line in process.stdout:
            append_to_textbox(line.strip(), output_text) # Update the textbox with each line of output
        
        process.wait() # Wait for the process to complete
        if process.returncode == 0:
            append_to_textbox(f"Successfully captured wtih tshark to {output_file}", output_text)
        else: 
            append_to_textbox("Error: Capture process failed.", output_text)
            logging.info("Error: Capture process failed.")
        logging.info(f"Successfully captured with tshark to {output_file}")
        append_to_textbox(f"You can now capture another pcap file with a different filename or duration or you can navigate to the ./Data directory that was created and upload that pcap file to our website!", output_text)
        return True
    except (Exception, FileNotFoundError, subprocess.CalledProcessError) as e:
        logging.warning(f"tshark failed: {e}")
        append_to_textbox(f"tshark failed: {e}", output_text)
        return False

def capture_with_pktmon(output_file, duration, output_text):
    """Windows fallback (requires admin)"""
    try:
        etl_file = output_file.replace(".pcap", ".etl")
        
        # Start capture
        cmd = f"pktmon start --etw -c --pkt-size 0 -s 1024 -f {etl_file}"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        # Read output line by line
        for line in process.stdout:
            append_to_textbox(line.strip(), output_text) # Update the textbox with each line of output
        
        sleep(duration)

        # Start capture
        cmd = f"pktmon stop"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        # Read output line by line
        for line in process.stdout:
            append_to_textbox(line.strip(), output_text) # Update the textbox with each line of output
        
        # Convert to pcap
        append_to_textbox(f"Attempting to convert {etl_file} to {output_file}", output_text)
        cmd = f"pktmon pcapng {etl_file} -o {output_file}"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)

        # Read output line by line
        for line in process.stdout:
            append_to_textbox(line.strip(), output_text) # Update the textbox with each line of output
                
        os.remove(etl_file)
        logging.info(f"Successfully captured with pktmon to {output_file}")
        append_to_textbox(f"Successfully captured wtih pktmon to {output_file}", output_text)
        return True
    except Exception as e:
        logging.error(f"pktmon failed: {e}")
        append_to_textbox(f"pktmon failed: {e}", output_text)
        return False

def capture_with_tcpdump(interface, output_file, duration, output_text):
    """macOS/Linux fallback (requires sudo)"""
    try:
        cmd = f"sudo tcpdump -i {interface} -w {output_file}"
        append_to_textbox(f"Running command: {cmd}", output_text)
        
        # Run with sudo (will prompt user)
        process = subprocess.Popen(
            cmd, 
            shell=True, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.STDOUT, 
            text=True, 
            preexec_fn=os.setpgrp
        )
        
        # Wait for duration or until process ends
        start_time = time.time()
        while time.time() - start_time < duration:
            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                append_to_textbox(line.strip(), output_text)
        
        # If still running after duration, kill it
        if process.poll() is None:
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            
        return True
        
    except Exception as e:
        logging.error(f"tcpdump failed: {e}")
        append_to_textbox(f"tcpdump failed: {e}", output_text)
        return False

def capture_traffic(interface, output_file, duration, output_text):
    """Main capture logic with permission handling"""
    # Try tshark first (no permissions needed)
    if shutil.which("tshark"):
        append_to_textbox("tshark found!", output_text)
        capture_with_tshark(interface, output_file, duration, output_text)
        return
    
    # Platform-specific fallbacks
    system = platform.system()
    append_to_textbox("tshark not found attempting backup!", output_text)
    if system == "Windows":
        if not is_admin_windows():
            logging.warning("pktmon requires admin rights. Requesting elevation...")
            append_to_textbox(f"pktmon requires admin rights. Requesting elevation...", output_text)
            run_as_admin_windows()
            return  # Script restarts as admin
        
        if not capture_with_pktmon(output_file, duration, output_text):
            logging.error("All Windows capture methods failed")
            append_to_textbox("All Windows capture methods failed! Please attempt to install tshark with 'pip install tshark'. Or you can also download the WireShark application, ensure to have tshark selected during the setup process!", output_text)
    
    elif system == "Darwin":  # macOS
        logging.warning("tcpdump requires sudo. Requesting permissions...")
        append_to_textbox("tcpdump requires sudo. Requesting permissions...", output_text)
        password = request_sudo_mac() # Not actual password just "True" or "False" if we have authorization
        if password:
            capture_with_tcpdump(interface, output_file, duration, output_text, password)
        else:
            logging.error("All macOS capture methods failed")
            append_to_textbox("All macOS capture methods failed! Please attempt to install tshark with 'brew install wireshark'. Or you can also download the WireShark application, ensure to have tshark selected during the setup process!", output_text)
    
    else:
        logging.error("Unsupported operating system")
        append_to_textbox("Unsupported operating system", output_text)

if __name__ == "__main__":
    # Check if we should use GUI or CLI
    if len(sys.argv) > 1:  # Command line mode
        parser = argparse.ArgumentParser(description="Capture network traffic.")
        parser.add_argument("-i", "--interface", default='Ethernet', help="Network interface")
        parser.add_argument("-o", "--output", default="1.pcap", help="Output filename")
        parser.add_argument("-d", "--duration", type=int, default=60, help="Capture duration (seconds)")
        args = parser.parse_args()
        
        # Ensure output directory exists
        os.makedirs("./Data/", exist_ok=True)
        output_path = f"./Data/{args.output}"
        
        capture_traffic(args.interface, output_path, args.duration)
    else:  # GUI mode
        create_gui()