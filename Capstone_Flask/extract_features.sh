#!/bin/bash

fileList=($(ls ${1:-"./Databases/"}*.pcap))
fileList=${fileList[@]}

PATH=$PATH':/usr/local/zeek/bin:~/.local/bin'

# Check dependencies
for tool in python argus zeek cicflowmeter tcpreplay; do
    if ! command -v $tool &> /dev/null; then
        echo "ERROR: This script requires $tool."
        #exit 255
    fi
done

if  [ ! -e ./Databases ]
then
    mkdir ./Databases
fi
# Set the correct timezone to match your expected time
echo "Setting correct timezone..."
sudo timedatectl set-timezone CDT  # Change "UTC" to your preferred timezone if needed
DATE_CMD="date '+%Y-%m-%d %H:%M:%S'"
LOG_FILE="/home/capstone4340-admin/E-CAT/Capstone_Flask/logs/${DATE_CMD}_feat_.log"
echo Reading files: ${fileList} >> "$LOG_FILE" 2>&1
echo 
BASE_PATH="/home/capstone4340-admin/E-CAT/Capstone_Flask"
DATA_PATH="/home/capstone4340-admin/E-CAT/Capstone_Flask/Databases"
CIC_PATH="/home/capstone4340-admin/E-CAT/Capstone_Flask/CICFlowMeter-3.0/bin"
for file in ${fileList}; do
    name=$(basename "$file" .pcap)
    echo "File: $name" >> "$LOG_FILE" 2>&1
    echo

    # Ensure the output directory exists
    mkdir -p $DATA_PATH/$name

    echo "Reading PCAP to Argus" >> "$LOG_FILE"
    argus -J -r "$file" -w $DATA_PATH/$name/$name.argus >> "$LOG_FILE" 2>&1 || {
        echo "Error: Argus failed to process $file"
        continue
    }

    echo "Converting Argus to CSV" >> "$LOG_FILE" 
    ra -nn -u -r $DATA_PATH/$name/$name.argus -c ',' -s saddr sport daddr dport proto state dur sbytes dbytes sttl dttl sloss dloss service sload dload spkts dpkts swin dwin stcpb dtcpb smeansz dmeansz sjit djit stime ltime sintpkt dintpkt tcprtt synack ackdat trans min max sum -M dsrs=+time,+flow,+metric,+agr,+jitter > $DATA_PATH/$name/argus.csv >> "$LOG_FILE" 2>&1|| {
        echo "Error: Failed to generate Argus CSV"
        continue
    }

    echo "Reading with Zeek" >> "$LOG_FILE"
    cd $DATA_PATH/$name || exit
    zeek -C -r "$DATA_PATH/$name.pcap" >> "$LOG_FILE" 2>&1 || {
        echo "Error: Zeek failed to process $file"
        cd - > /dev/null
        continue
    }
    cd - > /dev/null
	cd $DATA_PATH

    echo "Processing with CICFlowMeter" >> "$LOG_FILE"
    mv "$name.pcap" "${name}_OG.pcap" >> "$LOG_FILE" 2>&1
    sudo tcprewrite --dlt=enet --infile="${name}_OG.pcap" --outfile="$name.pcap" >> "$LOG_FILE" 2>&1
        # Ensure the output directory exists
    mkdir -p $DATA_PATH/OG_PCAPs
    mv "${name}_OG.pcap" "$DATA_PATH/OG_PCAPs/${name}_OG.pcap" >> "$LOG_FILE" 2>&1
	cd $BASE_PATH

	if [ ! -e "$CIC_PATH/data" ]; then
		sudo mkdir -p $CIC_PATH/data
		sudo mkdir -p $CIC_PATH/data/in
		sudo mkdir -p $CIC_PATH/data/out
        sudo chown -R capstone4340-admin:capstone4340-admin $CIC_PATH
        sudo chmod -R 755 $CIC_PATH/data
	fi

    mv "$file" "$CIC_PATH/data/in/$name.pcap" >> "$LOG_FILE" 2>&1
    cd $CIC_PATH || exit
    ./CICFlowMeter >> "$LOG_FILE" 2>&1|| {
        echo "Error: CICFlowMeter failed to process $file"
        cd - > /dev/null
        continue
    }
	sudo rm "$CIC_PATH/data/in/$name.pcap" >> "$LOG_FILE" 2>&1
    mv "$CIC_PATH/data/out/${name}_ISCX.csv" "$DATA_PATH/$name/cic.csv" >> "$LOG_FILE" 2>&1
    cd - > /dev/null

    echo "File: $name complete" >> "$LOG_FILE"
    echo
done

echo "Done!"