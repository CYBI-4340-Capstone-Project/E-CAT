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

echo Reading files: ${fileList}
echo 
BASE_PATH="/home/capstone4340-admin/E-CAT/Capstone_Flask"
DATA_PATH="/home/capstone4340-admin/E-CAT/Capstone_Flask/Databases"
CIC_PATH="/home/capstone4340-admin/E-CAT/Capstone_Flask/CICFlowMeter-3.0/bin"
for file in ${fileList}; do
    name=$(basename "$file" .pcap)
    echo "File: $name"
    echo

    # Ensure the output directory exists
    mkdir -p $DATA_PATH/$name

    echo "Reading PCAP to Argus"
    argus -J -r "$file" -w $DATA_PATH/$name/$name.argus || {
        echo "Error: Argus failed to process $file"
        continue
    }

    echo "Converting Argus to CSV"
    ra -nn -u -r $DATA_PATH/$name/$name.argus -c ',' -s saddr sport daddr dport proto state dur sbytes dbytes sttl dttl sloss dloss service sload dload spkts dpkts swin dwin stcpb dtcpb smeansz dmeansz sjit djit stime ltime sintpkt dintpkt tcprtt synack ackdat trans min max sum -M dsrs=+time,+flow,+metric,+agr,+jitter > $DATA_PATH/$name/argus.csv || {
        echo "Error: Failed to generate Argus CSV"
        continue
    }

    echo "Reading with Zeek"
    cd $DATA_PATH/$name || exit
    zeek -C -r "$DATA_PATH/$name.pcap" || {
        echo "Error: Zeek failed to process $file"
        cd - > /dev/null
        continue
    }
    cd - > /dev/null
	cd $DATA_PATH

    echo "Processing with CICFlowMeter"
    mv "$name.pcap" "${name}_OG.pcap"
    sudo tcprewrite --dlt=enet --infile="${name}_OG.pcap" --outfile="$name.pcap"
        # Ensure the output directory exists
    mkdir -p $DATA_PATH/OG_PCAPs
    mv "${name}_OG.pcap" "$DATA_PATH/OG_PCAPs/${name}_OG.pcap"
	cd $BASE_PATH

	if [ ! -e "$CIC_PATH/data" ]; then
		sudo mkdir -p $CIC_PATH/data
		sudo mkdir -p $CIC_PATH/data/in
		sudo mkdir -p $CIC_PATH/data/out
        sudo chown -R capstone4340-admin:capstone4340-admin $CIC_PATH
        sudo chmod -R 755 $CIC_PATH/data
	fi

    mv "$file" "$CIC_PATH/data/in/$name.pcap"
    cd $CIC_PATH || exit
    ./CICFlowMeter || {
        echo "Error: CICFlowMeter failed to process $file"
        cd - > /dev/null
        continue
    }
	sudo rm "$CIC_PATH/data/in/$name.pcap"
    mv "$CIC_PATH/data/out/${name}_ISCX.csv" "$DATA_PATH/$name/cic.csv"
    cd - > /dev/null

    echo "File: $name complete"
    echo
done

echo "Done!"