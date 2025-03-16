import os
import sys
import pandas as pd
import numpy as np
import datetime
from joblib import dump
import myFunc
from tqdm import tqdm
import time

from sklearn.utils.random import sample_without_replacement as uSample
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import StratifiedKFold
from imblearn.over_sampling import ADASYN, SMOTE
from imblearn.combine import SMOTETomek

import warnings
warnings.filterwarnings('ignore')

# Set pandas display options to show all columns and data types
pd.set_option('display.max_columns', None)
pd.set_option('display.max_colwidth', None)
pd.options.display.max_rows = 4000
pd.options.display.max_seq_items = 2000

# GLOBAL VARIABLES 

# Select PCAP and dataset types
# pcapType 0: MAWILab(no attacks) + synthetic attacks
# pcapType 1: UNSW_NB15
# pcapType 2: CIC-IDS
# pcapType 3: ToN-IoT
# pcapType 4: BoT-IoT
# pcapType 5: same as 0 but with internet synthetic attacks
#
# datasetType 0: UNSW_NB15
# datasetType 1: CIC-IDS
##

#XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

#---------#
# RUNNING #
#---------#
# Runs experiment for all algorithms on chosen dataset and saves as .joblib files
def runExperiment(pcapTypeNum, maxNumFiles, datasetTypeNum=1, scanOnly=False, scan=True, no_overwrite=True, balance="none"):
    #----------------------#
    # PREPARE FOR TRAINING #
    #----------------------#
    
    # Load training set..             using its own zero variance list
    print('Preparing for training...')
    print('pcapTypeNum: ', pcapTypeNum)
    print('maxNumFiles: ', maxNumFiles)
    print('datasetTypeNum: ', datasetTypeNum)
    print('scanOnly: ', scanOnly)
    print('scan: ', scan)
    
    X, y = myFunc.setTarget2(myFunc.loadDataset(pcapTypeNum, maxNumFiles, datasetTypeNum), pcapTypeNum, scanOnly, scan, pcapTypeNum)

    # Print columns and data types
    print("Columns in X:\n", X.columns)
    print("Data types in X:\n", X.dtypes)
    print("Columns in y:\n", y.name)
    print("Data types in y:\n", y.dtype)

    # Oversampling
    if balance == "ADASYN":
        print("Oversampling minority class using ADASYN")
        ada = ADASYN()
        print('Original dataset shape {0}'.format(y.value_counts()))
        X, y = ada.fit_resample(X, y)
        print('Resampled dataset shape {0}'.format(y.value_counts()))
    elif balance == "SMOTE_Tomek":
        print("Oversampling minority class using SMOTE + Tomek Links")
        smote_tomek = SMOTETomek(smote=SMOTE())
        print('Original dataset shape {0}'.format(y.value_counts()))
        X, y = smote_tomek.fit_resample(X, y)
        print('Resampled dataset shape {0}'.format(y.value_counts()))

    # Save the oversampled dataset
    oversampled_file = f'./dataset/final/oversampled_{pcapTypeNum}_{datasetTypeNum}.csv'
    oversampled_data = pd.concat([X, y], axis=1)
    oversampled_data.to_csv(oversampled_file, index=False)
    print(f'Oversampled dataset saved to {oversampled_file}')

#XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

# IF CALLED FROM TERMINAL

if __name__ == "__main__":

    datasetMSG = "Datasets available are :\n"
    DST_MSG = "Dataset types available are :\n"
    
    pcapTypeNum = 0 # pcap file to use
    datasetTypeNum = 1 # feature set to use
    maxNumFiles = 48 # maximum number of files to load
    balanceType = "none" # what type of balancing is done
    
    #no_overwrite: skip existing joblib files, dont overwrite
    #scan: target class is Scanning\Reconnaissance
    #scanOnly: remove other attacks from data

    # help
    if len(sys.argv) < 4:
        print("Usage: " + sys.argv[0] + " <MAX_NUM_FILES> <FEATURE_SET> <PCAP_SOURCE> [\"KEEP\"] [\"SCAN_ALL\" (has precedence)] [\"SCAN_ONLY\"]")
        print(datasetMSG, myFunc.datasetOptions())
        sys.exit()
        
    if len(sys.argv) > 3:
        pcapTypeNum = int(sys.argv[3])
        datasetTypeNum = int(sys.argv[2])
        maxNumFiles = int(sys.argv[1])
        # check for unknown dataset
        if pcapTypeNum not in myFunc.pcapOptions():
            print("Unknown dataset(s): ")
            print(datasetMSG, myFunc.datasetOptions())
            sys.exit()
       
        # ToN-IoT and BoT-IoT only available in CIC dataset type
        if pcapTypeNum in [3, 4]:
            datasetTypeNum = 1
            print("ToN-IoT and BoT-IoT only available in CIC dataset type")
        # check for invalid types
        elif (datasetTypeNum not in myFunc.featureOptions()):
            print("Invalid dataset type(s): ")
            print(DST_MSG, myFunc.featureOptions())
            sys.exit()
            
    if len(sys.argv) > 4:
        if "KEEP" in sys.argv[4:]:
            no_overwrite = True
            print("No Overwrite selected. Skipping ML for existing joblib files")
        else:
            print("Overwrite selected. Existing joblib files will be overwritten")
            no_overwrite = False
            
        if "SCAN_ALL" in sys.argv[4:]:
            scan = True # target class is Scanning\Reconnaissance
            scanOnly = False # keep background classes
            print("Target Class: Scanning\\Reconnaissance selected")
        elif "SCAN_ONLY" in sys.argv[4:]:
            scan = True # target class is Scanning\Reconnaissance
            scanOnly = True # exclude non Scanning\Reconnaissance attacks from data
            print("Target Class: Scanning\\Reconnaissance selected, exclude other attacks from Benign data")
        else:
            scan = False # all attack classes are targeted
            scanOnly = False # keep background classes
            
        if "SMOTE_Tomek" in sys.argv[4:]:
            balanceType = "SMOTE_Tomek"
            
        if "ADASYN" in sys.argv[4:]:
            balanceType = "ADASYN"
    
    # Cycle through datasets 1, 2, 3, 4
    for pcapTypeNum in [3]:
        runExperiment(pcapTypeNum, maxNumFiles, datasetTypeNum, scanOnly, scan, no_overwrite, balance=balanceType)