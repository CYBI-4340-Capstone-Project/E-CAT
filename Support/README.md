# About this directory
This directory contains Argus configuration files, scripts, and services used 
to set up, manage, and archive network traffic logs. These files help configure 
Argus, automate its execution, store logs efficiently, and export data for 
further analysis. Besides the excel.rc file these files have been modified
to fit my configuration needs. If you want the original version of these files
please refer to the Argus GitHub page that can be found in the INSTALL_ARGUS
file. Please refer to the INSTALL_ARGUS file for instructions on how to use
these configuration files and scripts. 

## argus
    INSTALL_ARGUS - This file provides installation instructions for setting 
                     up Argus on Ubuntu and provides troubleshooting steps for 
                     common issues.

    argus.conf - The argus.conf file is the main configuration file, specifying 
                  settings such as the network interface, port number, log file 
                  location, and data formatting options.

    argusarchive - An sh shell script for moving the argus daemon's output
                    file into a date based archive.  The archive file system 
                    is created when needed and the output file is compressed, 
                    copied into a .csv file and moved into the file system.

    argus.archive - The argus.archive directory stores these archived logs, 
                     organizing them by year, month, and day. 

    excel.rc - Excel.rc is a ra configuration file to write output so that it can 
                be imported by Microsoft's Excel. Basically generates a 
                comma-separated-file (csv) with appropriate titles for the columns 
                and a date format that Excel understands.

    argus.service - The argus.service file is a systemd service configuration that 
                     allows Argus to run automatically in the background, ensuring 
                     continuous network traffic monitoring and automatic restarts 
                     if needed.

## zeek
    INSTALL_ZEEK - This file provides installation instructions for setting 
                     up zeek on Ubuntu and provides steps to test zeek functionality. 
