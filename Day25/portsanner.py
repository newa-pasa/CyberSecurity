# Created by HackThacker

# PART ONE
# importing python modules for the port scanner 

import sys
import socket
from datetime import datetime

# PART TWO
#define a target ip address

if len(sys.argv) ==2:
    # hostname to ipv4
    target = socket.gethostbyname(sys.argv[1])
else:
    print("target hostname or ip address")

#PART THREE
#show the scan information

print("=" * 45)
print("scan target: " + target)
print("scanning started : " + str(datetime.now()))
print("=" * 45)


#PART FOUR 
#RUNNING THIS SCAN PROPELY

try:
        for port in range(1,1028):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            socket.setdefaulttimeout(1)

            # output the scan results
            result = s.connect_ex((target,port))
            if result ==0:
                print("port number {} is open".format(port))
                s.close()

#PART FIVE
# SCAN HALTED BY USER

except KeyboardInterrupt:
     print("\n scan was exiting by user")
     sys.exit()
