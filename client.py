import os
import sys
from select import select
import random
import time
timeout=7
timeout1=9
if len(sys.argv) < 4:
    print "Usage: python client.py <CLIENT_PORTS_RANGE> <PROXY_PORT> <END_SERVER_PORT>"
    print "Example: python client.py 20001-20010 20000 19990-19999"
    raise SystemExit

CLIENT_PORT = sys.argv[1]
PROXY_PORT = sys.argv[2]
SERVER_PORT = sys.argv[3]

D = {0: "GET", 1:"POST"}
t=''
f=''
while True:
    # filename = "%d.data" % (int(random.random()*9)+1)
    METHOD = D[int(random.random()*len(D))]

    print("\nDo you want authentication: y/n")
    choice = raw_input()

    print("\nEnter Filename: ")
    filename = (raw_input().split('\n'))[0]
    # filename = "bat.txt"
    # print(filename)
    if choice == 'y':
        print("\nEnter Username: ")
        username = (raw_input().split('\n'))[0]
        print("\nEnter Password: ")
        password = (raw_input().split('\n'))[0]
        # print(username, password)
        os.system("curl --request %s -u %s:%s --proxy 127.0.0.1:%s --local-port %s 127.0.0.1:%s/%s " % (METHOD, username, password, PROXY_PORT, CLIENT_PORT, SERVER_PORT, filename))
        time.sleep(10)
    elif choice == 'n':
        os.system("curl --request %s --proxy 127.0.0.1:%s --local-port %s 127.0.0.1:%s/%s" % (METHOD, PROXY_PORT, CLIENT_PORT, SERVER_PORT, filename))
        time.sleep(10)
    else:
        print("\nPlease enter y or n\n")
        continue