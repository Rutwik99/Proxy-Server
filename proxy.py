import base64
import copy
import thread
import socket
import sys
import os
import datetime
import time
import json
import threading
import email.utils as eut

# global variables
max_connections = 10
max_request_size = 4096
max_cache_size = 3
occ_cache = 2
blocked = []
super_users = []
a = 1

# Take Command line argument
if len(sys.argv) < 2 or len(sys.argv) > 2:
    print "Wrong Format\n"
    print "Usage: python %s 21000" % sys.argv[0]
    raise SystemExit

try:
    proxy_port = int(sys.argv[1])
except:
    print "Enter the Write Port Number"
    raise SystemExit

if not os.path.isdir("./cache"):
    os.makedirs("./cache")

f = open("blacklist.txt", "rb")
data = ""
while a:
    chunk = f.read()
    if not len(chunk):
        break
    data += (chunk * 1)
f.close()
blocked = data.splitlines()

f = open("username_password.txt", "rb")
data = ""
while a:
    chunk = f.read()
    if not len(chunk):
        break
    data += (chunk * 1)
f.close()
data = data.splitlines()

for d in range(len(data)):
    super_users.append(base64.b64encode(data[d]))

t1 = os.listdir("./cache")
for file in range(len(t1)):
    os.remove("./cache" + "/" + t1[file])


# lock fileurl
def get_access(fileurl):
    if fileurl not in locks:
        lock = threading.Lock()
        locks[fileurl] = lock
    else:
        lock = locks[fileurl]

    lock.acquire()

# unlock fileurl
def leave_access(fileurl):
    if fileurl not in locks:
        print "Lock problem"
        sys.exit()
    else:
        lock = locks[fileurl]
        lock.release()




def add_log(fileurl, client_addr):
    fileurl = fileurl.replace("/", "__")
    if not fileurl in logs:
        logs[fileurl] = []
    dt = time.strptime(time.ctime(), "%a %b %d %H:%M:%S %Y")
    logs[fileurl].append({
            "datetime" : dt,
            "client" : json.dumps(client_addr),
        })


def do_cache_or_not(fileurl):
    try:
        log_arr = logs[fileurl.replace("/", "__")]
        z1 = len(log_arr)
        z2 = occ_cache
        if z1 < z2:
            return False
        last_third = log_arr[z1 - z2]["datetime"]
        q1 = datetime.datetime.fromtimestamp(time.mktime(last_third))
        q2 = datetime.timedelta(minutes=10)

        if q1 + q2 < datetime.datetime.now():
            return False
        else:
            return True
    except Exception as e:
        print e
        return False

# check whether file is already cached or not
def get_current_cache_info(fileurl):

    if fileurl.startswith("/"):
        fileurl = fileurl.replace("/", "", 1)

    aa1 = "./cache"
    aa2 = fileurl.replace("/", "__")
    cache_path = aa1 + "/" + aa2

    if os.path.isfile(cache_path):
        last_mtime = time.strptime(time.ctime(os.path.getmtime(cache_path)), "%a %b %d %H:%M:%S %Y")
        return cache_path, last_mtime
    else:
        return cache_path, None


# collect all cache info
def get_cache_details(client_addr, dets):
    test1 = dets["total_url"]
    get_access(test1)
    add_log(test1, client_addr)
    do_cache = do_cache_or_not(test1)
    cache_path, last_mtime = get_current_cache_info(test1)
    leave_access(test1)
    dets["do_cache"] = do_cache
    dets["cache_path"] = cache_path
    dets["last_mtime"] = last_mtime
    return dets


# if cache is full then delete the least recently used cache item
def get_space_for_cache(fileurl):
    cache_files = os.listdir("./cache")
    if len(cache_files) < max_cache_size:
        return
    for file in cache_files:
        get_access(file)

    last_mtime = min(logs[file][-1]["datetime"] for file in cache_files)
    file_to_del = [file for file in cache_files if logs[file][-1]["datetime"] == last_mtime][0]

    ff1 = "./cache"
    ff2 = "/"
    os.remove(ff1 + ff2 + file_to_del)
    for file_ind in range(len(cache_files)):
        leave_access(cache_files[file_ind])


# returns a dictionary of details
def parse_details(client_addr, client_data):
    try:

        lines = client_data.splitlines()
        while lines[len(lines)-1] == '':
            lines.remove('')
        first_line_tokens = lines[0].split()
        url = first_line_tokens[1]

        # get starting index of IP
        url_pos = url.find("://")
        if url_pos != -1:
            protocol = url[:url_pos]
            url = url[(url_pos+3):]
        else:
            protocol = "http"

        port_pos = url.find(":")
        path_pos = url.find("/")
        if path_pos == -1:
            path_pos = len(url)


        # change request path accordingly
        if port_pos == -1 or path_pos < port_pos:
            server_port = 80
            server_url = url[:path_pos]
        else:
            server_port = int(url[(port_pos + 1):path_pos])
            server_url = url[:port_pos]

        # check for auth
        auth_line = [ line for line in lines if "Authorization" in line]
        if len(auth_line):
            auth_b64 = auth_line[0].split()[2]
        else:
            auth_b64 = None

        # build up request for server
        first_line_tokens[1] = url[path_pos:]
        lines[0] = ' '.join(first_line_tokens)
        client_data = "\r\n".join(lines) + '\r\n\r\n'

        return {
            "server_port" : server_port,
            "server_url" : server_url,
            "total_url" : url,
            "client_data" : client_data,
            "protocol" : protocol,
            "method" : first_line_tokens[0],
            "auth_b64" : auth_b64,
        }

    except Exception as e:
        print e
        print
        return None


# insert the header
def insert_if_modified(dets):

    lines = dets["client_data"].splitlines()
    while lines[len(lines)-1] == '':
        lines.remove('')

    #header = "If-Modified-Since: " + time.strptime("%a %b %d %H:%M:%S %Y", dets["last_mtime"])
    header = time.strftime("%a %b %d %H:%M:%S %Y", dets["last_mtime"])
    header = "If-Modified-Since: " + header
    lines.append(header)

    dets["client_data"] = "\r\n".join(lines) + "\r\n\r\n"
    return dets


# serve get request
def serve_get(client_socket, client_addr, details):
    gg = details["total_url"]

    try:

        client_data = details["client_data"]
        do_cache = details["do_cache"]
        cache_path = details["cache_path"]
        last_mtime = details["last_mtime"]

        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((details["server_url"], details["server_port"]))
        server_socket.send(details["client_data"])

        reply = server_socket.recv(max_request_size)
        if last_mtime and "304 Not Modified" in reply:
            print "returning cached file %s to %s" % (cache_path, str(client_addr))
            get_access(gg)
            f = open(cache_path, 'rb')
            chunk = f.read(max_request_size)
            while chunk:
                client_socket.send(chunk)
                chunk = f.read(max_request_size)
            f.close()
            leave_access(gg)

        else:
            if do_cache:
                print "caching file while serving %s to %s" % (cache_path, str(client_addr))
                get_space_for_cache(gg)
                get_access(gg)
                f = open(cache_path, "w+")
                # print len(reply), reply
                while len(reply):
                    client_socket.send(reply)
                    f.write(reply)
                    reply = server_socket.recv(max_request_size)
                    #print len(reply), reply
                f.close()
                leave_access(gg)
                client_socket.send("\r\n\r\n")
            else:
                print "without caching serving %s to %s" % (cache_path, str(client_addr))
                #print len(reply), reply
                while len(reply):
                    client_socket.send(reply)
                    reply = server_socket.recv(max_request_size)
                    #print len(reply), reply
                client_socket.send("\r\n\r\n")

        server_socket.close()
        client_socket.close()
        return

    except Exception as e:
        server_socket.close()
        client_socket.close()
        print e
        return


def serve_post(client_socket, client_addr, details):
    ff = ['server_url', 'server_port', 'client_data']
    try:
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((details[ff[0]], details[ff[1]]))
        server_socket.send(details[ff2[2]])

        while True:
            reply = server_socket.recv(max_request_size)
            if len(reply):
                client_socket.send(reply)
            else:
                break

        server_socket.close()
        client_socket.close()
        return

    except Exception as e:
        server_socket.close()
        client_socket.close()
        print e
        return

# Done
def is_blocked(cl_sckt, cl_addr, dets):
    temp1 = dets["server_url"]
    temp2 = ":"
    temp3 = str(dets["server_port"])
    temp4 = dets["auth_b64"]
    if not(temp1 + temp2 + temp3) in blocked:
    # if not (dets["server_url"] + ":" + str(dets["server_port"])) in blocked:
        return False
    if not (temp4):
        return True
    if temp4 in super_users:
        return False
    return True



# A thread function to handle one request
def handle_one_request_(client_socket, client_addr, client_data):
    hh = ["GET", "POST", "method", "last_mtime"]

    details = parse_details(client_addr, client_data)

    if not details:
        print "No any details"
        client_socket.close()
        return

    isssbbb = is_blocked(client_socket, client_addr, details)


    if isssbbb:
        print "Block status : ", isssbbb

    if isssbbb:
        jj = "\r\n"
        client_socket.send("HTTP/1.0 200 OK\r\n")
        client_socket.send("Content-Length: 11\r\n")
        client_socket.send(jj)
        client_socket.send("Error" + jj)
        client_socket.send(jj + jj)

    elif details[hh[2]] == hh[0]:
        details = get_cache_details(client_addr, details)
        if details[hh[3]]:
            details = insert_if_modified(details)
        serve_get(client_socket, client_addr, details)

    elif details[hh[2]] == hh[1]:
        serve_post(client_socket, client_addr, details)

    client_socket.close()
    print client_addr, "closed"
    print

### Main

logs = {}
locks = {}

# Initialize Socket
try:
    proxy_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    proxy_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    proxy_socket.bind(('', proxy_port))
    proxy_socket.listen(max_connections)

    print "Serving proxy on %s port %s ..." % (
        str(proxy_socket.getsockname()[0]),
        str(proxy_socket.getsockname()[1])
        )

except Exception as e:
    print "Error in starting proxy server ..."
    print e
    proxy_socket.close()
    raise SystemExit


# Main server loop
while True:
    try:
        client_socket, client_addr = proxy_socket.accept()
        client_data = client_socket.recv(max_request_size)

        print
        print "%s - - [%s] \"%s\"" % (
            str(client_addr),
            str(datetime.datetime.now()),
            client_data.splitlines()[0]
            )

        thread.start_new_thread(
            handle_one_request_,
            (
                client_socket,
                client_addr,
                client_data
            )
        )

    except KeyboardInterrupt:
        client_socket.close()
        proxy_socket.close()
        print "\nProxy server shutting down ..."
        break