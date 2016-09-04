#!/usr/bin/python
import requests
import urllib3
import json
import sys
import getpass
import paramiko
import time
import os

requests.packages.urllib3.disable_warnings()

logo = """\
                             _________
                           ______________
                        ___________________
                    __________________   _____
                _________  __________   _______
             __________  ____  _____   _________
           ___________  ___     ___  ____________
         ____________  ___     ___  _____________
       _____________   __     __   _______________
     ______________    _______    ________________
    ______________      ___      _________________
   ______________               __________________ HAIST
  ______________                _________________
 ______________                __________________  High
 _____________                 _________________   Altitude
______________     ______      ________________    Intercontinental
_____________    __________    _______________     Server
_____________   ____________    _____________      Transmitter
____________   ______________   ____________
____________   _______________  __________
 __________   ________________   _______
  _________   _________________  _____
   ________  ______________________
    _______  __________________
     _____   ____________
         __
"""

print(logo)

print("")
'''
Get information from user to auth against identity.
'''
username = raw_input('Enter Rackspace username: ')
password = getpass.getpass('Enter Password: ')

regions = ['iad', 'ord', 'dfw', 'syd', 'hkg', 'lon']

#Request to authenticate
def get_token(username,password):
    #setting up api call
    url = "https://identity.api.rackspacecloud.com/v2.0/tokens"
    headers = {'Content-type': 'application/json'}
    payload = {'auth':{'passwordCredentials':{'username': username,'password': password}}}

    #authenticating against the identity
    try:
        r = requests.post(url, headers=headers, json=payload)
    except requests.ConnectionError as e:
        print("Connection Error: Check your interwebs!")
        sys.exit()

    #Check status code. If not sucessful, exit.
    if r.status_code == 200:
        print("Authentication was successful!")
    elif r.status_code == 400:
        print("Bad Request. Missing required parameters. This error also occurs if you include both the tenant name and ID in the request.")
        sys.exit()
    elif r.status_code == 401:
        print("Unauthorized. This error message might indicate any of the following conditions:")
        print("    -You are not authorized to complete this operation.")
        print("    -Additional authentication credentials required. Submit a second authentication request with multi-factor authentication credentials")
        sys.exit()
    elif r.status_code == 403:
        print("User disabled Forbidden")
    elif r.status_code == 404:
        print("Item not found. The requested resource was not found. The subject token in X-Subject-Token has expired or is no longer available. Use the POST token request to get a new token.")
        sys.exit()
    elif r.status_code == 500:
        print("Service Fault. Service is not available")
        sys.exit()
    else:
        print("Unknown Authentication Error")
        sys.exit

    #loads json reponse into data as a dictionary.
    data = r.json()
    #assign token and account variables with info from json response.
    token = (data["access"]["token"]["id"])
    account = (data["access"]["token"]["tenant"]["id"])
    return token,account

token,account = get_token(username,password)

print(token)

print("")
src_srvr = raw_input('Enter Source Server UUID: ')

def get_src_details():
    headers = {"X-Auth-Token": token}
    for i in range(len(regions)):
        region = (regions[i])
        url = "https://" + region + ".servers.api.rackspacecloud.com/v2/" + account + "/servers/" + src_srvr
        try:
            r = requests.get(url,headers=headers, stream=True)
        except requests.ConnectionError as e:
            print("Can't connect to server, please try again or check your internet")
            sys.exit()
        if r.status_code == 200:
            data = r.json()
            src_name = (data["server"]["name"])
            src_status = (data["server"]["status"])
            src_ip = (data["server"]["accessIPv4"])
            src_flavor = (data["server"]["flavor"]["id"])
            src_image = (data["server"]["image"]["id"])
            print "Found instance in " + region + "!"
            return src_name,src_status,src_ip,src_flavor,src_image,region
            break
        else:
            print "Searching..." + region
            sys.stdout.write("\033[F") # Cursor up one line
            continue

src_name,src_status,src_ip,src_flavor,src_image,src_region = get_src_details()

src_vm_mode = "null"
os_type = "null"

def check_src_image(src_vm_mode,os_type):
    headers = {"X-Auth-Token": token}
    url = "https://" + src_region + ".images.api.rackspacecloud.com/v2/" + account + "/images/" + src_image
    try:
        r = requests.get(url,headers=headers, stream=True)
    except requests.ConnectionError as e:
        print("Can't connect to server, please try again or check your internet")
        sys.exit()
    if r.status_code == 200:
        data = r.json()
    else:
        print("There was a problem checking the source server's image.")
        sys.exit()
    try:
        src_vm_mode = (data["vm_mode"])
    except KeyError:
        try:
            os_type = (data["os_type"])
        except KeyError:
            src_vm_mode = str.lower(raw_input("Can't detect source server's vm_mode, is it xen or hvm?: "))

    if src_vm_mode == "hvm":
        src_vm_mode = "hvm"
    elif src_vm_mode == "xen":
        src_vm_mode = "xen"
    elif os_type == "windows":
        os_type = "windows"
        src_vm_mode = "hvm"
    elif os_type != "windows" and src_vm_mode != "hvm":
        src_vm_mode = "xen"
    else:
        src_vm_mode = raw_input("Can't detect source server's vm_mode or os_type, is it xen or hvm?: ")
    return src_vm_mode,os_type

src_vm_mode,os_type = check_src_image(src_vm_mode,os_type)

#Get destination details from user
def set_dst_region():
    while True:
        dst_region = str.lower(raw_input('Enter the region where this server will be copied to, i.e. dfw, ord, iad: '))
        for i in range(len(regions)):
            if dst_region == (regions[i]):
                dst_region_bool = True
                return dst_region
                break
            else:
                dst_region_bool = False
        if dst_region_bool == False:
            print("You entered an invalid region abbreviation, please try again!")
            print("Possible regions are as follows...")
            for i in range(len(regions)):
                print (regions[i])

dst_region = set_dst_region()

def get_dst_image():
    if src_vm_mode == "hvm" and os_type != "windows":
        dst_image_name = "Ubuntu%2014.04%20LTS%20(Trusty%20Tahr)%20(PVHVM)"
    elif src_vm_mode == "xen":
        dst_image_name = "Ubuntu%2014.04%20LTS%20(Trusty%20Tahr)%20(PV)"
    elif os_type == "windows":
        dst_image_name = "Windows%20Server%202012%20R2"
    else:
        pass

    headers = {"X-Auth-Token": token}
    url = "https://" + dst_region + ".images.api.rackspacecloud.com/v2/" + account + "/images?name=" + dst_image_name
    try:
        r = requests.get(url,headers=headers, stream=True)
    except requests.ConnectionError as e:
        print("Can't connect to server, please try again or check your internet")
    if r.status_code == 200:
        data = r.json()
        dst_image = (data["images"][0]["id"])
#        print "Found image to build destination skeleton server in " + dst_region + " (Image UUID: " + dst_image + ")"
        return dst_image
    else:
        print("There was a problem searching for the destination server's skeleton image")
        print("Enter the UUID of the base image your source server was created from.")
        dst_image = raw_input('Enter UUID: ')
        return dst_image

dst_image = get_dst_image()

print("")
print("IMPORTANT! At this time, the destination server must have the same size system disk or larger.")

def set_dst_flavor(question, default="no"):
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")

set_dst_flavor = set_dst_flavor('Yes to keep the same size and flavor. No to choose a different size or flavor', None)

#Actually set destination flavor variable based on set_dst_flavor bool
if set_dst_flavor == True:
    print "The destination server will be built as the " + src_flavor + " flavor."
    dst_flavor = src_flavor
else:
    print "Please see https://www.rackspace.com/cloud/servers for a breakdown of flavors."
    dst_flavor = str.lower(raw_input('Please enter a valid flavor: '))

dst_name = raw_input('Enter a name for the destination server: ')

def build_dst_srvr():
    payload = {'server':{'name': str(dst_name),'imageRef': dst_image,'flavorRef': dst_flavor}}
    headers = {'Content-type': 'application/json', 'X-Auth-Token': token}
    url = "https://" + dst_region + ".servers.api.rackspacecloud.com/v2/" + account + "/servers"
    try:
        r = requests.post(url, headers=headers, json=payload)
    except requests.ConnectionError as e:
        print("Can't connect to server, please try again or check your internet")
    if r.status_code == 202:
        data = r.json()
        dst_srvr_pass = (data["server"]["adminPass"])
        global dst_srvr
        dst_srvr = (data["server"]["id"])
        return dst_srvr_pass
    else:
        print("There was a problem requesting the server to be built.")
        print r.status_code
        sys.exit()

dst_srvr_pass = build_dst_srvr()
print("")
print "Destination server build request accepted, server is building. (New Server UUID: " + dst_srvr + ")"

def get_src_rescue_image():
    headers = {"X-Auth-Token": token}
    url = "https://" + src_region + ".images.api.rackspacecloud.com/v2/" + account + "/images?name=Ubuntu+14.04+LTS+%28Trusty+Tahr%29+%28PVHVM%29"
    try:
        r = requests.get(url,headers=headers, stream=True)
    except requests.ConnectionError as e:
        print("Can't connect to server, please try again or check your internet")
        sys.exit()
    if r.status_code == 200:
        data = r.json()
        src_rescue_image = (data["images"][0]["id"])
        return src_rescue_image
    else:
        print("There was a problem obtaining the rescue image UUID")
        sys.exit()

print("")
print "Placing source server into rescue mode for transfer operations! (Source IP: " + src_ip + ")"

src_rescue_image = get_src_rescue_image()

def src_enter_rescue():
    payload = {"rescue": {"rescue_image_ref": src_rescue_image}}
    headers = {'Content-type': 'application/json', 'X-Auth-Token': token}
    url = "https://" + src_region + ".servers.api.rackspacecloud.com/v2/" + account + "/servers/" + src_srvr + "/action"
    try:
        r = requests.post(url, headers=headers, json=payload)
    except requests.ConnectionError as e:
        print("Can't connect to server, please try again or check your internet")
        sys.exit()
    if r.status_code == 200:
        data = r.json()
        src_rescue_pass = (data["adminPass"])
        return src_rescue_pass
    else:
        print("There was a problem requesting the server to be placed into rescue mode")
        sys.exit()

src_rescue_pass = src_enter_rescue()

print src_name + " is entering rescue mode, the temporary root password is: " + src_rescue_pass

def src_poll_status():
        headers = {"X-Auth-Token": token}
        url = "https://" + src_region + ".servers.api.rackspacecloud.com/v2/" + account + "/servers/" + src_srvr
        try:
            r = requests.get(url,headers=headers, stream=True)
        except requests.ConnectionError as e:
            print("Can't connect to server, trying again....")
        if r.status_code == 200:
            data = r.json()
            src_rescue_status = (data["server"]["status"])
            return src_rescue_status

while src_poll_status() == "ACTIVE":
    for x in range (0,100):
        print ("Rescuing" + "." * x)
        sys.stdout.write("\033[F")
        time.sleep(5)
        if src_poll_status() == "RESCUE":
            break

print("Source server has entered rescue mode successfully!")

def dst_poll_status():
        headers = {"X-Auth-Token": token}
        url = "https://" + dst_region + ".servers.api.rackspacecloud.com/v2/" + account + "/servers/" + dst_srvr
        try:
            r = requests.get(url,headers=headers, stream=True)
        except requests.ConnectionError as e:
            print("Can't connect to server, trying again....")
        if r.status_code == 200:
            data = r.json()
            dst_status = (data["server"]["status"])
            global dst_ip
            dst_ip = (data["server"]["accessIPv4"])
            return dst_status

print("")

while dst_poll_status() != "ACTIVE":
    for x in range (0,100):
        print ("Destination server still building" + "." * x)
        sys.stdout.write("\033[F")
        time.sleep(7)
        if dst_poll_status() == "ACTIVE":
            break

print "The destination server finished building before source entered rescue mode! (Destination IP: " + str(dst_ip) + ")"
print("Placing destination server into rescue mode for transfer operations.")

def get_dst_rescue_image():
    headers = {"X-Auth-Token": token}
    url = "https://" + dst_region + ".images.api.rackspacecloud.com/v2/" + account + "/images?name=Ubuntu+14.04+LTS+%28Trusty+Tahr%29+%28PVHVM%29"
    try:
        r = requests.get(url,headers=headers, stream=True)
    except requests.ConnectionError as e:
        print("Can't connect to server, please try again or check your internet")
        sys.exit()
    if r.status_code == 200:
        data = r.json()
        dst_rescue_image = (data["images"][0]["id"])
        return dst_rescue_image
    else:
        print("There was a problem obtaining the rescue image UUID")
        sys.exit()

dst_rescue_image = get_dst_rescue_image()

def dst_enter_rescue():
    payload = {"rescue": {"rescue_image_ref": dst_rescue_image}}
    headers = {'Content-type': 'application/json', 'X-Auth-Token': token}
    url = "https://" + dst_region + ".servers.api.rackspacecloud.com/v2/" + account + "/servers/" + dst_srvr + "/action"
    try:
        r = requests.post(url, headers=headers, json=payload)
    except requests.ConnectionError as e:
        print("Can't connect to server, please try again or check your internet")
        sys.exit()
    if r.status_code == 200:
        data = r.json()
        dst_rescue_pass = (data["adminPass"])
        return dst_rescue_pass
    else:
        print("There was a problem requesting the server to be placed into rescue mode")
        sys.exit()

time.sleep(5)
dst_rescue_pass = dst_enter_rescue()

print "The destination instance is entering rescue mode, the temporary root password is: " + dst_rescue_pass

def dst_rescue_status():
        headers = {"X-Auth-Token": token}
        url = "https://" + dst_region + ".servers.api.rackspacecloud.com/v2/" + account + "/servers/" + dst_srvr
        try:
            r = requests.get(url,headers=headers, stream=True)
        except requests.ConnectionError as e:
            print("Can't connect to server, trying again....")
        if r.status_code == 200:
            data = r.json()
            dst_rescue_status = (data["server"]["status"])
            return dst_rescue_status

while dst_rescue_status() == "ACTIVE":
    for x in range (0,100):
        print ("Rescuing" + "." * x)
        sys.stdout.write("\033[F")
        time.sleep(5)
        if dst_rescue_status() == "RESCUE":
            break
print("Destination server has entered rescue mode successfully!")
print("")
print("Preparing to log into source server...")

time.sleep(3)

ssh = paramiko.SSHClient()
ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
ssh.connect(str(src_ip), username='root', password=str(src_rescue_pass))

print("Generating public/private rsa key pair for filesystem transmission.")
stdin, stdout, stderr = ssh.exec_command('ssh-keygen -t rsa -N "" -f ~/.ssh/id_rsa')
type(stdin)
stdout.readlines()
stderr.readlines()

print("")
print("Scanning destination server for host keys")
time.sleep(1)
stdin, stdout, stderr = ssh.exec_command('ssh-keyscan ' + str(dst_ip)\
 + ' >> ~/.ssh/known_hosts')
type(stdin)
for line in stdout.readlines():
    print line,
for line in  stderr.readlines():
    print line,

print("")
print("Updating source server's package lists.")
stdin, stdout, stderr = ssh.exec_command('apt-get update')
type(stdin)
stdout.readlines()
stderr.readlines()

stdin, stdout, stderr = ssh.exec_command('apt-get install sshpass -y')
type(stdin)
stdout.readlines()
stderr.readlines()

print("")
print("Installing temporary public rsa key on destination rescue instance.")
stdin, stdout, stderr = ssh.exec_command("sshpass -p " + str(dst_rescue_pass) + " ssh-copy-id\
 root@" + str(dst_ip))
type(stdin)
stdout.readlines()
stderr.readlines()

#Set TCP congestion algorithm for faster xfer
stdin, stdout, stderr = ssh.exec_command('sysctl net.ipv4.tcp_congestion_control=illinois &&\
 ssh root@' + str(dst_ip) + ' \"sysctl net.ipv4.tcp_congestion_control=illinois\"')
type(stdin)
stdout.readlines()
stderr.readlines()

stdin, stdout, stderr = ssh.exec_command("echo \"logfile flush 1\" >> /etc/screenrc")
type(stdin)
for line in stdout.readlines():
    print line,
for line in  stderr.readlines():
    print line,

stdin, stdout, stderr = ssh.exec_command("screen -LdmS HAIST bash -c \'dd if=/dev/xvdb conv=sync,noerror,sparse bs=64K | gzip -c | ssh root@" + str(dst_ip) + " \"gunzip -c | dd of=/dev/xvdb\"; exec bash\'")
type(stdin)
for line in stdout.readlines():
    print line,
for line in  stderr.readlines():
    print line,

time.sleep(3)

print("")
print("Initializing transfer!")
stdin, stdout, stderr = ssh.exec_command("screen -dmS PROGRESS bash -c \'watch -n 2 \"kill -USR1 $(pgrep ^dd) && sleep .5 && tail -n 1 screenlog.* > haist_progress\"; exec bash\'")
type(stdin)
for line in stdout.readlines():
    print line,
for line in  stderr.readlines():
    print line,

time.sleep(2)

counter = 0
progress = None
prevprogress = None
loopvar = True

while loopvar:
    stdin, stdout, stderr = ssh.exec_command('cat haist_progress')
    type(stdin)
    for line in stdout.readlines():
        print(line)
        sys.stdout.write("\033[F")
        sys.stdout.write("\033[F")
        prevprogress = progress
        progress = line
    time.sleep(3)
    if progress is not None and progress == prevprogress:
        counter = counter + 1
        if counter == 6:
            loopvar = False
    else:
        time.sleep(3)
        counter = - 1
        if counter == -3:
            counter = 0

print("")
print("The source server's file system has been cloned to the destination server's disk!")
print("")
print("Taking servers out of rescue mode now, Standby.")
time.sleep(5)

bye_dst_rescue = False
def dst_leave_rescue():
    payload = {"unrescue": 'null'}
    headers = {'Content-type': 'application/json', 'X-Auth-Token': token}
    url = "https://" + dst_region + ".servers.api.rackspacecloud.com/v2/" + account + "/servers/" + dst_srvr + "/action"
    try:
        r = requests.post(url, headers=headers, json=payload)
    except requests.ConnectionError as e:
        print("Can't connect to server, please try again or check your internet")
        sys.exit()
    if r.status_code == 202:
        bye_dst_rescue = True
        return bye_dst_rescue
    else:
        print("There was a problem requesting the server to leave rescue mode")
        sys.exit()

bye_dst_rescue = dst_leave_rescue()

bye_src_rescue = False
def src_leave_rescue():
    payload = {"unrescue": 'null'}
    headers = {'Content-type': 'application/json', 'X-Auth-Token': token}
    url = "https://" + src_region + ".servers.api.rackspacecloud.com/v2/" + account + "/servers/" + src_srvr + "/action"
    try:
        r = requests.post(url, headers=headers, json=payload)
    except requests.ConnectionError as e:
        print("Can't connect to server, please try again or check your internet")
        sys.exit()
    if r.status_code == 202:
        bye_src_rescue = True
        return bye_src_rescue
    else:
        print("There was a problem requesting the server to leave rescue mode")
        sys.exit()

bye_src_rescue = src_leave_rescue()

pollvar = True

reset_network = False

def status_chk(pollvar,reset_network):
    while pollvar:
        for x in range (0,100):
            print ("Un-Rescuing" + "." * x)
            sys.stdout.write("\033[F")
            headers = {"X-Auth-Token": token}
            dst_url = "https://" + dst_region + ".servers.api.rackspacecloud.com/v2/" + account + "/servers/" + dst_srvr
            src_url = "https://" + src_region + ".servers.api.rackspacecloud.com/v2/" + account + "/servers/" + src_srvr

            try:
                dst_r = requests.get(dst_url,headers=headers, stream=True)
            except requests.ConnectionError as e:
                print("Can't connect to server, trying again....")
            if dst_r.status_code == 200:
                dstdata = dst_r.json()
                dst_rescue_status = (dstdata["server"]["status"])

            try:
                src_r = requests.get(src_url,headers=headers, stream=True)
            except requests.ConnectionError as e:
                print("Can't connect to server, trying again....")
            if src_r.status_code == 200:
                srcdata = src_r.json()
                src_rescue_status = (srcdata["server"]["status"])

            if dst_rescue_status == "ACTIVE":
                reset_network = True
                return reset_network
            if dst_rescue_status and src_rescue_status == "ACTIVE":
                print("Both servers have exited rescue mode, and are powering on.")
                print("")
                pollvar = False
                if dst_rescue_status == "ERROR":
                    print("The destination server has entered an error state, please investigate.")
                if src_rescue_status == "ERROR":
                    print("The source server has entered an error state, please investigate.")
                if dst_rescue_status or src_rescue_status == "ERROR":
                    pollvar = False
                time.sleep(3)

if bye_src_rescue and bye_dst_rescue == True:
    print("Unrescue call has been accepted for both servers.")
    reset_network = status_chk(pollvar,reset_network)
else:
    raw_input('Please verify servers are unrescuing, then hit enter: ')
    reset_network = status_chk(pollvar,reset_network)

dst_reset = False
def reset_dst_net(reset_network,dst_reset):
    if reset_network == True:
        payload = {"resetNetwork": 'null'}
        headers = {'Content-type': 'application/json', 'X-Auth-Token': token}
        url = "https://" + dst_region + ".servers.api.rackspacecloud.com/v2/" + account + "/servers/" + dst_srvr + "/action"
        for x in range (0,120):
            print ("Attempting network reset on destination server in " + str(120 - x) + " seconds.")
            sys.stdout.write("\033[F")
            time.sleep(1)
        try:
            r = requests.post(url, headers=headers, json=payload)
        except requests.ConnectionError as e:
            print("Can't connect to server, please try again or check your internet")
            sys.exit()
        if r.status_code == 202:
            dst_reset = True
            return dst_reset
        else:
            print("There was a problem requesting the server to be placed into rescue mode")
            sys.exit()

dst_reset = reset_dst_net(reset_network,dst_reset)

if dst_reset == True:
    for x in range (0,15):
        print ("The reset network request has been sent, resetting..." + str(15 - x))
        sys.stdout.write("\033[F")
        time.sleep(1)
    print("")
    print("Checking network connectivity to " + str(dst_name))
    dst_icmp = os.system("ping -c 10 " + dst_ip + " > /dev/null 2>&1")
    if dst_icmp == 0:
        print(str(dst_name) + " is responding to icmp.")
        os.system("ping -c 4 " + dst_ip)
    else:
        print(str(dst_name) + " is not responding to ICMP requests.")

print("")

dst_console = None
def get_dst_console(dst_console):
    payload = {'os-getVNCConsole': {'type': 'novnc'}}
    headers = {'Content-type': 'application/json', 'X-Auth-Token': token}
    url = "https://" + dst_region + ".servers.api.rackspacecloud.com/v2/" + account + "/servers/" + dst_srvr + "/action"
    try:
        r = requests.post(url, headers=headers, json=payload)
    except requests.ConnectionError as e:
        print("Can't connect to server, please try again or check your internet")
        sys.exit()
    if r.status_code == 200:
        data = r.json()
        dst_console = (data["url"])
        return dst_console
    else:
        print("While trying to get a novnc console URL for " + str(dst_name) + ", got a " + str(r.status_code)) + " status code."

dst_console = get_dst_console(dst_console)

if dst_console is not None:
    print("If you'd like to investigate the destination server via console, here is a novnc (HTML5) console link")
    print(dst_console)

print("")

print("End of script, I hope you enjoyed it!")
