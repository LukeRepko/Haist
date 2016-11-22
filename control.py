#!/usr/bin/python
import requests
import urllib3
import json
import sys
import getpass
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
   ______________               __________________ Boot a HAIST Controller
  ______________                _________________
 ______________                __________________  High
 _____________                 _________________  Altitude
______________     ______      ________________  Intercontinental
_____________    __________    _______________  Server
_____________   ____________    _____________  Transmitter
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
password = getpass.getpass('Enter Password or API Key: ')

regions = ['iad', 'ord', 'dfw', 'syd', 'hkg', 'lon']

#Request to authenticate using password
def get_token(username,password):
    #setting up api call
    url = "https://identity.api.rackspacecloud.com/v2.0/tokens"
    headers = {'Content-type': 'application/json'}
    payload = {'auth':{'passwordCredentials':{'username': username,'password': password}}}
    payload2 = {'auth':{'RAX-KSKEY:apiKeyCredentials':{'username': username,'apiKey': password}}}

    #authenticating against the identity
    try:
        r = requests.post(url, headers=headers, json=payload)
    except requests.ConnectionError as e:
        print("Connection Error: Check your interwebs!")
        sys.exit()

    if r.status_code != 200:
        r = requests.post(url, headers=headers, json=payload2)
        if r.status_code != 200:
            print("Invalid username / password / apiKey")
            sys.exit()
        else:
            print("Authentication was successful!")
    elif r.status_code == 200:
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
        sys.exit()

    #loads json reponse into data as a dictionary.
    data = r.json()
    #assign token and account variables with info from json response.
    token = (data["access"]["token"]["id"])
    account = (data["access"]["token"]["tenant"]["id"])
    return token,account

token,account = get_token(username,password)

regions = ['iad', 'ord', 'dfw', 'syd', 'hkg', 'lon']

def set_dst_region():
    while True:
        dst_region = str.lower(raw_input('Enter the region where the HAIST controller will be built: '))
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
    dst_image_name = "Ubuntu%2014.04%20LTS%20(Trusty%20Tahr)%20(PVHVM)"
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
        print("There was a problem! Can't find image, please enter the UUID of the Ubuntu 14.04 PVHVM base image to continue.")
        dst_image = raw_input('Enter UUID: ')
        return dst_image

dst_image = get_dst_image()

dst_name = "Haist-Controller"

def build_dst_srvr():
    cloud_conf = "I2Nsb3VkLWNvbmZpZw0KDQpwYWNrYWdlczoNCg0KIC0gYnVpbGQtZXNzZW50aWFsDQogLSBsaWJzc2wtZGV2DQogLSBsaWJmZmktZGV2DQogLSBweXRob24tZGV2DQogLSBweXRob24tcGlwDQogLSB1bnppcA0KDQpydW5jbWQ6DQoNCiAtIHdnZXQgaHR0cHM6Ly9ib290c3RyYXAucHlwYS5pby9lel9zZXR1cC5weSAtTyAtIHwgc3VkbyBweXRob24NCiAtIHBpcCBpbnN0YWxsIC0tdXBncmFkZSByZXF1ZXN0cw0KIC0gcGlwIGluc3RhbGwgdXJsbGliMw0KIC0gcGlwIGluc3RhbGwgcGFyYW1pa28NCiAtIHdnZXQgaHR0cHM6Ly9naXRodWIuY29tL0x1a2VSZXBrby9IYWlzdC9hcmNoaXZlL21hc3Rlci56aXAgLU8gL3Jvb3QvaGFpc3QuemlwDQogLSB1bnppcCAvcm9vdC9oYWlzdC56aXAgLWQgL3Jvb3QvDQogLSBlY2hvICJzY3JlZW4gLVMgSGFpc3QtQ29udHJvbGxlciBiYXNoIC1jICdlY2hvICYmIGVjaG8gXCJZb3UgYXJlIGluIGEgc2NyZWVuIHNlc3Npb24sIHByZXNzIFwiY3RybCArIGFkXCIgYXQgYW55IHRpbWUgdG8gZHJvcCB0byBhIHNoZWxsLiBzY3JlZW4gLXIgY2FuIGJlIHVzZWQgdG8gY29tZSBiYWNrIHRvIEhBSVNULlwiICYmIHB5dGhvbiAvcm9vdC9IYWlzdC1tYXN0ZXIvaGFpc3QucHk7IGV4ZWMgYmFzaCciID4+IC9yb290Ly5iYXNocmM="
    payload = {'server':{'name': dst_name,'imageRef': dst_image,'flavorRef': 'general1-1', 'config_drive': 'true','user_data': cloud_conf}}
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

if dst_srvr_pass is not None:
    print "Haist control server is building. (Server UUID: " + dst_srvr + ")"

time.sleep(5)

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
        print ("Server building" + "." * x)
        sys.stdout.write("\033[F")
        time.sleep(7)
        if dst_poll_status() == "ACTIVE":
            break

print "Haist-Controller finished building!"
print("")

for x in range (0,90):
    print ("Connecting to controller in " + str(90 - x) + " seconds. Packages should be installed by then.")
    sys.stdout.write("\033[F")
    time.sleep(1)

print("Please log into the controller now. (IPv4: " + str(dst_ip) + ")" + " (Password: " + str(dst_srvr_pass) + ")")

os.system('ssh-keyscan ' + str(dst_ip) + ' >> ~/.ssh/known_hosts')
os.system('ssh root@' + dst_ip)
