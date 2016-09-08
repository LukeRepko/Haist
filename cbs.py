import requests
import json
def jprint(jsondoc):
    print json.dumps(jsondoc, sort_keys=True, indent=2, separators=(',', ': '))
server_to_match = ""

token = ""
headers = {"X-Auth-Token": token}
url = "https://dfw.blockstorage.api.rackspacecloud.com/v1/account/volumes/detail"

r = requests.get(url,headers=headers)

rvol = r.json()['volumes']

found = False

for volume in rvol:
    attachments = volume['attachments']
    for attachment in attachments:
        if attachment['server_id'] == server_to_match:
            found = True
            v = volume

if found:
    jprint(v)
    for attachment in v['attachments']:
        print attachment['volume_id']

else:
    print("no exist")
