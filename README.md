# Haist. High.Altitude.Server.Transmitter

This script can be used to systematically (hastily) clone a Rackspace public cloud server to another, or the same datacenter. It creates a new, "skeleton" server which receives the clone of the source server. 

The source server will be placed into rescue mode where /dev/xvdb will be copied (block-for-block) to the destination server which will also be in rescue mode to receive and process the incoming data transmission.

## Warning...
```
This script is still a work in progress!

control.py can be used to stand up a control server which gets booted with a config drive and user_data. 
Once built, you can log into the control server with the provided username and password where the 
main script will be presented to you in a screen session - ready to hastily clone a server! 

The main script, "haist.py" can also be run from a local workstation, but this is not reccommended.
```
