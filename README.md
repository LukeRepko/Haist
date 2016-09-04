# Haist. High.Altitude.Server.Transmitter

This script can be used to systematically clone a Rackspace public cloud server to another, or the same datacenter. It creates a new, "skeleton" server which receives the clone of the source server. 

The source server will be placed into rescue mode where /dev/xvdb will be copied (block-for-block) to the destination server which will also be in rescue mode to receive and process the incoming data transmission.
