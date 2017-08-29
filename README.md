# Haist. High.Altitude.Intercontinental.Server.Transmitter

Use this script to clone a Rackspace public cloud server to the same, or another datacenter. This is accomplished by building a new server of the desired flavor and size to the datacenter you choose. Both the original, and new servers are placed into rescue mode so that the source server's file system can be systematically cloned (block for block) using the all powerful, linux command line utility, "dd" over ssh to the destination server's system disk. 

This is all accomplished with some **fairly ugly** python, but it works! :) (TL;DR this was one of my first python scripts so there is MUCH to be improved upon, and I'll get around to it one day). The underlying mechanics have shown to be fairly solid regardless. 

The destination server's disk size must be the same size, or larger than the original server's disk. This script will prevent a smaller local disk, or block storage volume from being specified for the destination server.

Do you have an old Standard flavor server that you'd like to upgrade to a performance flavor like Compute, Memory, or I/O? Using Haist, this can be done with ease. No more fighting with images!

This script is still a work in progress, and I intend to eventually add a few features, improvements, and address any open issues.

## Use:
control.py should be executed which stands up a control server. Once built, you can log into the control server with the provided username and password. After login, the main program will be presented to you in a screen session ready to take the arguments needed to begin processing.  

The main script, "haist.py" can also be run from a local workstation, but this is not reccommended.
