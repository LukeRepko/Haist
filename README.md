# Haist. High.Altitude.Intercontinental.Server.Transmitter

Use this script to clone a Rackspace public cloud server to the same, or another datacenter. This is accomplished by building a new server of the desired flavor and size to the datacenter you choose. Both the original, and new servers are placed into rescue mode so that the original server's file system can be systematically cloned (block for block) using the linux command line utility, "dd".

The destination server's disk size must be the same size, or larger than the original server's disk. This script has "bumpers" which will prevent a smaller local disk, or block storage volume from being specified for the destination server.

Do you have an old Standard flavor server that you'd like to upgrade to a performance flavor like Compute, Memory, or I/O? Using Haist, this can be done with ease. No more fighting with images!

```
This script is still a work in progress!

control.py can be used to stand up a control server which gets booted with a config drive and user_data.
Once built, you can log into the control server with the provided username and password where the
main script will be presented to you in a screen session - ready to hastily clone a server!

The main script, "haist.py" can also be run from a local workstation, but this is not reccommended.
```
