node-red-contrib-n2n
====================

A <a href="http://nodered.org" target="_new">Node-RED</a> node that provides
automatic links between different topics on Node-RED instances within UDP multicast range.

**Only use this for short messages like data readings**.

Install
-------

Run the following command in your Node-RED user directory - typically `~/.node-red`

    npm install node-red-contrib-n2n

Uses multicast to send packets - if you have multiple network adapters you may need to
set a static multicast route - for example

    Linux - sudo route add -net 225.0.18.83 netmask 255.255.255.255 dev eth0
    Mac   - sudo route add -net 225.0.18.83/32 -interface en0

where eth0/en0 is the network interface you wish to use.

Usage
-----

**Only use this for short messages like data readings**.

Discover other Node-RED devices on the network and open channels from them.

You can specify what topics are of interest. The node will "request" these from remote instances.
The remote node will only send data if the message has a **msg.topic** that matches.

Topics of interest are specified by a regex string.

 - ^[0-9]{3}$ - matches a 3 digit number
 - ^cat.* - matches topics starting with cat. cats, cathedral, catastrophe

Also outputs **msg.host** - the hostname of the sending node, and
**msg.hostip** - the ip of the sending node.

The network interface for the multicast can be fixed if required. If not it will try
to bind to all available interfaces - which will probably work fine for input - but may not necessarily
route out correctly - see above for how to set a static multicast route.

**Note:** the MTU may well restrict the message to around 1500 characters.
**Only use this for short messages like data readings**.
