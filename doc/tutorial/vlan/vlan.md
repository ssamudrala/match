# Match interface: accelerating VLAN with match interface
###### 2015-10-13


## Introduction

This document provides a brief description on using match interface to use the hardware to push/ pop/ set VLANs.


## Basics

For this we use fm10k driver with UIO support. Note that, this is not the same as fm10k driver that is included with released kernels. To load the driver use either 'insmod' or 'modprobe'

```
# insmod ./fm10k.ko
```

The simplest way I know to check for UIO support is to verify fm10k linked with uio.

```
# lsmod|grep fm10k
fm10k                 115316  1
vxlan                  37619  1 fm10k
uio                    19360  3 fm10k
ptp                    18933  2 fm10k,e1000e
```

The critical line is 'uio'. If that is missing then the driver is not built or does not support UIO.
UIO is out of scope for this document but is used to map the PCI bars into userspace for match interface.

Next start matchd,

```
# matchd -s
```

The '-s' is required to put all ports in the default VLAN group. 'matchd' does not support a daemon mode yet so it will not return from the command prompt. Users can either start it in the background or in another terminal. Starting it in another terminal and launching with the verbose '-v' option allows the user to see useful information describing how/ when the hardware is being programmed. To start in the background use '&' like,

```
# matchd -s &
```
Once 'matchd' is started its worth running a few basic test to verify it is up and running.

```
# match get_actions
       1: set_egress_port ( u32 egress_port )
       13: drop_packet (  )
       14: route_via_ecmp ( u16 ecmp_group_id )
       15: route ( u64 newDMAC, u16 newVLAN )
       3: set_dst_mac ( u64 mac_address )
       2: set_src_mac ( u64 mac_address )
       5: set_ipv4_dst_ip ( u32 ip_address )
       6: set_ipv4_src_ip ( u32 ip_address )
       10: set_udp_src_port ( u16 port )
  ...
```

The above command will list all the actions the attached device supports. If this works the basics are up and running.

## Test Environment

The base test environment for this document is an fm10k device running back to back with another fm10k device.

When fm10k is loaded, net devices will be created. On my system the fm10k device netdev is named 'p6p1' on both Host 1 and Host 2.


At this point a sanity check is usually worthwhile. So, I assign IP addresses 60.0.0.1/24 to 'p6p1' interface on Host 1, 60.0.0.2/24 to 'p6p1' interface on Host 2 and attempt a ping,

```
# ping 60.0.0.1
PING 60.0.0.1 (60.0.0.1) 56(84) bytes of data.
64 bytes from 60.0.0.1: icmp_seq=1 ttl=64 time=0.706 ms
64 bytes from 60.0.0.1: icmp_seq=2 ttl=64 time=0.154 ms
```

This base setup is tweaked to test out the VLAN actions. We attempt to ping Host 2 from Host 1.

VLAN membership may be added using match interface. For example,

```
match set_port port 1 vlans 1,100
```



## TCAM VLAN Actions
##### Push VLAN

This TCAM action could be used to push a new outermost VLAN header onto the frame.

##### Set VLAN

This TCAM action could be used to set the VLAN ID of the frame to a new value.

##### Pop VLAN

This TCAM action could be used to pop the outermost VLAN header from the frame. After popping the VLAN header, it sets the VLAN to the default value of 1.


## Push VLAN Use-Case

Figure 1 shows the test setup.


![Alt text](https://github.com/match-interface/match/blob/master/doc/tutorial/vlan/img1.png "Figure 1: Push VLAN Test Setup")

##### Host 1

IP address 60.0.0.1/24 is assigned to 'p6p1' interface on Host 1.

```
# ifconfig p6p1 60.0.0.1/24
```

We push a new VLAN header with VLAN ID 100 for packets ingressing the switch untagged from the PEP port (Port 20). Ethernet port (in our case Port 1) needs to be a tagged member of VLAN 100. This is needed so that the frame will egress the switch port with the VLAN tag inserted.

```
# match create source 1 name push-vlan id 20 size 64 match ig_port_metadata.ingress_port mask action push_vlan

# match set_rule prio 10 handle 5 table 20 match ig_port_metadata.ingress_port 20 action push_vlan 100
```

##### Host 2

IP address 60.0.0.2/24 is assigned to 'p6p1' interface on Host 2.

```
# ifconfig p6p1 60.0.0.2/24
```

We pop the VLAN header from the packets ingressing the switch from the Ethernet port (Port 1).  Ethernet port and PEP port VLAN memberships are not required.

```
# match create source 1 name pop-vlan id 20 size 64 match ig_port_metadata.ingress_port mask match vlan.vid mask action pop_vlan

# match set_rule prio 10 handle 5 table 20 match ig_port_metadata.ingress_port 1 match vlan.vid 100 action pop_vlan
```

Ping Host 2 from Host 1

```
# ping 60.0.0.2
```
When we run a packet capturing tool like tcpdump on 'p6p1' interface on Host 1, we see VLAN packets with VLAN ID 100. Running tcpdump on 'p6p1' interface on Host 2, shows no VLAN packets. This shows a new VLAN header being pushed in Host 1 and popped in Host 2.



## Set VLAN Use-Case

Figure 2 shows the test setup.


![Alt text](https://github.com/match-interface/match/blob/master/doc/tutorial/vlan/img2.png "Figure 2: Set VLAN Test Setup")

##### Host 1

On Host 1, add a new VLAN 'p6p1.150' on interface 'p6p1'

```
# ip link add link p6p1 name p6p1.150 type vlan id 150
```

Assign IP address 60.0.0.1/24 to this VLAN interface and bring up the interface:

```
# ifconfig p6p1.150 60.0.0.1/24
# ifconfig p6p1.150 up
```
We set the VLAN ID to 150 for packets ingressing the switch from Ethernet port with VALN ID 100. Ethernet port (Port 1) and PEP port (Port 20) need to be a tagged member of VLAN 150.

```
# match create source 1 name set-vlan id 20 size 64 match ig_port_metadata.ingress_port mask match vlan.vid mask action set_vlan

# match set_rule prio 10 handle 5 table 20 match ig_port_metadata.ingress_port 1 match vlan.vid 100 action set_vlan 150
```


##### Host 2

On Host 2, we add a new VLAN 'p6p1.100' on interface 'p6p1'

```
# ip link add link p6p1 name p6p1.100 type vlan id 100
```
Assign IP address 60.0.0.2/24 to this VLAN interface and bring up the interface:

```
# ifconfig p6p1.100 60.0.0.2/24
# ifconfig p6p1.100 up
```

For packets ingressing the switch from Ethernet port we set the VLAN from 150 to 100. Ethernet port (Port 1) and PEP port (Port 20) need to be a tagged member of VLAN 100.

```
# match create source 1 name set-vlan id 20 size 64 match ig_port_metadata.ingress_port mask action set_vlan

# match set_rule prio 10 handle 5 table 20 match ig_port_metadata.ingress_port 1 action set_vlan 100
```


Ping Host 2 from Host 1

```
# ping 60.0.0.2
```
When we run tcpdump on 'p6p1' interface on Host 1, we can see VLAN packets with VLAN ID 150. Running tcpdump on 'p6p1' interface on Host 2 shows VLAN packets with VLAN ID 100. This clearly exhibits set VLAN action.


## Pop VLAN Use-Case

Figure 3 shows the test setup.


![Alt text](https://github.com/match-interface/match/blob/master/doc/tutorial/vlan/img3.png "Figure 3: Pop VLAN Test Setup")

##### Host 1

IP address 60.0.0.1/24 is assigned to 'p6p1' interface on Host 1.

```
# ifconfig p6p1 60.0.0.1/24
```

On Host 1, Ethernet Port (Port 1) is a tagged member and PEP Port (Port 20) is an untagged member of VLAN 1 (default VLAN). No rules are set on Host 1.

##### Host 2

On Host 2, we add a new VLAN 'p6p1.100'

```
# ip link add link p6p1 name p6p1.100 type vlan id 100
```

Assign IP address 60.0.0.2/24 to this VLAN interface and bring up the interface:

```
# ifconfig p6p1.100 60.0.0.2/24
# ifconfig p6p1.100 up
```

We set the VLAN for packets ingressing the switch from Ethernet port to 100. We also pop the VLAN for packets ingressing the switch from the PEP port.  Ethernet port (Port 1) and PEP Port (Port 20) need to be tagged members of VLAN 100.

```
# match create source 1 name set-pop-vlan id 20 size 64 match ig_port_metadata.ingress_port mask action set_vlan action pop_vlan

# match set_rule prio 10 handle 5 table 20 match ig_port_metadata.ingress_port 1 action set_vlan 100
# match set_rule prio 10 handle 5 table 20 match ig_port_metadata.ingress_port 20 action pop_vlan
```

Ping Host 2 from Host 1

```
# ping 60.0.0.2
```
When we run tcpdump on 'p6p1' interface on Host 2, we can see VLAN packets with VLAN ID 100.


