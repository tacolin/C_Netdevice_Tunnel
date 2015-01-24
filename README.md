# C_Netdevice_Tunnel

Implement a UDP tunnel by Virutal Net Device and Netfilter Hook

Only the following packets can be passed in this tunnel:

* ARP request / reply
* IPV4 ICMP request / reply
* IPV4 TCP packets
* IPV4 UDP packets

## File Descriptions

| File        | Descriptions                                                          |
|-------------|-----------------------------------------------------------------------|
| kmain.c     | kernel init / exit functions.                                         |
| kdev.c      | create virtual net device and implement tunnel tx.                    |
| kfilter.c   | create net filter hook and implement tunnel rx.                       |
| taco.h      | linux heraders, defined values, macros, type / function declarations. |
 

## Verification Environment

* Ubuntu 14.04 i386 and amd64 - Kernel version 3.13.0
* Mint 17 i386 and amd64      - Kernel version 3.13.0

## How to test?

Prepare 2 computers : COMPUTER A and COMPUTER B

* COMPUTER A : Real ip address 192.168.1.1
* COMPUTER B : Real ip address 192.168.1.2

Build your proejct, and insert kernel module in COMPUTER A:

    $ cd C_Netdevice_Tunnel
    $ make 
    $ sudo insmod taco.ko g_dst=192.168.1.2
    $ sudo ifconfig taco01 10.10.10.1 netmask 255.255.255.0

You will see the new network interface "taco01" with ipaddr "10.10.10.1"

Do it again in COMPUTER B:

    $ sudo insmod taco.ko g_dst=192.168.1.1
    $ sudo ifconfig taco01 10.10.10.2 netmask 255.255.255.0

you will see the new network interface "taco01" with ipaddr "10.10.10.2"

In COMPUTER A:
    $ ping 10.10.10.2 
In COMPUTER B:
    $ ping 10.10.10.1

## Tunnel Data Transmission Flow

### Tx
    User Space Program (ex. PING) 
    -> LINUX TCP/IP Protocol Stack 
    -> Virtual Net Device(taco01) ndo_start_xmit() = my_start_xmit()
       pack tunnel header, change outgoing device, ...
    -> Real Net Device(eth0) 
    -> Ethernet Cable

### Rx
    Ethernet Cable
    -> Real Net Device(eth0)
    -> Net filter hook function = my_hook_fn()
       unpack tunnel header, change incoming device, ...
    -> LINUX TCP/IP Protocol Stack
    -> User Space Program (ex. PING)


## Reference

1.[netpoll_send_udp()](http://lxr.oss.org.cn/source/net/core/netpoll.c#L431)

