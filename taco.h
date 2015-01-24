#ifndef _TACO_H_
#define _TACO_H_

#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/version.h>

#include <linux/etherdevice.h>
#include <linux/netdevice.h>

#include <uapi/linux/if_ether.h>  // for ETH_P_IP define value
#include <uapi/linux/ip.h>        // for struct iphdr
#include <uapi/linux/udp.h>       // for struct udphdr
#include <uapi/linux/in.h>        // for IPPROTO_ICMP
#include <linux/inet.h>           // for in4_pton
#include <net/sock.h>             // for IPPROTO_IP, SOCK_DGRAM, AF_INET
#include <linux/inetdevice.h>     // for struct in_device
#include <net/route.h>            // for routing table
#include <linux/netfilter_ipv4.h> // for netfilter
#include <linux/netfilter_arp.h>  // for netfilter

//////////////////////////////////////////////////////////////////////////////
//      Macros
//////////////////////////////////////////////////////////////////////////////
#define dprint(a, b...) printk("%s(): "a"\n", __func__, ##b)
#define derror(a, b...) printk("[ERROR] %s(): "a"\n", __func__, ##b)

#define check_if(assertion, error_action, ...) \
{\
    if (assertion) \
    { \
        derror(__VA_ARGS__); \
        {error_action;} \
    }\
}

#define fn_apply_all(type, fn, ...) \
{\
    void* _stopPoint = (int[]){0};\
    void** _listForApplyAll = (type[]){__VA_ARGS__, _stopPoint};\
    int i;\
    for (i=0; _listForApplyAll[i] != _stopPoint; i++)\
    {\
        fn(_listForApplyAll[i]);\
    }\
}


//////////////////////////////////////////////////////////////////////////////
//      Inline Functions
//////////////////////////////////////////////////////////////////////////////
static inline int my_inet_pton(int af, const char *src, void *dst)
{
    if (AF_INET == af) {
        return in4_pton(src, strlen(src), (u8*)dst, '\0', NULL);
    } else if (AF_INET6 == af) {
        return in6_pton(src, strlen(src), (u8*)dst, '\0', NULL);
    } else {
        return -1;
    }
}

//////////////////////////////////////////////////////////////////////////////
//      Module Parameters
//////////////////////////////////////////////////////////////////////////////
extern char* g_name;
extern char* g_dst;
extern int   g_port;

//////////////////////////////////////////////////////////////////////////////
//      Functions
//////////////////////////////////////////////////////////////////////////////
int create_my_netdev(void);
int destroy_my_netdev(void);
struct net_device* get_my_netdev(void);

int create_my_netfilter_hook(void);
int destroy_my_netfilter_hook(void);

#endif // _TACO_H_
