#include "taco.h"

static struct net_device* my_netdev = NULL;

static bool is_wanted_data(struct sk_buff* skb)
{
    struct ethhdr* eth = eth_hdr(skb);
    struct iphdr* iph  = ip_hdr(skb);

    if (!skb) return false;

    if (!eth) return false;

    if (ETH_P_ARP == ntohs(eth->h_proto)) return true;

    if (ETH_P_IP == ntohs(eth->h_proto)) {
        if (!iph) return false;

        if (iph->protocol == IPPROTO_UDP)  return true;

        if (iph->protocol == IPPROTO_TCP)  return true;

        if (iph->protocol == IPPROTO_ICMP) return true;
    }

    return false;
}

static void pack_tunnel_udp_header(struct sk_buff* skb, int udp_len, u32 srcip, u32 dstip)
{
    struct udphdr* udph = NULL;

    skb_push(skb, sizeof(struct udphdr));
    skb_reset_transport_header(skb);

    udph         = udp_hdr(skb);
    udph->source = htons(g_port);
    udph->dest   = htons(g_port);
    udph->len    = htons(udp_len);

    udph->check = 0;
    udph->check = csum_tcpudp_magic(srcip, dstip, udp_len, IPPROTO_UDP, csum_partial(udph, udp_len, 0));
}

static void pack_tunnel_ip_header(struct sk_buff* skb, int ip_len, u32 srcip, u32 dstip)
{
    static atomic_t ip_ident;

    struct iphdr* iph = NULL;

    skb_push(skb, sizeof(struct iphdr));
    skb_reset_network_header(skb);

    iph = ip_hdr(skb);
    // the following line is equivalent to iph->version = 4; iph->ihl = 5;
    put_unaligned(0x45, (unsigned char*)iph);
    iph->tos = 0;
    put_unaligned(htons(ip_len), &(iph->tot_len));
    iph->id = htons(atomic_inc_return(&ip_ident));
    iph->frag_off = 0;
    iph->ttl = 64;
    iph->protocol = IPPROTO_UDP;
    iph->check = 0;
    put_unaligned(srcip, &(iph->saddr));
    put_unaligned(dstip, &(iph->daddr));

    iph->check = ip_fast_csum((unsigned char*)iph, iph->ihl);
}

static void pack_tunnel_eth_header(struct sk_buff* skb, u8* srcmac, u8* dstmac)
{
    struct ethhdr* eth = (struct ethhdr*)skb_push(skb, ETH_HLEN);
    skb_reset_mac_header(skb);

    skb->protocol = eth->h_proto = htons(ETH_P_IP);
    memcpy(eth->h_source, srcmac, ETH_ALEN);
    memcpy(eth->h_dest,   dstmac, ETH_ALEN);
}

static struct rtable* find_routing_table(u32 dstip)
{
    struct flowi4 fl4 = {.daddr = dstip};
    struct rtable* rtbl = NULL;
    rtbl = ip_route_output_key(&init_net, &fl4);

    // NOTICE:
    //
    // ip_route_output_key will return an NON-NULL address even if no routing table found.
    // system will be crached (or stuck?) if accessing it.
    //
    // it is necessary that do an extra check by IS_ERR().

    return (rtbl && !IS_ERR(rtbl)) ? rtbl : NULL;
}

static u32 find_source_ip(struct rtable* rtbl)
{
    struct in_device* indev = __in_dev_get_rtnl(rtbl->dst.dev);
    return indev->ifa_list->ifa_local;
}

static void get_destination_mac(u32 dstip, struct rtable* rtbl, u8* dstmac)
{
    extern struct neigh_table arp_tbl;
    struct neighbour* neigh = neigh_lookup(&arp_tbl, &dstip, rtbl->dst.dev);
    if (!neigh || IS_ERR(neigh)) {
        // do broadcast if no neighbour exists.
        // i know it is a little dirty, but works.
        memset(dstmac, 0xff, ETH_ALEN);
    } else {
        memcpy(dstmac, neigh->ha, ETH_ALEN);
    }
}

static int pack_tunnel_skb(struct sk_buff* skb)
{
    // i copy some contents in netpoll_send_udp(), modify them,
    // and separate them into the following functions:
    //
    // 1. this function (pack_tunnel_skb)
    // 2. pack_tunnel_udp_header
    // 3. pack_tunnel_ip_header
    // 4. pack_tunnel_eth_header
    //
    // if you want to know more,
    // see netpoll_send_udp() in "netpoll.c" of linux kernel source.

    int payload_len, udp_len, ip_len;
    u32 srcip, dstip;
    u8  srcmac[ETH_ALEN], dstmac[ETH_ALEN];
    struct rtable* rtbl = NULL;
    int chk;

    payload_len = skb->len;
    udp_len     = payload_len + sizeof(struct udphdr);
    ip_len      = udp_len + sizeof(struct iphdr);

    chk = my_inet_pton(AF_INET, g_dst, &dstip);
    check_if(chk < 0, goto error, "my_inet_pton failed");

    rtbl = find_routing_table(dstip);
    check_if(rtbl == NULL, goto error, "find_routing_table failed");

    srcip = find_source_ip(rtbl);

    memcpy(&srcmac, rtbl->dst.dev->dev_addr, ETH_ALEN);
    get_destination_mac(dstip, rtbl, dstmac);

    pack_tunnel_udp_header(skb, udp_len, srcip, dstip);
    pack_tunnel_ip_header(skb, ip_len, srcip, dstip);
    pack_tunnel_eth_header(skb, srcmac, dstmac);

    skb->dev = rtbl->dst.dev;

    return 0;

error:
    return -1;
}

static void send_by_tunnel(struct sk_buff* skb)
{
    struct sk_buff* newskb = NULL;
    // tunnel header will be packed by ourself
    // we can limit ip header size to 20 bytes = sizeof(struct iphdr)
    int headroom = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
    int chk;

    // skb_realloc_headroom will return a new skb which is created by skb_clone or skb_copy in different cases.
    newskb = skb_realloc_headroom(skb, headroom);
    check_if(newskb == NULL, goto error, "skb_realloc_headroom failed");

    chk = pack_tunnel_skb(newskb);
    check_if(chk < 0, goto error, "pack_tunnel_skb failed");

    chk = dev_queue_xmit(newskb);
    check_if(chk < 0, goto error, "dev_queue_xmit failed");

    return;

error:
    if (newskb) kfree_skb(newskb);
}

netdev_tx_t my_start_xmit(struct sk_buff* skb, struct net_device* dev)
{
    rcu_read_lock();

    // send the necessary data by tunnel
    if (is_wanted_data(skb)) send_by_tunnel(skb);

    // orphan != kfree, you should do them both ... maybe? (@_@)
    if (unlikely(skb_orphan_frags(skb, GFP_ATOMIC))) goto drop;

    skb_orphan(skb);

    dev->stats.tx_packets++;
    dev->stats.tx_bytes += skb->len;
    kfree_skb(skb);
    rcu_read_unlock();
    return NETDEV_TX_OK;

drop:
    dev->stats.tx_dropped++;
    skb_tx_error(skb);
    kfree_skb(skb);
    rcu_read_unlock();
    return NETDEV_TX_OK;
}

static int my_change_mtu(struct net_device* dev, int new_mtu)
{
    dev->mtu = (new_mtu > 1500) ? 1500 : new_mtu;
    dprint("change mtu to %d", dev->mtu);
    return 0;
}

static const struct net_device_ops my_net_dev_ops =
{
    .ndo_start_xmit      = my_start_xmit,
    .ndo_change_mtu      = my_change_mtu,

    .ndo_set_mac_address = eth_mac_addr,
    .ndo_validate_addr   = eth_validate_addr,
};

static void config_my_netdev(void)
{
    my_netdev->netdev_ops = &my_net_dev_ops;
    ether_setup(my_netdev);
    eth_hw_addr_random(my_netdev);
    snprintf(my_netdev->name, IFNAMSIZ, g_name);

    // NOTICE:
    //
    // it is necessary to reserve the headroom for tunnel headers.
    // data after packing tunnel headers may exceed 1514 bytes (max ethernet frame size) if you forget it.
    //
    // life should be spent on beautiful things.
    // drecrease MTU size, and keep the dirty work (fragment/reassemble) to linux system.
    //
    // for safety, we use max ip header size (60 bytes) in calculation.
    my_netdev->mtu = 1500 - (sizeof(struct ethhdr) + 60 + sizeof(struct udphdr));
    return;
}

struct net_device* get_my_netdev(void)
{
    return my_netdev;
}

int create_my_netdev(void)
{
    int chk;

    my_netdev = alloc_etherdev(0);
    check_if(my_netdev == NULL, goto error, "alloc_etherdev failed");

    config_my_netdev();

    chk = register_netdev(my_netdev);
    check_if(chk < 0, goto error, "register_netdev failed");

    return 0;

error:
    if (my_netdev) free_netdev(my_netdev);
    return -1;
}

int destroy_my_netdev(void)
{
    if (my_netdev) {
        unregister_netdev(my_netdev);
        free_netdev(my_netdev);
    }

    return 0;
}
