#include "taco.h"

static struct nf_hook_ops my_hook = {};

static bool is_tunnel_data(struct sk_buff* skb)
{
    // tunnel data should fit the following conditions:
    //
    // 1. ip data
    // 2. ip src = g_dst
    // 3. udp data
    // 4. udp dst port = g_port (default 50000)

    struct ethhdr* eth  = eth_hdr(skb);
    struct iphdr*  iph  = ip_hdr(skb);
    struct udphdr* udph = udp_hdr(skb);
    u32 srcip;
    int chk;

    if (!skb) return false;

    if (!eth) return false;
    if (ntohs(eth->h_proto) != ETH_P_IP) return false;

    chk = my_inet_pton(AF_INET, g_dst, &srcip);
    if (chk < 0) return false;

    if (!iph) return false;
    if (iph->saddr != srcip) return false;
    if (iph->protocol != IPPROTO_UDP) return false;

    if (!udph) return false;
    if (ntohs(udph->dest) != g_port) return false;

    return true;
}

static unsigned int my_hook_fn(const struct nf_hook_ops *ops,
                           struct sk_buff *skb,
                           const struct net_device *in,
                           const struct net_device *out,
                           int (*okfn)(struct sk_buff*))
{
    if (is_tunnel_data(skb)) {

        // NOTICE:
        //
        // skb->data is already the beginning of ip header.
        //
        //           <------------ skb->len ------------->
        // +---------+--------+---------+----------------+
        // | eth hdr | ip hdr | udp hdr | Tunnel payload |
        // +---------+--------+---------+----------------+
        //           |
        //           +---> skb->data
        //
        struct iphdr* iph = ip_hdr(skb);

        // we can limit ip header size to 20 bytes when sending.
        // but we can't limit the opposite side of the tunnel.
        // for safety, you should calculate ip header size by ihl field at receiving.
        int iphsize = iph->ihl << 2;
        int rest_tunnel_header_size = iphsize + sizeof(struct udphdr);
        int datalen;
        struct net_device* mydev = get_my_netdev();

        skb_pull(skb, rest_tunnel_header_size);
        datalen = skb->len;

        // after skb_pull:
        //
        //                              <--- skb->len --->
        // +---------+--------+---------+----------------+
        // | eth hdr | ip hdr | udp hdr | Tunnel payload |
        // +---------+--------+---------+----------------+
        //                              |
        //              skb->data <-----+
        //

        skb->dev = mydev;
        skb->protocol = eth_type_trans(skb, mydev);
        skb->ip_summed = CHECKSUM_UNNECESSARY;

        if (netif_rx(skb) == NET_RX_SUCCESS) {
            mydev->stats.rx_packets++;
            mydev->stats.rx_bytes += datalen;
            return NF_STOLEN;
        } else {
            mydev->stats.rx_dropped++;
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}


int create_my_netfilter_hook(void)
{
    my_hook.pf       = PF_INET;
    my_hook.hooknum  = NF_INET_LOCAL_IN;
    // PRI_FIRST or PRI_LAST will both be ok
    my_hook.priority = NF_IP_PRI_FIRST;
    my_hook.hook     = my_hook_fn;

    return nf_register_hook(&my_hook);
}

int destroy_my_netfilter_hook(void)
{
    nf_unregister_hook(&my_hook);
    return 0;
}
