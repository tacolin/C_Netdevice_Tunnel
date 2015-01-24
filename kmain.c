#include "taco.h"

MODULE_AUTHOR("tacolin");
MODULE_DESCRIPTION("KERNEL SPACE TUNNEL");
MODULE_LICENSE("GPL");

char* g_name = "taco01";  // interface name
char* g_dst  = NULL;      // tunnel opposite site real ip address
int   g_port = 50000;     // tunnel udp destination port

module_param(g_name, charp, S_IRUSR);
module_param(g_dst,  charp, S_IRUSR);
module_param(g_port, int,   S_IRUSR);

static int __init taco_init(void)
{
    int chk;

    check_if(g_dst == NULL, return -1, "no destination real ip");

    chk = create_my_netdev();
    check_if(chk < 0, return -1, "create_my_netdev failed");

    chk = create_my_netfilter_hook();
    check_if(chk < 0, return -1, "create_my_netfilter_hook failed");

    dprint("init ok");
    return 0;
}

static void __exit taco_exit(void)
{
    destroy_my_netfilter_hook();
    destroy_my_netdev();

    dprint("exit ok");
    return;
}

module_init(taco_init);
module_exit(taco_exit);
