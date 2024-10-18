#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include "tc_ingress_clsact_filter.h" // Include the header file

// Define the function to be exported
int tc_ingress_clsact_filter(struct sk_buff *skb) {
    cant_migrate();

    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)(skb->data + skb->len);

    // Check for invalid Ethernet header and drop the packet
    if (data + sizeof(struct ethhdr) > data_end) {
        return -1; // Drop packet
    }

    struct ethhdr *eth = data;

    // If not IPv4, continue processing
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return 0; // Continue processing
    }

    // Check for invalid IP header
    if (data + sizeof(struct ethhdr) + sizeof(struct iphdr) > data_end) {
        return -1; // Drop packet
    }

    struct iphdr *ip = (struct iphdr *)(data + sizeof(struct ethhdr));
    __be32 src_ip = ip->saddr; // Get source IP

    if (src_ip == __constant_htonl(0xC0A80101)) {
        return 0; // ACCEPT packet
    }

    return -1; // DROP packet
}

// Module initialization function
static int __init tc_ingress_clsact_filter_module_init(void) {
    printk(KERN_INFO "tc_ingress_clsact_filter module loaded\n");
    return 0;
}

// Module exit function
static void __exit tc_ingress_clsact_filter_module_exit(void) {
    printk(KERN_INFO "tc_ingress_clsact_filter module unloaded\n");
}

// Register module init and exit functions
module_init(tc_ingress_clsact_filter_module_init);
module_exit(tc_ingress_clsact_filter_module_exit);

// Export the tc_ingress_clsact_filter function
EXPORT_SYMBOL(tc_ingress_clsact_filter); // Corrected export statement

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Uddhav P. Gautam");
MODULE_DESCRIPTION("Module for tc_ingress_clsact_filter functionality");
