#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>

#define PROTO_UDP	17
#define DROP_PORT	3050
#define UDP_HLEN	8

static struct nf_hook_ops nfho;

unsigned int hook_func(const struct nf_hook_ops *ops,
		       struct sk_buff *skb,
		       const struct nf_hook_state *state)
{
	struct iphdr *ip_header = (struct iphdr *)skb_network_header(skb);
	struct udphdr *udp_header;

	/* drop udp packets with dst port DROP_PORT */
	if (ip_header->protocol == PROTO_UDP) {
		udp_header = (struct udphdr *)skb_transport_header(skb);
		if (ntohs(udp_header->dest) == DROP_PORT) {
			char *payload;
			int len = ntohs(udp_header->len) - UDP_HLEN;

			printk("__galp__: drop packet with dst udp port %d\n", DROP_PORT);
			payload = kzalloc(len, GFP_KERNEL);
			if (!payload) {
				printk("__galp__: NOMEM\n");
				return NF_DROP;
			}

			memcpy(payload, (u8 *)udp_header + UDP_HLEN, len);
			printk("__galp__: %s\n", payload);
			kfree(payload);
			return NF_DROP;
		}
	}
	return NF_ACCEPT;
}

int init_module()
{
	nfho.hook = hook_func;
	nfho.hooknum = 0; /* called right after packet recieved, first hook in Netfilter */
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST; /* set to highest priority over all other hook functions */

	printk("__galp__: module loaded\n");
	nf_register_hook(&nfho);
	return 0;
}

void cleanup_module()
{
	printk("__galp__: bye bye\n");
	nf_unregister_hook(&nfho);
}
