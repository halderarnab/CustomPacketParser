/* SPDX-License-Identifier: GPL-2.0 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <linux/in6.h>
#include "tokens.h"

/* Notice how this XDP/BPF-program contains several programs in the same source
 * file. These will each get their own section in the ELF file, and via libbpf
 * they can be selected individually, and via their file-descriptor attached to
 * a given kernel BPF-hook.
 *
 * The libbpf bpf_object__find_program_by_title() refers to SEC names below.
 * The iproute2 utility also use section name.
 *
 * Slightly confusing, the names that gets listed by "bpftool prog" are the
 * C-function names (below the SEC define).
 */

struct token_params {
    __u64 timestamp;
    __u64 prop_delay;
    __u32 num_tokens;
    __u64 dropped;
    __u64 transmitted;
} __attribute__((packed));

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __type(key, __u16); /* TCP or UDP dst port */
        __type(value, struct token_params);
        __uint(max_entries, MAX_NUM_FLOWS);
} token_map SEC(".maps");

struct network_xor {
        char filled[8]; /* either 0 or "result" */
        __u32 first; /* first operand, will also hold the result eventually */
        __u32 second; /* second operand */
} __attribute__((packed));

int token_bucket_policer(__u16 key) {
        if(MAX_TOKENS == 0){
                bpf_printk("\n MAX_TOKENS is 0.");
                return 0;
        }

        void *params = bpf_map_lookup_elem((void*)&token_map, (void*)&key);
        if(params == NULL) {
                bpf_printk("\n params empty, bpf_map_lookup_elem is NULL");
                struct token_params new_params = {
                        .timestamp = bpf_ktime_get_ns(),
                        .prop_delay = 0,
                        .num_tokens = MAX_TOKENS - 1,
                        .dropped = 0,
                        .transmitted = 1
                };
                bpf_map_update_elem((void*)&token_map, (void*)&key, (void*)&new_params, BPF_NOEXIST);
                bpf_printk("\n New token_param inserted in map. timestamp: %lu, num_tokens: %u, prop_delay: %lu ", new_params.timestamp, new_params.num_tokens, new_params.prop_delay);
                bpf_printk("\n dropped: %lu, transmitted: %lu ", new_params.dropped, new_params.transmitted);
        } else {
                struct token_params* new_params = (struct token_params*)params;
                bpf_printk("\n params NOT empty, bpf_map_lookup_elem found. timestamp: %lu, num_tokens: %u, prop_delay: %lu", new_params->timestamp, new_params->num_tokens, new_params->prop_delay);
                bpf_printk("\n dropped: %lu, transmitted: %lu ", new_params->dropped, new_params->transmitted);
                
                __u64 current_time = bpf_ktime_get_ns();
                bpf_printk("\n current_time: %lu,  new_params->timestamp: %lu" , current_time, new_params->timestamp);
                //Propgation delay added here to ensure that the tokens are getting filled periodically.
                __u64 time_elapsed = current_time - new_params->timestamp + new_params->prop_delay;
                bpf_printk("\n Time elapsed: %lu " , time_elapsed);

                __u32 tokens_to_add = (time_elapsed * TOKEN_RATE_PPS) / 1000000000;
                bpf_printk("\n Tokens to add: %u " , tokens_to_add);

                if(new_params->num_tokens + tokens_to_add < MAX_TOKENS)
                        new_params->num_tokens += tokens_to_add;
                else
                        new_params->num_tokens = MAX_TOKENS;
                bpf_printk("\n New num_tokens: %u, MAX_TOKENS: %u" , new_params->num_tokens, MAX_TOKENS);

                new_params->timestamp = current_time;
                new_params->prop_delay = time_elapsed % 1000000000;
                if(new_params->num_tokens > 0) {
                        new_params->num_tokens--;
                        new_params->transmitted++;
                        bpf_map_update_elem((void*)&token_map, (void*)&key, (void*)new_params, BPF_ANY);
                        bpf_printk("\n bpf_map_update_elem success. Packets transmitted: %lu, dropped: %lu", new_params->transmitted, new_params->dropped);
                        bpf_printk("\n timestamp: %lu, num_tokens: %u, prop_delay: %lu", new_params->timestamp, new_params->num_tokens,new_params->prop_delay);
                } else {
                        new_params->dropped++;
                        bpf_map_update_elem((void*)&token_map, (void*)&key, (void*)new_params, BPF_ANY);
                        bpf_printk("\n bpf_map_update_elem success. Packets dropped: %lu, transmitted: %lu", new_params->dropped, new_params->transmitted);
                        bpf_printk("\n timestamp: %lu, num_tokens: %u, prop_delay: %lu", new_params->timestamp, new_params->num_tokens,new_params->prop_delay);
                        return 0;
                }
        }
        return 1;
}

SEC("xdp")
int  xdp_pass_func(struct xdp_md *ctx)
{
        void *data = (void *)(long)ctx->data;
        void *data_end = (void *)(long)ctx->data_end;

        struct ethhdr* eth = (struct ethhdr*)data; 

        //Check if memory access is safe.
        if (data + sizeof(struct ethhdr) > data_end) 
                return XDP_DROP;

        //Converting from network to host to reorder the bytes in correct order.
        int x = bpf_ntohs(eth->h_proto);

        // bpf_printk("\n(void*)(long)ctx->data: %lx\n", (void*)(long)ctx->data);
        bpf_printk("\n x: %x", x);

        struct iphdr* ipv4;
        struct ipv6hdr* ipv6;
        int proto;

        if(x == ETH_P_IP) {
                bpf_printk("\n ETH_P_IP");
                ipv4 = (struct iphdr*)(data + sizeof(struct ethhdr));
                if((void*)ipv4 + sizeof(struct iphdr) > data_end) {
                        bpf_printk("\n ETH_P_IP: ipv4 packet dropped.");
                        return XDP_DROP;
                }
                proto = ipv4->protocol;
                bpf_printk("\n IPv4 Prtocol: %d", proto);

                if(proto == IPPROTO_TCP){
                        bpf_printk("\n IPv4 IPPROTO_TCP");
                        struct tcphdr* tcp_hdr = (struct tcphdr*)((void*)ipv4 + (ipv4->ihl * 4));

                        if((void*)tcp_hdr +  sizeof(struct tcphdr) > data_end) {
                                bpf_printk("\n TCP Protocol: ipv4 packet dropped.");
                                return XDP_DROP;
                        }
                        __be16	source = bpf_ntohs(tcp_hdr->source);
	                __be16	dest = bpf_ntohs(tcp_hdr->dest);

                        bpf_printk("\n IPv4/TCP Source: %d, Destination: %d", source, dest);

                        void *payl1 = (void*)tcp_hdr + (tcp_hdr->doff * 4);
                        // bpf_printk("\n IPv4/TCP Payload: %d", payl1);

                        if (payl1 + sizeof(struct network_xor) > data_end){
                                bpf_printk("\n XOR: IPv4/TCP packet dropped.");
                                return XDP_DROP;
                        }
                        struct network_xor* payl = (struct network_xor*)(payl1);
                        bpf_printk("\n IPv4/TCP first: %u, second: %u", payl->first, payl->second);
                        
                        if(token_bucket_policer(dest)) {
                                payl->first = bpf_htonl(bpf_ntohl(payl->first) ^ bpf_ntohl(payl->second));
                        
                                bpf_printk("\n IPv4/TCP After XOR, first: %u, second: %u", bpf_ntohl(payl->first), bpf_ntohl(payl->second));
                                
                                // long noarg_ret = BPF_SNPRINTF(payl->filled, sizeof(payl->filled), "RESULT");
                                // bpf_printk("\n noarg_ret: %ld", noarg_ret);

                                payl->filled[0] = 'R';
                                payl->filled[1] = 'E';
                                payl->filled[2] = 'S';
                                payl->filled[3] = 'U';
                                payl->filled[4] = 'L';
                                payl->filled[5] = 'T';
                                payl->filled[6] = '\0';

                                struct ethhdr temp_eth;
                                __builtin_memcpy(&temp_eth, eth, sizeof(struct ethhdr));
                                __builtin_memcpy(eth->h_dest, temp_eth.h_source, ETH_ALEN);
                                __builtin_memcpy(eth->h_source, temp_eth.h_dest, ETH_ALEN);

                                bpf_printk("\n IPv4 Before swap, ipv4->saddr: %u, ipv4->daddr: %u", ipv4->saddr, ipv4->daddr);
                                __u32 temp_ip = ipv4->saddr;
                                ipv4->saddr = ipv4->daddr;
                                ipv4->daddr = temp_ip;
                                bpf_printk("\n IPv4 After swap, ipv4->saddr: %u, ipv4->daddr: %u", ipv4->saddr, ipv4->daddr);

                                bpf_printk("\n IPv4/TCP Before swap, Source: %d, Destination: %d", source, dest);
                                tcp_hdr->source = dest;
                                tcp_hdr->dest = source;
                                bpf_printk("\n IPv4/TCP After swap, Source: %d, Destination: %d", tcp_hdr->source, tcp_hdr->dest);

                                return XDP_TX;
                        } else {
                                bpf_printk("\n Token Bucket Policer dropped the IPv4/TCP packet.");
                                return XDP_DROP;
                        }

                } else if(proto == IPPROTO_UDP){
                        bpf_printk("\n IPv4 IPPROTO_UDP");
                        struct udphdr* udp_hdr = (struct udphdr*)((void*)ipv4 + (ipv4->ihl * 4));

                        if((void*)udp_hdr +  sizeof(struct udphdr) > data_end) {
                                bpf_printk("\n UDP Protocol: ipv4 packet dropped.");
                                return XDP_DROP;
                        }
                        __be16	source = bpf_ntohs(udp_hdr->source);
	                __be16	dest = bpf_ntohs(udp_hdr->dest);

                        bpf_printk("\n IPv4/UDP Source: %d, Destination: %d", source, dest);

                        void *payl1 = (void*)udp_hdr + sizeof(struct udphdr);
                        // bpf_printk("\n IPv4/UDP Payload: %d", payl);

                        if (payl1 + sizeof(struct network_xor) > data_end){
                                bpf_printk("\n XOR: IPv4/UDP packet dropped.");
                                return XDP_DROP;
                        }
                        struct network_xor* payl = (struct network_xor*)(payl1);
                        bpf_printk("\n IPv4/UDP first: %u, second: %u", bpf_ntohl(payl->first), bpf_ntohl(payl->second));                        

                        if(token_bucket_policer(dest)) {
                                payl->first = bpf_htonl(bpf_ntohl(payl->first) ^ bpf_ntohl(payl->second));
                        
                                bpf_printk("\n IPv4/UDP After XOR, first: %u, second: %u", bpf_ntohl(payl->first), bpf_ntohl(payl->second));
                                
                                // long noarg_ret = BPF_SNPRINTF(payl->filled, sizeof(payl->filled), "RESULT");
                                // bpf_printk("\n noarg_ret: %ld", noarg_ret);

                                payl->filled[0] = 'R';
                                payl->filled[1] = 'E';
                                payl->filled[2] = 'S';
                                payl->filled[3] = 'U';
                                payl->filled[4] = 'L';
                                payl->filled[5] = 'T';
                                payl->filled[6] = '\0';

                                struct ethhdr temp_eth;
                                __builtin_memcpy(&temp_eth, eth, sizeof(struct ethhdr));
                                __builtin_memcpy(eth->h_dest, temp_eth.h_source, ETH_ALEN);
                                __builtin_memcpy(eth->h_source, temp_eth.h_dest, ETH_ALEN);

                                bpf_printk("\n IPv4 Before swap, ipv4->saddr: %u, ipv4->daddr: %u", ipv4->saddr, ipv4->daddr);
                                __u32 temp_ip = ipv4->saddr;
                                ipv4->saddr = ipv4->daddr;
                                ipv4->daddr = temp_ip;
                                bpf_printk("\n IPv4 After swap, ipv4->saddr: %u, ipv4->daddr: %u", ipv4->saddr, ipv4->daddr);
                                
                                bpf_printk("\n IPv4/UDP Before swap, Source: %d, Destination: %d", source, dest);
                                udp_hdr->source = dest;
                                udp_hdr->dest = source;
                                bpf_printk("\n IPv4/UDP After swap, Source: %d, Destination: %d", udp_hdr->source, udp_hdr->dest);
                                return XDP_TX;
                        } else {
                                bpf_printk("\n Token Bucket Policer dropped the IPv4/UDP packet.");
                                return XDP_DROP;
                        }

                } else if(proto == IPPROTO_ICMP){
                        bpf_printk("\n IPv4 IPPROTO_ICMP");
                        struct icmphdr * icmp_hdr = (struct icmphdr*)((void*)ipv4 + (ipv4->ihl * 4));

                        if((void*)icmp_hdr +  sizeof(struct icmphdr) > data_end) {
                                bpf_printk("\n ICMP Protocol: ipv4 packet dropped.");
                                return XDP_DROP;
                        }
                        __u8 icmp_type = icmp_hdr->type;
                        __u8 icmp_code = icmp_hdr->code;
                        
                        bpf_printk("\n IPv4/ICMP icmp_type: %d, icmp_code: %d", icmp_type, icmp_code);

                        void *payload = (void*)icmp_hdr + sizeof(struct icmphdr);
                        bpf_printk("\n IPv4/ICMP Payload: %d", payload);
                } else {
                        bpf_printk("\n Protocol: ipv4 packet dropped.");
                        return XDP_DROP;
                }
        } else if(x == ETH_P_IPV6) {
                bpf_printk("\n ETH_P_IPV6");
                ipv6 = (struct ipv6hdr*)(data + sizeof(struct ethhdr));
                if((void*)ipv6 + sizeof(struct ipv6hdr) > data_end) {
                        bpf_printk("\n ETH_P_IPV6: ipv6 packet dropped.");
                        return XDP_DROP;
                }
                proto =ipv6->nexthdr;
                bpf_printk("\n IPv6 nexthdr: %d", proto);

                if(proto == IPPROTO_TCP){
                        bpf_printk("\n IPv6 IPPROTO_TCP");
                        struct tcphdr* tcp_hdr = (struct tcphdr*)((void*)ipv6 + sizeof(struct ipv6hdr));
                        
                        if((void*)tcp_hdr +  sizeof(struct tcphdr) > data_end) {
                                bpf_printk("\n TCP Protocol: ipv6 packet dropped.");
                                return XDP_DROP;
                        }

                        __be16	source = bpf_ntohs(tcp_hdr->source);
	                __be16	dest = bpf_ntohs(tcp_hdr->dest);

                        bpf_printk("\n IPv6/TCP Source: %d, Destination: %d", source, dest);

                        void *payl1 = (void*)tcp_hdr + (tcp_hdr->doff * 4);
                        // bpf_printk("\n IPv6/TCP Payload: %d", payl1);

                        if (payl1 + sizeof(struct network_xor) > data_end){
                                bpf_printk("\n XOR: IPv6/TCP packet dropped.");
                                return XDP_DROP;
                        }
                        struct network_xor* payl = (struct network_xor*)(payl1);
                        bpf_printk("\n IPv6/TCP first: %u, second: %u", payl->first, payl->second);
                        
                        if(token_bucket_policer(dest)) {
                                payl->first = bpf_htonl(bpf_ntohl(payl->first) ^ bpf_ntohl(payl->second));
                        
                                bpf_printk("\n IPv6/TCP After XOR, first: %u, second: %u", bpf_ntohl(payl->first), bpf_ntohl(payl->second));
                                
                                // long noarg_ret = BPF_SNPRINTF(payl->filled, sizeof(payl->filled), "RESULT");
                                // bpf_printk("\n noarg_ret: %ld", noarg_ret);

                                payl->filled[0] = 'R';
                                payl->filled[1] = 'E';
                                payl->filled[2] = 'S';
                                payl->filled[3] = 'U';
                                payl->filled[4] = 'L';
                                payl->filled[5] = 'T';
                                payl->filled[6] = '\0';

                                struct ethhdr temp_eth;
                                __builtin_memcpy(&temp_eth, eth, sizeof(struct ethhdr));
                                __builtin_memcpy(eth->h_dest, temp_eth.h_source, ETH_ALEN);
                                __builtin_memcpy(eth->h_source, temp_eth.h_dest, ETH_ALEN);

                                __u8 temp_ip6[16];
                                __builtin_memcpy(temp_ip6, &ipv6->saddr, sizeof(__u8) * 16);
                                __builtin_memcpy(&ipv6->saddr, &ipv6->daddr, sizeof(__u8) * 16);
                                __builtin_memcpy(&ipv6->daddr, temp_ip6, sizeof(__u8) * 16);

                                bpf_printk("\n IPv6/TCP Before swap, Source: %d, Destination: %d", source, dest);
                                tcp_hdr->source = dest;
                                tcp_hdr->dest = source;
                                bpf_printk("\n IPv6/TCP After swap, Source: %d, Destination: %d", tcp_hdr->source, tcp_hdr->dest);

                                return XDP_TX;
                        } else {
                                bpf_printk("\n Token Bucket Policer dropped the IPv6/TCP packet.");
                                return XDP_DROP;
                        }

                } else if(proto == IPPROTO_UDP){
                        bpf_printk("\n IPv6 IPPROTO_UDP");
                        struct udphdr* udp_hdr = (struct udphdr*)((void*)ipv6 + sizeof(struct ipv6hdr));

                        if((void*)udp_hdr +  sizeof(struct udphdr) > data_end) {
                                bpf_printk("\n UDP Protocol: ipv6 packet dropped.");
                                return XDP_DROP;
                        }
                        __be16	source = bpf_ntohs(udp_hdr->source);
	                __be16	dest = bpf_ntohs(udp_hdr->dest);

                        bpf_printk("\n IPv6/UDP Source: %d, Destination: %d", source, dest);

                        void *payl1 = (void*)udp_hdr + sizeof(struct udphdr);
                        // bpf_printk("\n IPv6/UDP Payload: %d", payl);
                        
                        if (payl1 + sizeof(struct network_xor) > data_end){
                                bpf_printk("\n XOR: IPv6/UDP packet dropped.");
                                return XDP_DROP;
                        }

                        struct network_xor* payl = (struct network_xor*)(payl1);
                        bpf_printk("\n IPv6/UDP first: %u, second: %u", payl->first, payl->second);

                        if(token_bucket_policer(dest)) {
                                payl->first = bpf_htonl(bpf_ntohl(payl->first) ^ bpf_ntohl(payl->second));
                        
                                bpf_printk("\n IPv6/UDP After XOR, first: %u, second: %u", bpf_ntohl(payl->first), bpf_ntohl(payl->second));
                                
                                // long noarg_ret = BPF_SNPRINTF(payl->filled, sizeof(payl->filled), "RESULT");
                                // bpf_printk("\n noarg_ret: %ld", noarg_ret);

                                payl->filled[0] = 'R';
                                payl->filled[1] = 'E';
                                payl->filled[2] = 'S';
                                payl->filled[3] = 'U';
                                payl->filled[4] = 'L';
                                payl->filled[5] = 'T';
                                payl->filled[6] = '\0';

                                struct ethhdr temp_eth;
                                __builtin_memcpy(&temp_eth, eth, sizeof(struct ethhdr));
                                __builtin_memcpy(eth->h_dest, temp_eth.h_source, ETH_ALEN);
                                __builtin_memcpy(eth->h_source, temp_eth.h_dest, ETH_ALEN);

                                __u8 temp_ip6[16];
                                __builtin_memcpy(temp_ip6, &ipv6->saddr, sizeof(__u8) * 16);
                                __builtin_memcpy(&ipv6->saddr, &ipv6->daddr, sizeof(__u8) * 16);
                                __builtin_memcpy(&ipv6->daddr, temp_ip6, sizeof(__u8) * 16);

                                bpf_printk("\n IPv6/UDP Before swap, Source: %d, Destination: %d", source, dest);
                                udp_hdr->source = dest;
                                udp_hdr->dest = source;
                                bpf_printk("\n IPv6/UDP After swap, Source: %d, Destination: %d", udp_hdr->source, udp_hdr->dest);
                                return XDP_TX;
                        } else {
                                bpf_printk("\n Token Bucket Policer dropped the IPv6/UDP packet.");
                                return XDP_DROP;
                        }
                } else if(proto == IPPROTO_ICMPV6){
                        bpf_printk("\n IPv6 IPPROTO_ICMPV6");
                        struct icmp6hdr * icmp6_hdr = (struct icmp6hdr*)((void*)ipv6 + sizeof(struct ipv6hdr));

                        if((void*)icmp6_hdr +  sizeof(struct icmp6hdr) > data_end) {
                                bpf_printk("\n ICMPV6 Protocol: ipv6 packet dropped.");
                                return XDP_DROP;
                        }
                        __u8 icmp6_type = icmp6_hdr->icmp6_type;
                        __u8 icmp6_code = icmp6_hdr->icmp6_code;
                        
                        bpf_printk("\n IPv6/ICMPV6 icmp6_type: %d, icmp6_code: %d", icmp6_type, icmp6_code);

                        void *payload = (void*)icmp6_hdr + sizeof(struct icmp6hdr);
                        bpf_printk("\n IPv6/ICMPV6 Payload: %d", payload);
                } else {
                        bpf_printk("\n Nexthdr: ipv6 packet dropped.");
                        return XDP_DROP;
                }                
        } else
                return XDP_DROP;

	return XDP_PASS;
}

SEC("xdp")
int  xdp_drop_func(struct xdp_md *ctx)
{
	return XDP_DROP;
}

/* Assignment#2: Add new XDP program section that use XDP_ABORTED */

char _license[] SEC("license") = "GPL";

/* Hint the avail XDP action return codes are:

enum xdp_action {
        XDP_ABORTED = 0,
        XDP_DROP,
        XDP_PASS,
        XDP_TX,
        XDP_REDIRECT,
};
*/


