/**
 * @file
 * of_helper.c
 *
 * This file contains the main OpenFlow helper functions
 *
 */

/*
 * This file is part of the Zodiac FX firmware.
 * Copyright (c) 2016 Northbound Networks.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Author: Paul Zanna <paul@northboundnetworks.com>
 *
 */

#include <asf.h>
#include <string.h>
#include <stdlib.h>
#include "trace.h"
#include "config_zodiac.h"
#include "openflow.h"
#include "of_helper.h"
#include "command.h"
#include "lwip/tcp.h"
#include "ipv4/lwip/ip.h"
#include "ipv4/lwip/inet_chksum.h"
#include "ipv4/lwip/ip_addr.h"
#include "lwip/tcp_impl.h"
#include "lwip/udp.h"
#include "switch.h"
#include "timers.h"

#define ALIGN8(x) (x+7)/8*8

// Global variables
extern struct zodiac_config Zodiac_Config;
extern int iLastFlow;
extern int OF_Version;
extern int totaltime;
extern uint8_t last_port_status[TOTAL_PORTS];
extern uint8_t port_status[TOTAL_PORTS];
extern struct flows_counter flow_counters[MAX_FLOWS_13];
extern struct ofp_flow_mod *flow_match10[MAX_FLOWS_10];
extern struct flow_tbl_actions *flow_actions10[MAX_FLOWS_10];
extern struct table_counter table_counters[MAX_TABLES];

// Local Variables
uint8_t timer_alt = 0;
uint8_t update_interval = 0;

static inline uint64_t (htonll)(uint64_t n)
{
	return HTONL(1) == 1 ? n : ((uint64_t) HTONL(n) << 32) | HTONL(n >> 32);
}

/*
*	Updates the IP Checksum after a SET FIELD operation.
*	Returns the flow number if it matches.
*
*	@param *p_uc_data - Pointer to the buffer that contains the packet to be updated.
*	@param packet_size - The size of the packet.
*	@param iphdr_offset - IP Header offset.
*
*/
void set_ip_checksum(uint8_t *p_uc_data, int packet_size, int iphdr_offset)
{
	struct ip_hdr *iphdr;
	struct tcp_hdr *tcphdr;
	struct udp_hdr *udphdr;
	struct icmp_echo_hdr *icmphdr;
	int payload_offset;

	iphdr = p_uc_data + iphdr_offset;
	payload_offset = iphdr_offset + IPH_HL(iphdr)*4;
	struct pbuf *p = pbuf_alloc(PBUF_RAW, packet_size - payload_offset, PBUF_ROM);
	p->payload = p_uc_data + payload_offset;
	if (IPH_PROTO(iphdr) == IP_PROTO_TCP) {
		tcphdr = (struct tcp_hdr*)(p_uc_data + payload_offset);
		tcphdr->chksum = 0;
		tcphdr->chksum = inet_chksum_pseudo(p,
		(ip_addr_t*)&(iphdr->src),
		(ip_addr_t*)&(iphdr->dest),
		IP_PROTO_TCP,
		packet_size - payload_offset);
		TRACE("of_helper.c: TCP header modified, recalculating Checksum. 0x%X", htons(tcphdr->chksum));
	}
	if (IPH_PROTO(iphdr) == IP_PROTO_UDP) {
		udphdr = (struct udp_hdr*)(p_uc_data + payload_offset);
		udphdr->chksum = 0;
		udphdr->chksum = inet_chksum_pseudo(p,
		(ip_addr_t*)&(iphdr->src),
		(ip_addr_t*)&(iphdr->dest),
		IP_PROTO_UDP,
		packet_size - payload_offset);
		TRACE("of_helper.c: UDP header modified, recalculating Checksum. 0x%X", htons(udphdr->chksum));
	}
	if (IPH_PROTO(iphdr) == IP_PROTO_ICMP) {
		icmphdr = (struct icmp_echo_hdr*)(p_uc_data + payload_offset);
		icmphdr->chksum = 0;
		icmphdr->chksum = inet_chksum(icmphdr, packet_size - payload_offset);
		TRACE("of_helper.c: ICMP header modified, recalculating Checksum. 0x%X", htons(icmphdr->chksum));
	}
	pbuf_free(p);

	IPH_CHKSUM_SET(iphdr, 0);
	IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, IPH_HL(iphdr)*4));
}

/*
*	OpenFlow house keeping timer function.
*	Calls the port stat update functions.
*	Processes timeouts for flows.
*
*/
void nnOF_timer(void)
{
	totaltime ++; // Because this is called every 500ms totaltime is actually 2 x the real time
	// Round robin the timer events so they don't have such a big impact on switching
	update_interval ++;
	if ((update_interval/2) > Zodiac_Config.stats_interval)
	{
		if (timer_alt == 0){
			if (Zodiac_Config.stats_interval > 0) update_port_stats();
			timer_alt = 1;
		} else if (timer_alt == 1){
			flow_timeouts();
			if (Zodiac_Config.stats_interval > 0) update_port_status();
			// If port status has changed send a port status message
			for (int x=0;x<TOTAL_PORTS;x++)
			{
				if (last_port_status[x] != port_status[x] && OF_Version == 1 && Zodiac_Config.of_port[x] == 1) port_status_message10(x);
			}
			timer_alt = 0;
		}
		update_interval = 2;
	}
	return;
}

/*
*	Matches packet headers against the installed flows for OpenFlow v1.0 (0x01).
*	Returns the flow number if it matches.
*
*	@param *pBuffer - pointer to the buffer that contains the packet to be macthed.
*	@param port - The port that the packet was received on.
*
*/
int flowmatch10(uint8_t *pBuffer, int port, struct packet_fields *fields)
{
	int matched_flow = -1;
	int i;
	uint8_t *eth_dst = pBuffer;
	uint8_t *eth_src = pBuffer + 6;
	uint8_t icmp_type;
	uint8_t icmp_code;
	bool port_match, eth_src_match, eth_dst_match, eth_prot_match;
	bool ip_src_match, ip_dst_match, ip_prot_match;
	bool tcp_src_match = false;
	bool tcp_dst_match = false;
	uint64_t zero_field = 0;

	if (!fields->parsed) {
		packet_fields_parser(pBuffer, fields);
	}

	TRACE("of_helper.c: Looking for match from port %d : "
	"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X -> %.2X:%.2X:%.2X:%.2X:%.2X:%.2X eth type %4.4X", port,
	eth_src[0], eth_src[1], eth_src[2], eth_src[3], eth_src[4], eth_src[5],
	eth_dst[0], eth_dst[1], eth_dst[2], eth_dst[3], eth_dst[4], eth_dst[5],
	ntohs(fields->eth_prot))

	// IP packets
	if (ntohs(fields->eth_prot) == 0x0800 && fields->ip_prot == 1)		// ICMP
	{
		memcpy(&icmp_type, pBuffer + 34, 1);
		memcpy(&icmp_code, pBuffer + 35, 1);
	}

	for (i=0;i<iLastFlow;i++)
	{
		// Make sure its an active flow
		if (flow_counters[i].active == false)
		{
			continue;
		}

		// If this flow is of a lower priority then one that is already match then there is no point going through a check.
		if (matched_flow > -1)
		{
			if(ntohs(flow_match10[i]->priority) <= ntohs(flow_match10[matched_flow]->priority)) continue;
		}

		port_match = (ntohl(flow_match10[i]->match.wildcards) & OFPFW_IN_PORT) || ntohs(flow_match10[i]->match.in_port) == port || flow_match10[i]->match.in_port == 0;
		eth_src_match = (ntohl(flow_match10[i]->match.wildcards) & OFPFW_DL_SRC) || memcmp(eth_src, flow_match10[i]->match.dl_src, 6) == 0 || memcmp(flow_match10[i]->match.dl_src, zero_field, 6) == 0;
		eth_dst_match = (ntohl(flow_match10[i]->match.wildcards) & OFPFW_DL_DST) || memcmp(eth_dst, flow_match10[i]->match.dl_dst, 6) == 0 || memcmp(flow_match10[i]->match.dl_dst, zero_field, 6) == 0;
		eth_prot_match = (ntohl(flow_match10[i]->match.wildcards) & OFPFW_DL_TYPE) || fields->eth_prot == flow_match10[i]->match.dl_type || flow_match10[i]->match.dl_type == 0;
		
		uint8_t ip_src_wild = ntohl(flow_match10[i]->match.wildcards) >> 8; // OFPFW_NW_SRC_SHIFT
		ip_src_wild &= 63; // OFPFW_NW_SRC_BITS
		ip_src_match = (ip_src_wild >= 32) || (ntohs(fields->eth_prot) == 0x0800 && (ntohl(fields->ip_src) >> ip_src_wild) == (ntohl(flow_match10[i]->match.nw_src) >> ip_src_wild)) || flow_match10[i]->match.nw_src == 0;

		uint8_t ip_dst_wild = ntohl(flow_match10[i]->match.wildcards) >> 14;
		ip_dst_wild &= 63;
		ip_dst_match = (ip_dst_wild >= 32) || (ntohs(fields->eth_prot) == 0x0800 && (ntohl(fields->ip_dst) >> ip_dst_wild) == (ntohl(flow_match10[i]->match.nw_dst) >> ip_dst_wild)) || flow_match10[i]->match.nw_dst == 0;
		ip_prot_match = (ntohl(flow_match10[i]->match.wildcards) & OFPFW_NW_PROTO) || (ntohs(fields->eth_prot) == 0x0800 && fields->ip_prot == flow_match10[i]->match.nw_proto) || flow_match10[i]->match.nw_proto == 0  || ntohs(fields->eth_prot) != 0x0800;
		// If it is TCP or UDP we match on source and destination ports
		if (ntohs(fields->eth_prot) == 0x0800 && (fields->ip_prot == 6 || fields->ip_prot == 17))
		{
			tcp_src_match = (ntohl(flow_match10[i]->match.wildcards) & OFPFW_TP_SRC) || fields->tp_src == flow_match10[i]->match.tp_src || flow_match10[i]->match.tp_src == 0;
			tcp_dst_match = (ntohl(flow_match10[i]->match.wildcards) & OFPFW_TP_DST) || fields->tp_dst == flow_match10[i]->match.tp_dst || flow_match10[i]->match.tp_dst == 0;
		}
		// If it is ICMP the TCP source and destination ports become type and code values
		if (ntohs(fields->eth_prot) == 0x0800 && fields->ip_prot == 1)
		{
			tcp_src_match = (ntohl(flow_match10[i]->match.wildcards) & OFPFW_TP_SRC) || icmp_type == ntohs(flow_match10[i]->match.tp_src) || flow_match10[i]->match.tp_src == 0;
			tcp_dst_match = (ntohl(flow_match10[i]->match.wildcards) & OFPFW_TP_DST) || icmp_code == ntohs(flow_match10[i]->match.tp_dst) || flow_match10[i]->match.tp_dst == 0;
		}
		// If it is ARP then we skip IP and TCP/UDP values
		if (ntohs(fields->eth_prot) == 0x0806)
		{
			ip_src_match = true;
			ip_dst_match = true;
			tcp_src_match = true;
			tcp_dst_match = true;
		}
		if (port_match && eth_src_match && eth_dst_match && eth_prot_match && ip_src_match && ip_dst_match && ip_prot_match && tcp_src_match && tcp_dst_match)
		{
			if (matched_flow > -1)
			{
				if(ntohs(flow_match10[i]->priority) > ntohs(flow_match10[matched_flow]->priority)) matched_flow = i;
			}
			else
			{
				matched_flow = i;
			}
		}
	}

	return matched_flow;
}

/*
*	Populate the packet header fields.
*
*	@param *pBuffer - pointer to the buffer that contains the packet to be macthed.
*	@param *fields - pointer the struct to store the field values.
*
*/
void packet_fields_parser(uint8_t *pBuffer, struct packet_fields *fields) {
	// MPLS EtherTypes
	static const uint8_t mpls1[2] = { 0x88, 0x47 };
	static const uint8_t mpls2[2] = { 0x88, 0x48 };

	fields->isMPLSTag = false;
	uint8_t *eth_type = pBuffer + 12;
	
	// Get MPLS values
	if (memcmp(eth_type, mpls1, 2)==0 || memcmp(eth_type, mpls2, 2)==0)
	{
		uint32_t mpls;
		memcpy(&mpls, eth_type+2, 4);
		fields->mpls_label = ntohl(mpls)>>12;
		fields->mpls_tc = (ntohl(mpls)>>9)&7;
		fields->mpls_bos = (ntohl(mpls)>>8)&1;
		fields->isMPLSTag = true;
		eth_type += 4;
	}
	
	memcpy(&fields->eth_prot, eth_type, 2);
	fields->payload = eth_type + 2; // payload points to ip_hdr, etc.
	
	if(ntohs(fields->eth_prot) == 0x0800){
		struct ip_hdr *iphdr = (struct ip_hdr*)fields->payload;
		uint8_t *ip_payload = fields->payload + IPH_HL(iphdr) * 4;
		fields->ip_src = iphdr->src.addr;
		fields->ip_dst = iphdr->dest.addr;
		fields->ip_prot = IPH_PROTO(iphdr);
		if(IPH_PROTO(iphdr)==IP_PROTO_TCP){
			struct tcp_hdr *tcphdr = (struct tcp_hdr*)ip_payload;
			fields->tp_src = tcphdr->src;
			fields->tp_dst = tcphdr->dest;
		}
		if(IPH_PROTO(iphdr)==IP_PROTO_UDP){
			struct udp_hdr *udphdr = (struct udp_hdr*)ip_payload;
			fields->tp_src = udphdr->src;
			fields->tp_dst = udphdr->dest;
		}
	}
	fields->parsed = true;
}

/*
*	Compares 2 match fields
*	Return 1 if they are a match
*
*	@param *match_a - pointer to the first match field
*	@param *match_b - pointer to the second match field
*
*/
int field_match10(struct ofp_match *match_a, struct ofp_match *match_b)
{
	int match = 0;

	if (match_a->wildcards == 0xff203800) return 1;	//First check if all wildcards are set, if so return a match

	uint8_t ip_src_wild = ntohl(match_a->wildcards) >> 8;
	ip_src_wild &= 63;
	uint8_t ip_dst_wild = ntohl(match_a->wildcards) >> 14;
	ip_dst_wild &= 63;

	// Check all the match fields. There is definitely a more elegant way of doing this and it's on my TODO list!
	match += (((ntohl(match_a->nw_dst) >> ip_dst_wild) == (ntohl(match_b->nw_dst) >> ip_dst_wild)) || ip_dst_wild == 32);
	match += (((ntohl(match_a->nw_src) >> ip_src_wild) == (ntohl(match_b->nw_src) >> ip_src_wild)) || ip_src_wild == 32);
	match += (match_a->in_port == match_b->in_port || (ntohl(match_a->wildcards) & OFPFW_IN_PORT));
	match += (memcmp(match_a->dl_src, match_b->dl_src, 6) == 0 || (ntohl(match_a->wildcards) & OFPFW_DL_SRC));
	match += (memcmp(match_a->dl_dst, match_b->dl_dst, 6) == 0 || (ntohl(match_a->wildcards) & OFPFW_DL_DST));
	match += (match_a->dl_type == match_b->dl_type || (ntohl(match_a->wildcards) & OFPFW_DL_TYPE));
	match += (match_a->nw_proto == match_b->nw_proto || (ntohl(match_a->wildcards) & OFPFW_NW_PROTO));
	match += (match_a->tp_src == match_b->tp_src || (ntohl(match_a->wildcards) & OFPFW_TP_SRC));
	match += (match_a->tp_dst == match_b->tp_dst || (ntohl(match_a->wildcards) & OFPFW_TP_DST));

	if (match == 10 ) return 1; // If all 10 values match or are wild then return 1
	return 0;
}

/*
*	Remove a flow entry from the flow table (OF 1.0)
*
*	@param flow_id - the index number of the flow to remove
*
*/
void remove_flow10(int flow_id)
{
	// Clear flow counters and actions
	memset(&flow_counters[flow_id], 0, sizeof(struct flows_counter));
	membag_free(flow_match10[flow_id]);
	membag_free(flow_actions10[flow_id]);
	// Copy the last flow to here to fill the gap
	flow_match10[flow_id] = flow_match10[iLastFlow-1];
	flow_actions10[flow_id] = flow_actions10[iLastFlow-1];
	// Clear the pointers to the flows that moved
	flow_match10[iLastFlow-1] = NULL;
	flow_actions10[iLastFlow-1] = NULL;
	// Move the counters
	memcpy(&flow_counters[flow_id], &flow_counters[iLastFlow-1], sizeof(struct flows_counter));
	// Clear the counters and action from the last flow that was moved
	memset(&flow_counters[iLastFlow-1], 0, sizeof(struct flows_counter));
	iLastFlow --;
	return;

}

/*
*	Processes flow timeouts
*
*/
void flow_timeouts()
{
	for (int i=0;i<iLastFlow;i++)
	{
		if (flow_counters[i].active == true) // Make sure its an active flow
		{
			if (&flow_match10[i]->idle_timeout != OFP_FLOW_PERMANENT && flow_counters[i].lastmatch > 0 && ((totaltime/2) - flow_counters[i].lastmatch) >= ntohs(&flow_match10[i]->idle_timeout))
			{
				if (ntohs(flow_match10[i]->flags) &  OFPFF10_SEND_FLOW_REM) flowrem_notif10(i,OFPRR10_IDLE_TIMEOUT);
				// Clear flow counters and actions
				remove_flow10(i);
				iLastFlow --;
				return;
			}

			if (&flow_match10[i]->hard_timeout != OFP_FLOW_PERMANENT && flow_counters[i].lastmatch > 0 && ((totaltime/2) - flow_counters[i].duration) >= ntohs(&flow_match10[i]->hard_timeout))
			{
				if (ntohs(&flow_match10[i]->flags) &  OFPFF10_SEND_FLOW_REM) flowrem_notif10(i,OFPRR10_HARD_TIMEOUT);
				// Clear flow counters and actions
				remove_flow10(i);
				iLastFlow --;
				return;
			}
		}
	}
	return;
}

/*
*	Clears the flow table
*
*/
void clear_flows(void)
{
	iLastFlow = 0;
	membag_init();

	/*	Clear OpenFlow 1.0 flow table	*/
	if (OF_Version == 0x01)
	{
		for(int q=0;q<MAX_FLOWS_10;q++)
		{
			memset(&flow_counters[q], 0, sizeof(struct flows_counter));
			if (flow_match10[q] != NULL) flow_match10[q] = NULL;
			if (flow_actions10[q] != NULL) flow_actions10[q] = NULL;
		}
	}
}

/*
*	Builds the body of a flow stats request for OF 1.0
*
*	@param *buffer- pointer to the buffer to store the response
*	@param *first - first flow to include
*	@param *last - last flow to include
*
*/
int flow_stats_msg10(char *buffer, int first, int last)
{
	struct ofp_flow_stats flow_stats;
	struct ofp_action_header *action_hdr1;
	struct ofp_action_header *action_hdr2;
	struct ofp_action_header *action_hdr3;
	struct ofp_action_header *action_hdr4;
	int len = sizeof(struct ofp10_stats_reply);
	int stats_size = 0;
	int actionsize = 0;
	if ((last - first) > 20) last = first + 20;	// Only show first 20 flows to conserve memory

	for(int k=first; k<last;k++)
	{
		action_hdr1 = flow_actions10[k]->action1;
		action_hdr2 = flow_actions10[k]->action2;
		action_hdr3 = flow_actions10[k]->action3;
		action_hdr4 = flow_actions10[k]->action4;
		stats_size = sizeof(flow_stats);
		flow_stats.table_id = 0;
		memcpy(&flow_stats.match, &flow_match10[k]->match, sizeof(struct ofp_match));
		memcpy(&flow_stats.cookie, &flow_match10[k]->cookie, sizeof(uint64_t));
		memcpy(&flow_stats.priority, flow_match10[k]->priority, sizeof(uint16_t));
		memcpy(&flow_stats.idle_timeout, flow_match10[k]->idle_timeout, sizeof(uint16_t));
		memcpy(&flow_stats.hard_timeout, flow_match10[k]->hard_timeout, sizeof(uint16_t));
		flow_stats.duration_sec = HTONL((totaltime/2) - flow_counters[k].duration);
		flow_stats.duration_nsec = 0;
		flow_stats.packet_count = htonll(flow_counters[k].hitCount);
		flow_stats.byte_count = htonll(flow_counters[k].bytes);
		actionsize = ntohs(action_hdr1->len) + ntohs(action_hdr2->len) + ntohs(action_hdr3->len) + ntohs(action_hdr4->len);
		flow_stats.length = htons(stats_size + actionsize);

		memcpy(buffer + len, &flow_stats, stats_size);
		len += stats_size;

		if(ntohs(action_hdr1->len) > 0)
		{
			memcpy(buffer + len, flow_actions10[k]->action1, ntohs(action_hdr1->len));
			stats_size += ntohs(action_hdr1->len);
			len += ntohs(action_hdr1->len);
		}

		if(ntohs(action_hdr2->len) > 0)
		{
			memcpy(buffer + len, flow_actions10[k]->action2, ntohs(action_hdr2->len));
			stats_size += ntohs(action_hdr2->len);
			len += ntohs(action_hdr2->len);
		}

		if(ntohs(action_hdr3->len) > 0)
		{
			memcpy(buffer + len, flow_actions10[k]->action3, ntohs(action_hdr3->len));
			stats_size += ntohs(action_hdr3->len);
			len += ntohs(action_hdr3->len);
		}

		if(ntohs(action_hdr4->len) > 0)
		{
			memcpy(buffer + len, flow_actions10[k]->action4, ntohs(action_hdr4->len));
			stats_size += ntohs(action_hdr4->len);
			len += ntohs(action_hdr4->len);
		}
	}
	return len;
}