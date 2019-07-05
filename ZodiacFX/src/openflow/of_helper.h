/**
 * @file
 * of_helper.h
 *
 * This file contains the function declarations and structures for the OpenFlow helper functions
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


#ifndef OF_HELPER_H_
#define OF_HELPER_H_

#include "openflow.h"

struct packet_fields
{
	bool parsed;
	bool isMPLSTag;
	uint8_t *payload;
	uint16_t eth_prot;
	uint8_t ip_prot;
	uint32_t ip_src;
	uint32_t ip_dst;
	uint32_t mpls_label;
	uint8_t mpls_tc;
	uint8_t mpls_bos;
	uint8_t mpls_ttl;
	// transport layer
	uint16_t tp_src;
	uint16_t tp_dst;
};

void packet_fields_parser(uint8_t *pBuffer, struct packet_fields *fields);
int flowmatch10(uint8_t *pBuffer, int port, struct packet_fields *fields);
int field_match10(struct ofp_match *match_a, struct ofp_match *match_b);
void nnOF_timer(void);
void flow_timeouts(void);
void clear_flows(void);
int flow_stats_msg10(char *buffer, int first, int last);
void set_ip_checksum(uint8_t *p_uc_data, int packet_size, int iphdr_offset);
void remove_flow10(int flow_id);

#endif /* OF_HELPER_H_ */
