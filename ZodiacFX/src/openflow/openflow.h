/**
 * @file
 * openflow.h
 *
 * This file contains the function declarations and structures for the OpenFlow functions
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

#ifndef OPENFLOW_H_
#define OPENFLOW_H_

#include "openflow_spec/openflow_spec10.h"
#include "of_helper.h"
#include "config_zodiac.h"
#include <lwip/err.h>

struct flow_tbl_actions
{
	uint8_t action1[16];
	uint8_t action2[16];
	uint8_t action3[16];
	uint8_t action4[16];
};

struct policing_sample
{
	uint32_t	packet_time;	// sys_get_ms() when sampled
	uint16_t	byte_count;		// Number of bytes during this sample
	uint16_t	packet_count;	// Number of packets during this sample
};

struct action_bucket {
	int active;
	uint64_t packet_count;
	uint64_t byte_count;
	uint8_t data[64];
};

void task_openflow(void);
void nnOF_tablelookup(uint8_t *p_uc_data, uint32_t *ul_size, int port);
void nnOF10_tablelookup(uint8_t *p_uc_data, uint32_t *ul_size, int port);
void of10_message(struct ofp_header *ofph, int size, int len);
void barrier10_reply(uint32_t xid);
void sendtcp(const void *buffer, uint16_t len, uint8_t push);
void flowrem_notif10(int flowid, uint8_t reason);
void port_status_message10(uint8_t port);

#define HTONS(x) ((((x) & 0xff) << 8) | (((x) & 0xff00) >> 8))
#define NTOHS(x) HTONS(x)
#define HTONL(x) ((((x) & 0xff) << 24) | \
(((x) & 0xff00) << 8) | \
(((x) & 0xff0000UL) >> 8) | \
(((x) & 0xff000000UL) >> 24))
#define NTOHL(x) HTONL(x)

#define SUCCESS		0
#define FAILURE		1

#endif /* OPENFLOW_H_ */
