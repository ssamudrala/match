/*******************************************************************************
  Library of routines to pack/unpack match action table Netlink messages

  Author: John Fastabend <john.r.fastabend@intel.com>
  Copyright (c) <2015>, Intel Corporation

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
      this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright
      notice, this list of conditions and the following disclaimer in the
      documentation and/or other materials provided with the distribution.
    * Neither the name of Intel Corporation nor the names of its contributors
      may be used to endorse or promote products derived from this software
      without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE
  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
  OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
  OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*******************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <stdbool.h>
#include <stdarg.h>
#include <inttypes.h>

#include <getopt.h>

#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/socket.h>
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/ctrl.h>
#include <libnl3/netlink/attr.h>

#include <linux/if_ether.h>

#include <gvc.h>

#include "if_match.h"
#include "matchlib.h"
#include "matlog.h"
#include "matstream.h"

#include <arpa/inet.h>

#define MAX_TABLES 200
#define MAX_HDRS 200
#define MAX_FIELDS 200
#define MAX_ACTIONS 200
#define MAX_NODES 200

#ifdef PRIx64
#undef PRIx64
#define PRIx64 "llx"
#endif

static char none[] = "<none>";
static char label[] = "label";
static char any[] = "<any>";
static char empty[] = "";
static char agopen_g[] = "g";
static char rankdir[] = "rankdir";
static char LR[] = "LR";
static char shape[] = "shape";
static char record[] = "record";

Agnode_t *graphviz_table_nodes[MAX_NODES];
Agnode_t *graphviz_header_nodes[MAX_NODES];

struct net_mat_tbl *tables[MAX_TABLES];
struct net_mat_hdr *headers[MAX_HDRS];
struct net_mat_field *header_fields[MAX_HDRS][MAX_FIELDS];
struct net_mat_action *actions[MAX_ACTIONS];
struct net_mat_hdr_node *graph_nodes[MAX_NODES];

char *graph_names(unsigned int uid);
char *table_names(unsigned int uid);
static void ppg_table_graph(struct mat_stream *matsp, struct net_mat_tbl_node *nodes);
static void ppg_header_graph(struct mat_stream *matsp, struct net_mat_hdr_node *nodes);

char *graph_names(unsigned int uid)
{
	if (uid < MAX_NODES)
		return graph_nodes[uid] ? graph_nodes[uid]->name : none;
	else
		return NULL;
}

struct net_mat_hdr_node *get_graph_node(unsigned int uid)
{
	if (uid < MAX_NODES)
		return graph_nodes[uid];
	else
		return NULL;
}

char *headers_names(unsigned int uid)
{
	if (uid < MAX_HDRS)
		return headers[uid] ? headers[uid]->name : none;
	else
		return NULL;
}

struct net_mat_hdr *get_headers(unsigned int uid)
{
	if (uid < MAX_HDRS)
		return headers[uid];
	else
		return NULL;
}

char *fields_names(unsigned int hid, unsigned int fid)
{
	if (hid < MAX_HDRS && fid < MAX_FIELDS)
		if (header_fields[hid][fid])
			return header_fields[hid][fid]->name;
		else
			return none;
	else
		return none;
}

struct net_mat_field *get_fields(unsigned int huid, unsigned int uid)
{
	if (huid < MAX_HDRS && uid < MAX_FIELDS)
		return header_fields[huid][uid];
	else
		return NULL;
}

char *table_names(unsigned int uid)
{
	if (uid < MAX_TABLES)
		return tables[uid] ? tables[uid]->name : none;
	else
		return NULL;
}

struct net_mat_tbl *get_tables(unsigned int uid)
{
	if (uid < MAX_TABLES)
		return tables[uid];
	else
		return NULL;
}

unsigned int get_table_id(char *name)
{
	int i;

	for (i = 0; i < MAX_TABLES; i++) {
		if (tables[i] && (strcmp(tables[i]->name, name) == 0))
			return tables[i]->uid;
	}

	return 0;
}

unsigned int gen_table_id(void)
{
	unsigned int i;

	for (i = 1; i < MAX_TABLES; i++) {
		if (!tables[i])
			return i;
	}
	return 0;
}

char *action_names(unsigned int uid)
{
	if (uid < MAX_ACTIONS)
		return actions[uid] ? actions[uid]->name : none;
	else
		return NULL;
}

struct net_mat_action *get_actions(unsigned int uid)
{
	if (uid < MAX_ACTIONS)
		return actions[uid];
	else
		return NULL;
}

unsigned find_table(const char *name)
{
	unsigned int i;

	for (i = 0; i < MAX_TABLES; i++) {
		if (tables[i] && strcmp(table_names(i), name) == 0)
			return tables[i]->uid;
	}

	return 0;
}

unsigned int find_action(const char *name)
{
	unsigned int i;

	for (i = 0; i < MAX_ACTIONS; i++) {
		if (actions[i] && strcmp(action_names(i), name) == 0)
			return actions[i]->uid;
	}
	return 0;
}

unsigned int find_header_node(const char *name)
{
	unsigned int i;

	for (i = 0; i < MAX_NODES; i++) {
		if (graph_nodes[i] && strcmp(graph_names(i), name) == 0)
			return graph_nodes[i]->uid;
	}
	return 0;
}

unsigned int find_field(const char *field, unsigned int hdr)
{
	struct net_mat_hdr *header;
	unsigned int i;

	header = get_headers(hdr);

	if (!header) {
		MAT_LOG(ERR, "invalid header\n");
		return 0;
	}
	for (i = 0; i < header->field_sz; i++) {
		if (header->fields[i].uid &&
		    strcmp(header->fields[i].name, field) == 0)
			return header->fields[i].uid;
	}
	return 0;
}

int find_match(const char *header, const char *field, unsigned int *hi, unsigned int *li)
{
	unsigned int i;

	*hi = *li = 0;

	for (i = 0; i < MAX_HDRS; i++) {
		if (headers[i] && strcmp(headers_names(i), header) == 0) {
			*hi = headers[i]->uid;
			break;
		}
	}

	for (i = 0; *hi > 0 && i < MAX_FIELDS; i++) {
		if (header_fields[*hi][i] &&
		    strcmp(fields_names(*hi, i), field) == 0) {
			*li = header_fields[*hi][i]->uid;
			break;
		}
	}

	if (*hi == 0 || *li == 0)
		return -EINVAL;

	return 0;
}

void match_push_headers(struct net_mat_hdr **h)
{
	unsigned int i;

	for (i = 0; h[i] && h[i]->uid; i++)
		headers[h[i]->uid] = h[i];
}

void match_push_actions(struct net_mat_action **a)
{
	unsigned int i;

	for (i = 0; a[i]; i++)
		actions[a[i]->uid] = a[i];
}

void match_push_actions_ary(struct net_mat_action *a)
{
	unsigned int i;

	for (i = 0; a[i].uid; i++)
		actions[a[i].uid] = &a[i];
}

void match_push_tables(struct net_mat_tbl **t)
{
	unsigned int i;

	for (i = 0; t[i] && t[i]->uid; i++)
		tables[t[i]->uid] = t[i];
}

void match_push_tables_a(struct net_mat_tbl *t)
{
	unsigned int i;

	for (i = 0; t[i].uid; i++)
		tables[t[i].uid] = &t[i];
}

void match_pop_tables(struct net_mat_tbl **t)
{
	unsigned int i;

	for (i = 0; t[i] && t[i]->uid; i++)
		free(tables[t[i]->uid]);
}
void match_push_header_fields(struct net_mat_hdr **h)
{
	unsigned int j;
	int i;

	for (i = 0; h[i] && h[i]->uid; i++) {
		struct net_mat_field *f = h[i]->fields;
		__u32 uid = h[i]->uid;

		for (j = 0; j < h[i]->field_sz; j++)
			header_fields[uid][f[j].uid] = &f[j];
	}
}

void match_push_graph_nodes(struct net_mat_hdr_node **n)
{
	unsigned int i;

	for (i = 0; n[i]; i++)
		graph_nodes[n[i]->uid] = n[i];
}

static void pfprintf(struct mat_stream *matsp, const char *format, ...)
{
	va_list args;

	va_start(args, format);

	if (matsp)
		mat_stream_vprintf(matsp, format, args);

	va_end(args);
}


struct nla_policy net_mat_table_policy[NET_MAT_TABLE_ATTR_MAX + 1] = {
	[NET_MAT_TABLE_ATTR_NAME]	= { .type = NLA_STRING },
	[NET_MAT_TABLE_ATTR_UID]	= { .type = NLA_U32 },
	[NET_MAT_TABLE_ATTR_SOURCE]	= { .type = NLA_U32 },
	[NET_MAT_TABLE_ATTR_APPLY]	= { .type = NLA_U32 },
	[NET_MAT_TABLE_ATTR_SIZE]	= { .type = NLA_U32 },
	[NET_MAT_TABLE_ATTR_MATCHES]	= { .type = NLA_NESTED },
	[NET_MAT_TABLE_ATTR_ACTIONS]	= { .type = NLA_NESTED },
	[NET_MAT_TABLE_ATTR_NAMED_VALUES] = { .type = NLA_NESTED },
};

struct nla_policy net_mat_action_policy[NET_MAT_ACTION_ATTR_MAX + 1] = {
	[NET_MAT_ACTION_ATTR_NAME]	= {.type = NLA_STRING, },
	[NET_MAT_ACTION_ATTR_UID]	= {.type = NLA_U32 },
	[NET_MAT_ACTION_ATTR_SIGNATURE] = {.type = NLA_NESTED },
};

struct nla_policy net_mat_action_arg_policy[NET_MAT_ACTION_ARG_MAX + 1] = {
	[NET_MAT_ACTION_ARG_NAME]	= {.type = NLA_STRING, },
	[NET_MAT_ACTION_ARG_TYPE]	= {.type = NLA_U32 },
	[NET_MAT_ACTION_ARG_VALUE]	= {.type = NLA_UNSPEC, },
};

static struct nla_policy match_get_field_policy[NET_MAT_FIELD_ATTR_MAX+1] = {
	[NET_MAT_FIELD_ATTR_NAME]	= { .type = NLA_STRING },
	[NET_MAT_FIELD_ATTR_UID]	= { .type = NLA_U32 },
	[NET_MAT_FIELD_ATTR_BITWIDTH]	= { .type = NLA_U32 },
};

static struct nla_policy net_mat_field_policy[NET_MAT_FIELD_REF_MAX + 1] = {
	[NET_MAT_FIELD_REF_NEXT_NODE]  = { .type = NLA_U32,},
	[NET_MAT_FIELD_REF_INSTANCE]   = { .type = NLA_U32,},
	[NET_MAT_FIELD_REF_HEADER]	= { .type = NLA_U32,},
	[NET_MAT_FIELD_REF_FIELD]	= { .type = NLA_U32,},
	[NET_MAT_FIELD_REF_MASK_TYPE]	= { .type = NLA_U32,},
	[NET_MAT_FIELD_REF_TYPE]	= { .type = NLA_U32,},
	[NET_MAT_FIELD_REF_VALUE]	= { .type = NLA_UNSPEC,},
	[NET_MAT_FIELD_REF_MASK]	= { .type = NLA_UNSPEC,},
};

static struct nla_policy match_table_rule_policy[NET_MAT_ATTR_MAX+1] = {
	[NET_MAT_ATTR_ERROR]		= { .type = NLA_U32,},
	[NET_MAT_ATTR_TABLE]		= { .type = NLA_U32,},
	[NET_MAT_ATTR_UID]		= { .type = NLA_U32,},
	[NET_MAT_ATTR_PRIORITY]		= { .type = NLA_U32,},
	[NET_MAT_ATTR_BYTES]		= { .type = NLA_U64,},
	[NET_MAT_ATTR_PACKETS]		= { .type = NLA_U64,},
	[NET_MAT_ATTR_MATCHES]		= { .type = NLA_NESTED,},
	[NET_MAT_ATTR_ACTIONS]		= { .type = NLA_NESTED,},
};

static struct nla_policy match_get_header_policy[NET_MAT_HEADER_ATTR_MAX+1] = {
	[NET_MAT_HEADER_ATTR_NAME]	= { .type = NLA_STRING },
	[NET_MAT_HEADER_ATTR_UID]	= { .type = NLA_U32 },
	[NET_MAT_HEADER_ATTR_FIELDS]	= { .type = NLA_NESTED },
};

static struct nla_policy match_get_node_policy[NET_MAT_TABLE_GRAPH_NODE_MAX+1] = {
	[NET_MAT_TABLE_GRAPH_NODE_UID]    = { .type = NLA_U32,},
	[NET_MAT_TABLE_GRAPH_NODE_FLAGS]    = { .type = NLA_U32,},
	[NET_MAT_TABLE_GRAPH_NODE_JUMP]   = { .type = NLA_NESTED,},
};

static struct nla_policy match_get_hdr_node_policy[NET_MAT_HEADER_NODE_MAX+1] = {
	[NET_MAT_HEADER_NODE_NAME] = { .type = NLA_STRING,},
	[NET_MAT_HEADER_NODE_UID]  = { .type = NLA_U32,},
	[NET_MAT_HEADER_NODE_HDRS] = { .type = NLA_NESTED,},
	[NET_MAT_HEADER_NODE_JUMP] = { .type = NLA_NESTED,},
};

static struct nla_policy net_mat_named_value_policy[NET_MAT_TABLE_ATTR_VALUE_T_MAX+1] = {
	[NET_MAT_TABLE_ATTR_VALUE_T_NAME]  = { .type = NLA_STRING,},
	[NET_MAT_TABLE_ATTR_VALUE_T_UID]   = { .type = NLA_U32,},
	[NET_MAT_TABLE_ATTR_VALUE_T_TYPE]  = { .type = NLA_U32,},
	[NET_MAT_TABLE_ATTR_VALUE_T_VALUE] = { .type = NLA_UNSPEC,},
	[NET_MAT_TABLE_ATTR_VALUE_T_WRITE] = { .type = NLA_U8,},
};

static struct nla_policy net_mat_port_policy[NET_MAT_PORT_T_MAX+1] = {
	[NET_MAT_PORT_T_ID]	= { .type = NLA_U32, },
	[NET_MAT_PORT_T_PHYS_ID]= { .type = NLA_U32, },
	[NET_MAT_PORT_T_TYPE]	= { .type = NLA_U32, },
	[NET_MAT_PORT_T_STATE]	= { .type = NLA_U32, },
	[NET_MAT_PORT_T_SPEED]	= { .type = NLA_U32, },
	[NET_MAT_PORT_T_MAX_FRAME_SIZE]	= { .type = NLA_U32, },
	[NET_MAT_PORT_T_VLAN]	= { .type = NLA_NESTED, },
	[NET_MAT_PORT_T_STATS]  = { .type = NLA_NESTED, },
	[NET_MAT_PORT_T_MAC_ADDR]	= { .type = NLA_U64, },
	[NET_MAT_PORT_T_GLORT]	= { .type = NLA_U32, },
	[NET_MAT_PORT_T_PCI]   = { .type = NLA_UNSPEC, .minlen = sizeof(struct net_mat_port_pci)},
	[NET_MAT_PORT_T_LOOPBACK] = { .type = NLA_U32, },
	[NET_MAT_PORT_T_LEARNING] = { .type = NLA_U32, },
	[NET_MAT_PORT_T_UPDATE_DSCP] = { .type = NLA_U32, },
	[NET_MAT_PORT_T_UPDATE_TTL] = { .type = NLA_U32, },
	[NET_MAT_PORT_T_MCAST_FLOODING] = { .type = NLA_U32, },
	[NET_MAT_PORT_T_UPDATE_DMAC] = { .type = NLA_U32, },
	[NET_MAT_PORT_T_UPDATE_SMAC] = { .type = NLA_U32, },
	[NET_MAT_PORT_T_UPDATE_VLAN] = { .type = NLA_U32, },

};

static struct nla_policy net_mat_port_stats_policy[NET_MAT_PORT_T_STATS_MAX+1] = {
       [NET_MAT_PORT_T_STATS_RX] = { .type = NLA_NESTED, },
       [NET_MAT_PORT_T_STATS_TX] = { .type = NLA_NESTED, },
};

static struct nla_policy net_mat_port_stats_rxtx_policy[NET_MAT_PORT_T_STATS_RXTX_MAX+1] = {
       [NET_MAT_PORT_T_STATS_BYTES]		= { .type = NLA_U64, },
       [NET_MAT_PORT_T_STATS_UNICAST_BYTES]	= { .type = NLA_U64, },
       [NET_MAT_PORT_T_STATS_MULTICAST_BYTES]	= { .type = NLA_U64, },
       [NET_MAT_PORT_T_STATS_BROADCAST_BYTES]	= { .type = NLA_U64, },
       [NET_MAT_PORT_T_STATS_PACKETS]		= { .type = NLA_U64, },
       [NET_MAT_PORT_T_STATS_UNICAST_PACKETS]	= { .type = NLA_U64, },
       [NET_MAT_PORT_T_STATS_MULTICAST_PACKETS] = { .type = NLA_U64, },
       [NET_MAT_PORT_T_STATS_BROADCAST_PACKETS] = { .type = NLA_U64, },
};

static struct nla_policy net_mat_port_vlan_policy[NET_MAT_PORT_T_VLAN_MAX+1] = {
	[NET_MAT_PORT_T_VLAN_DEF_VLAN]		= { .type = NLA_U32, },
	[NET_MAT_PORT_T_VLAN_DROP_TAGGED]	= { .type = NLA_U32, },
	[NET_MAT_PORT_T_VLAN_DROP_UNTAGGED]	= { .type = NLA_U32, },
	[NET_MAT_PORT_T_VLAN_DEF_PRIORITY]	= { .type = NLA_U32, },
	[NET_MAT_PORT_T_VLAN_MEMBERSHIP]	= { .type = NLA_UNSPEC, .minlen =(MAX_VLAN / 8), },
};

static char *
match_pp_mac_addr(__u64 *addr, char *buf, size_t len)
{
	__u8 *tmp = (__u8 *)addr;
	int err;

	err = snprintf(buf, len, "%02x:%02x:%02x:%02x:%02x:%02x",
		       tmp[5], tmp[4], tmp[3], tmp[2], tmp[1], tmp[0]);
	if (err < 0 || err >= (int)len)
		return NULL;

	return buf;
}

static void pp_field_ref(struct mat_stream *matsp, struct net_mat_field_ref *ref,
		bool first, bool nl, Agedge_t *e)
{
	char fieldstr[1024];
	size_t fieldlen = sizeof(fieldstr);
	char valbuf[32], maskbuf[32];
	unsigned int inst = ref->instance;
	unsigned int hi = ref->header;
	unsigned int fi = ref->field;

	if (!hi) {
		pfprintf(matsp, "\t *");
		return;
	}

	if (!ref->type) {
		if (!ref->header && !ref->field) {
			pfprintf(matsp, "\t <any>");
			if (e)
				agsafeset(e, label, any, empty);
		} else if (!first) {
			pfprintf(matsp, " %s", fi ? fields_names(hi, fi) : empty);
			if (e)
				agsafeset(e, label, fi ? fields_names(hi, fi) : empty, empty);
		} else {
			pfprintf(matsp, "\n\t field: %s [%s",
				 graph_names(inst), fi ? fields_names(hi, fi) : empty);
			if (e)
				agsafeset(e, label, fi ? fields_names(hi, fi) : empty, empty);
		}

		switch (ref->mask_type) {
		case NET_MAT_MASK_TYPE_EXACT:
			pfprintf(matsp, " (exact)");
			break;
		case NET_MAT_MASK_TYPE_LPM:
			pfprintf(matsp, " (lpm)");
			break;
		default:
			break;
		}
	}

	if(!headers_names(hi) || !fields_names(hi, fi)) {
		MAT_LOG(ERR,"Invalid header or field\n");
		return;
	}
	switch (ref->type) {
	case NET_MAT_FIELD_REF_ATTR_TYPE_U8:
		snprintf(fieldstr, fieldlen, "\t %s.%s = %02x (%02x)",
			headers_names(hi), fi ? fields_names(hi, fi) : empty,
			ref->v.u8.value_u8, ref->v.u8.mask_u8);

		if (e)
			agsafeset(e, label, fieldstr, empty);
		break;
	case NET_MAT_FIELD_REF_ATTR_TYPE_U16:
		snprintf(fieldstr, fieldlen, "\t %s.%s = %04x (%04x)",
			headers_names(hi), fi ? fields_names(hi, fi) : empty,
			ref->v.u16.value_u16, ref->v.u16.mask_u16);
		if (e)
			agsafeset(e, label, fieldstr, empty);
		break;
	case NET_MAT_FIELD_REF_ATTR_TYPE_U32:
		snprintf(fieldstr, fieldlen, "\t %s.%s = %08x (%08x)",
			headers_names(hi), fi ? fields_names(hi, fi) : empty,
			ref->v.u32.value_u32, ref->v.u32.mask_u32);
		if (e)
			agsafeset(e, label, fieldstr, empty);
		break;
	case NET_MAT_FIELD_REF_ATTR_TYPE_U64:
		if (!match_pp_mac_addr(&ref->v.u64.value_u64, valbuf, sizeof(valbuf)))
			snprintf(valbuf, sizeof(valbuf), "0x%" PRIx64, ref->v.u64.value_u64);
		if (!match_pp_mac_addr(&ref->v.u64.mask_u64, maskbuf, sizeof(maskbuf)))
			snprintf(valbuf, sizeof(valbuf), "0x%" PRIx64, ref->v.u64.mask_u64);
		snprintf(fieldstr, fieldlen, "\t %s.%s = %s (%s)",
			 headers_names(hi), fi ? fields_names(hi, fi) : empty,
			 valbuf, maskbuf);
		if (e)
			agsafeset(e, label, fieldstr, empty);
		break;
	case NET_MAT_FIELD_REF_ATTR_TYPE_IN6:
		inet_ntop(AF_INET6, ref->v.in6.value_in6.s6_addr32, valbuf, sizeof(valbuf));
		inet_ntop(AF_INET6, ref->v.in6.mask_in6.s6_addr32, maskbuf, sizeof(maskbuf));
		snprintf(fieldstr, fieldlen, "\t %s.%s = %s (%s)",
			 headers_names(hi), fi ? fields_names(hi, fi) : empty,
			 valbuf, maskbuf);
		if (e)
			agsafeset(e, label, fieldstr, empty);
		break;
	default:
		break;
	}

	if (ref->type)
		pfprintf(matsp, "%s", fieldstr);

	if (ref->type && nl)
		pfprintf(matsp, "\n");
}

static void pp_fields(struct mat_stream *matsp, struct net_mat_field_ref *ref)
{
	int i;
	bool first = true;

	for (i = 0; ref[i].header; i++) {
		if (i > 0  && (ref[i-1].header != ref[i].header)) {
			pfprintf(matsp, "]");
			first = true;
		}

		pp_field_ref(matsp, &ref[i], first, true, NULL);
		first = false;
	}
	if (i > 0 && !ref[i-1].type)
		pfprintf(matsp, "]\n");
}

const char *match_table_arg_type_str[__NET_MAT_ACTION_ARG_TYPE_VAL_MAX] = {
	[NET_MAT_ACTION_ARG_TYPE_NULL] = "null",
	[NET_MAT_ACTION_ARG_TYPE_U8]	= "u8",
	[NET_MAT_ACTION_ARG_TYPE_U16]	= "u16",
	[NET_MAT_ACTION_ARG_TYPE_U32]	= "u32",
	[NET_MAT_ACTION_ARG_TYPE_U64]	= "u64",
	[NET_MAT_ACTION_ARG_TYPE_VARIADIC] = "...,",
	[NET_MAT_ACTION_ARG_TYPE_IN6]	= "in6",
};

void
pp_action(struct mat_stream *matsp, struct net_mat_action *act, bool print_values)
{
	struct net_mat_action_arg *arg;
	int i;
	char addr[INET6_ADDRSTRLEN];
	struct net_mat_action *act_name;
	struct net_mat_action_arg *arg_name;

	if ((act->uid < MAX_ACTIONS) && actions[act->uid])
		act_name = actions[act->uid];
	else
		act_name = act;

	pfprintf(matsp, "\t   %i: %s ( ", act->uid,
		act_name->name ? act_name->name : empty);

	if (!act->args)
		goto out;

	for (i = 0; act->args[i].type; i++) {
		arg = &act->args[i];
		arg_name = &act_name->args[i];

		if (i > 0)
			pfprintf(matsp, ", ");

		pfprintf(matsp, "%s %s",
			 match_table_arg_type_str[arg->type],
			 arg_name->name ? arg_name->name : empty);

		if (!print_values)
			continue;

		switch (arg->type) {
		case NET_MAT_ACTION_ARG_TYPE_U8:
			pfprintf(matsp, " %02x ", arg->v.value_u8);
			break;
		case NET_MAT_ACTION_ARG_TYPE_U16:
			pfprintf(matsp, " %" PRIu16 "", arg->v.value_u16);
			break;
		case NET_MAT_ACTION_ARG_TYPE_U32:
			pfprintf(matsp, " 0x%x", arg->v.value_u32);
			break;
		case NET_MAT_ACTION_ARG_TYPE_U64:
			pfprintf(matsp, " %" PRIu64 "", arg->v.value_u64);
			break;
		case NET_MAT_ACTION_ARG_TYPE_IN6:
			pfprintf(matsp, " %s ",
				inet_ntop(AF_INET6, &arg->v.value_in6, addr, sizeof(addr)));
			break;
		case NET_MAT_ACTION_ARG_TYPE_NULL:
		case NET_MAT_ACTION_ARG_TYPE_VARIADIC:
		default:
			break;
		}
	}
out:
	pfprintf(matsp, " )\n");
}

void pp_actions(struct mat_stream *matsp, struct net_mat_action *actions)
{
	int i;

	for (i = 0; actions[i].uid; i++)
		pp_action(matsp, &actions[i], true);
}

static void pp_named_value(struct mat_stream *matsp, struct net_mat_named_value *v)
{
	char valbuf[32] = "";

	if (v->name)
		pfprintf(matsp, "\t%s %s = ", v->name,
			 v->write == NET_MAT_NAMED_VALUE_IS_WRITABLE ?
			 "(w)": "");
	else
		pfprintf(matsp, "\t%i %s = ", v->uid,
			 v->write == NET_MAT_NAMED_VALUE_IS_WRITABLE ?
			 "(w)": "");


	switch (v->type) {
	case NET_MAT_NAMED_VALUE_TYPE_U8:
		pfprintf(matsp, "%02x\n", v->value.u8);
		break;
	case NET_MAT_NAMED_VALUE_TYPE_U16:
		pfprintf(matsp, "%" PRIu16 "\n", v->value.u16);
		break;
	case NET_MAT_NAMED_VALUE_TYPE_U32:
		pfprintf(matsp, "%" PRIu32 "\n", v->value.u32);
		break;
	case NET_MAT_NAMED_VALUE_TYPE_U64:
		if (!match_pp_mac_addr(&v->value.u64, valbuf, sizeof(valbuf)))
			snprintf(valbuf, sizeof(valbuf), "0x%" PRIx64, v->value.u64);
		pfprintf(matsp, "%s\n", valbuf);
		break;
	case NET_MAT_NAMED_VALUE_TYPE_NULL:
	default:
		pfprintf(matsp, "null\n");
		break;
	}
}

void pp_table(struct mat_stream *matsp, struct net_mat_tbl *table)
{
	int i;

	pfprintf(matsp, "\n%s:%u src %u apply %u size %u\n",
		 table->name, table->uid, table->source, table->apply_action,
		 table->size);

	pfprintf(matsp, "  matches:");
	if (table->matches)
		pp_fields(matsp, table->matches);

	pfprintf(matsp, "  actions:\n");
	if (table->actions) {
		for (i = 0; table->actions[i]; i++) {
			struct net_mat_action *act = actions[table->actions[i]];

			if (!act) {
				MAT_LOG(ERR, "unknown action uid %i\n",
					table->actions[i]);
				continue;
			}

			if (act->uid)
				pp_action(matsp, act, false);
		}
	}

	pfprintf(matsp, "  attributes:\n");
	if (table->attribs) {
		for (i = 0; table->attribs[i].uid; i++)
			pp_named_value(matsp, &table->attribs[i]);
	}

	mat_stream_flush(matsp);
}

void pp_header(struct mat_stream *matsp, struct net_mat_hdr *header)
{
	struct net_mat_field *f;
	int i = 0;

	pfprintf(matsp, "  %s {\n\t", header->name);

	for (f = &header->fields[i];
	     f->uid;
	     f = &header->fields[++i]) {
		if (f->bitwidth)
			pfprintf(matsp, " %s:%i ", f->name, f->bitwidth);
		else
			pfprintf(matsp, " %s:* ", f->name);

		if (i && !(i % 5))
			pfprintf(matsp, " \n\t");
	}

	if (i % 5)
		pfprintf(matsp, "\n\t");
	pfprintf(matsp, " }\n");

	mat_stream_flush(matsp);
}

void pp_rule(struct mat_stream *matsp, struct net_mat_rule *rule)
{
	pfprintf(matsp, "table : %u  ", rule->table_id);
	pfprintf(matsp, "uid : %u  ", rule->uid);
	pfprintf(matsp, "prio : %u  ", rule->priority);
	pfprintf(matsp, "bytes : %lu  ", rule->bytes);
	pfprintf(matsp, "packets : %lu\n", rule->packets);

	if (rule->matches)
		pp_fields(matsp, rule->matches);
	if (rule->actions)
		pp_actions(matsp, rule->actions);

	mat_stream_flush(matsp);
}


void pp_rules(struct mat_stream *matsp, struct net_mat_rule *rules)
{
	int i;

	if (!matsp)
		return;

	for (i = 0; rules[i].uid; i++)
		pp_rule(matsp, &rules[i]);
}

static void pp_jump_table(struct mat_stream *matsp,
			  struct net_mat_jump_table *jump)
{
	if (!matsp)
		return;
	pp_field_ref(matsp, &jump->field, 0, false, NULL);
	if (!jump->node)
		pfprintf(matsp, " -> terminal\n");
	else
		pfprintf(matsp, " -> %s\n", table_names(jump->node));

}

static void pp_port_stats(struct mat_stream *matsp, struct net_mat_port_stats *s)
{
	pfprintf(matsp, "    stats:\n");
	pfprintf(matsp, "        rx_packets           %" PRIu64 "\n", s->rx_packets);
	pfprintf(matsp, "        rx_bytes             %" PRIu64 "\n", s->rx_bytes);
	pfprintf(matsp, "        rx_unicast_packets   %" PRIu64 "\n", s->rx_unicast_packets);
	pfprintf(matsp, "        rx_multicast_packets %" PRIu64 "\n", s->rx_multicast_packets);
	pfprintf(matsp, "        rx_broadcast_packets %" PRIu64 "\n", s->rx_broadcast_packets);
	pfprintf(matsp, "        rx_unicast_bytes     %" PRIu64 "\n", s->rx_unicast_bytes);
	pfprintf(matsp, "        rx_multicast_bytes   %" PRIu64 "\n", s->rx_multicast_bytes);
	pfprintf(matsp, "        rx_broadcast_bytes   %" PRIu64 "\n", s->rx_broadcast_bytes);
	pfprintf(matsp, "        tx_packets           %" PRIu64 "\n", s->tx_packets);
	pfprintf(matsp, "        tx_bytes             %" PRIu64 "\n", s->tx_bytes);
	pfprintf(matsp, "        tx_unicast_packets   %" PRIu64 "\n", s->tx_unicast_packets);
	pfprintf(matsp, "        tx_multicast_packets %" PRIu64 "\n", s->tx_multicast_packets);
	pfprintf(matsp, "        tx_broadcast_packets %" PRIu64 "\n", s->tx_broadcast_packets);
	pfprintf(matsp, "        tx_unicast_bytes     %" PRIu64 "\n", s->tx_unicast_bytes);
	pfprintf(matsp, "        tx_multicast_bytes   %" PRIu64 "\n", s->tx_multicast_bytes);
	pfprintf(matsp, "        tx_broadcast_bytes   %" PRIu64 "\n", s->tx_broadcast_bytes);
}

static void pp_port_vlan(struct mat_stream *matsp, struct net_mat_port_vlan *v)
{
	pfprintf(matsp, "    vlan:\n");
	pfprintf(matsp, "        default vlan: %u\n", v->def_vlan);
	if (v->def_priority != NET_MAT_PORT_T_DEF_PRI_UNSPEC)
		pfprintf(matsp, "        default priority: %u\n", v->def_priority);
	if (v->drop_tagged)
		pfprintf(matsp, "        drop tagged: %s\n", flag_state_str(v->drop_tagged));
	if (v->drop_untagged)
		pfprintf(matsp, "        drop untagged: %s\n", flag_state_str(v->drop_untagged));
	if (v->vlan_membership_bitmask) {
		int i;
		bool is_trunk = true;

		pfprintf(matsp, "        vlan membership: ");
		for (i = 0; i < MAX_VLAN; i++) {
			int slot = (i / 8);

			if (v->vlan_membership_bitmask[slot] != 0xff) {
				if (slot == 0 && v->vlan_membership_bitmask[slot] == 0xfe)
					continue;
				is_trunk = false;
				break;
			}
		}

		for (i = 0; !is_trunk && i < MAX_VLAN; i++) {
			int slot = (i / 8);
			__u8 index = (__u8) (i % 8);
			if ((v->vlan_membership_bitmask[slot] >> index) & 0x01) {
				pfprintf(matsp, "%i ", i);
			}
		}
		pfprintf(matsp, "%s\n", is_trunk ? "trunk" : "");
	}

}

void pp_port(struct mat_stream *matsp,
	     struct net_mat_port *port)
{
	pfprintf(matsp, " port %u:\n", port->port_id);
	pfprintf(matsp, "    state: %s\n", port_state_str(port->state));
	pfprintf(matsp, "    speed: %s\n", port_speed_str(port->speed));
	if (port->port_phys_id)
		pfprintf(matsp, "    phys_id: %u\n", port->port_phys_id);
	if (port->max_frame_size)
		pfprintf(matsp, "    max_frame_size: %u\n",
		         port->max_frame_size);
	pfprintf(matsp, "    type: %s\n", port_type_str(port->type));

	if (port->pci.bus) {
		pfprintf(matsp, "    pci: (%x:%x.%x)\n",
			 port->pci.bus, port->pci.device, port->pci.function);
	}

	if (port->loopback)
		pfprintf(matsp, "    loopback: %s\n",
			 flag_state_str(port->loopback));

	if (port->glort) {
		pfprintf(matsp, "    glort: 0x%x\n", port->glort);
	}

	if (port->learning)
		pfprintf(matsp, "    learning: %s\n", flag_state_str(port->learning));

	if (port->update_dscp)
		pfprintf(matsp, "    update_dscp: %s\n", flag_state_str(port->update_dscp));

	if (port->update_ttl)
		pfprintf(matsp, "    update_ttl: %s\n", flag_state_str(port->update_ttl));

	if (port->mcast_flooding)
		pfprintf(matsp, "    mcast_flooding: %s\n", flag_state_str(port->mcast_flooding));

	if (port->update_dmac)
		pfprintf(matsp, "    update_dmac: %s\n", flag_state_str(port->update_dmac));

	if (port->update_smac)
		pfprintf(matsp, "    update_smac: %s\n", flag_state_str(port->update_smac));

	if (port->update_vlan)
		pfprintf(matsp, "    update_vlan: %s\n", flag_state_str(port->update_vlan));

	pp_port_vlan(matsp, &port->vlan);

	pp_port_stats(matsp, &port->stats);
}

void pp_ports(struct mat_stream *matsp, struct net_mat_port *ports)
{
        int i;

        if (!matsp)
                return;

        for (i = 0; ports[i].port_id != NET_MAT_PORT_ID_UNSPEC; i++)
                pp_port(matsp, &ports[i]);
}

static int match_compar_graph_nodes(const void *a, const void *b)
{
	const struct net_mat_tbl_node *g_a, *g_b;
	const struct net_mat_tbl *t_a, *t_b;

	g_a = a;
	g_b = b;

	t_a = get_tables(g_a->uid);
	t_b = get_tables(g_b->uid);

	if (!t_a || !t_b) {
		MAT_LOG(ERR, "Error: no tables to compare\n");
		return -1;
	}
	if (t_a->source < t_b->source)
		return -1;
	else if (t_a->source == t_b->source)
		return 0;
	else if (t_a->source > t_b->source)
		return 1;

	return -EINVAL;
}

static void pp_tbl_node_flags(struct mat_stream *matsp, __u32 flags)
{
	if (!matsp)
		return;

	if (flags)
		pfprintf(matsp, "( ");
	if (flags & NET_MAT_TABLE_EGRESS_ROOT)
		pfprintf(matsp, "EGRESS ");
	if (flags & NET_MAT_TABLE_INGRESS_ROOT)
		pfprintf(matsp, "INGRESS ");
	if (flags & NET_MAT_TABLE_DYNAMIC)
		pfprintf(matsp, "DYNAMIC ");
	if (flags)
		pfprintf(matsp, ") ");
}

void pp_table_graph(struct mat_stream *matsp, struct net_mat_tbl_node *nodes)
{
	unsigned int src = 0;
	unsigned int i, j;

	if (!matsp)
		return;

	for (i = 0; nodes[i].uid; i++)
		;

	qsort(nodes, i, sizeof(*nodes), match_compar_graph_nodes);
	for (i = 0; nodes[i].uid; i++) {
		struct net_mat_tbl *t = get_tables(nodes[i].uid);

		if(!t) {
			MAT_LOG(ERR, "Error: table doesn't exist\n");
			return;
		}
		if (src != t->source) {
			src = t->source;
			pfprintf(matsp, "source: %u: ", src);
		}

		pfprintf(matsp, " %s ", table_names(nodes[i].uid));
		pp_tbl_node_flags(matsp, nodes[i].flags);
		pfprintf(matsp, "\n");

		if (nodes[i].jump) {
			for (j = 0; nodes[i].jump[j].node || nodes[i].jump[j].field.instance; ++j)
				pp_jump_table(matsp, &nodes[i].jump[j]);
		} else {
			pfprintf(matsp, "\t * -> terminal\n");
		}
	}

	mat_stream_flush(matsp);
}

static void ppg_jump_table(struct mat_stream *matsp __unused, struct net_mat_jump_table *jump,
			   Agraph_t *g, Agnode_t *n)
{
	Agedge_t *e;

	if (jump->node > 0) {
		e = agedge(g, n, graphviz_table_nodes[jump->node], 0, 1);

		if (jump->field.instance)
			pp_field_ref(NULL, &jump->field, 0, false, e);
	}
}

void ppg_table_graph(struct mat_stream *matsp, struct net_mat_tbl_node *nodes)
{
	Agraph_t *s = NULL, *g = agopen(agopen_g, Agdirected, 0);
	char srcstr[80];
	__u32 src = 0;
	unsigned int i, j;
	FILE *fp = NULL;

	if (matsp)
		fp = mat_stream_get_fp(matsp);

	agsafeset(g, rankdir, LR, empty);
	for (i = 0; nodes[i].uid; i++) {
		struct net_mat_tbl *t = get_tables(nodes[i].uid);
		Agnode_t *n;
		if(!t) {
			MAT_LOG(ERR, "Error: table doesn't exist\n");
			return;
		}

		if (src != t->source) {
			src = t->source;
			sprintf(srcstr, "cluster-%u", src);
			s = agsubg(g, srcstr, 1);
			sprintf(srcstr, "source-%u", src);
			agsafeset(s, label, srcstr, empty);
		}

		n = agnode(s, table_names(nodes[i].uid), 1);

		agsafeset(n, shape, record, empty); /* use record boxes */
		graphviz_table_nodes[nodes[i].uid] = n;
	}

	qsort(nodes, i, sizeof(*nodes), match_compar_graph_nodes);
	for (i = 0; nodes[i].uid; i++) {
		for (j = 0; nodes[i].jump && nodes[i].jump[j].node; ++j)
			ppg_jump_table(matsp, &nodes[i].jump[j], s,
				       graphviz_table_nodes[nodes[i].uid]);
	}
	agwrite(g, fp);
}

void ppg_header_graph(struct mat_stream *matsp, struct net_mat_hdr_node *nodes)
{
	Agraph_t *g = agopen(agopen_g, Agdirected, 0);
	Agedge_t *e;
	int i, j;
	FILE *fp = NULL;

	if (matsp)
		fp = mat_stream_get_fp(matsp);

	for (i = 0; nodes[i].uid; i++)
		graphviz_header_nodes[nodes[i].uid] = agnode(g, nodes[i].name, 1);

#if 0
		for (j = 0; nodes[i].hdrs[j]; j++)
			pfprintf(matsp, " %s ",
				 headers_names(nodes[i].hdrs[j]));
#endif

	for (i = 0; nodes[i].uid; i++) {
		for (j = 0; nodes[i].jump && nodes[i].jump[j].node; ++j) {
			if (nodes[i].jump[j].node > 0) {
				e = agedge(g, graphviz_header_nodes[nodes[i].uid],
					   graphviz_header_nodes[nodes[i].jump[j].node],
					   0, 1);
				pp_field_ref(NULL, &nodes[i].jump[j].field,
					     0, false, e);
			}
		}
	}
	agwrite(g, fp);
}

void pp_header_graph(struct mat_stream *matsp, struct net_mat_hdr_node *nodes)
{
	int i, j;

	if (!matsp)
		return;

	for (i = 0; nodes[i].uid; i++) {
		pfprintf(matsp, "%s: ", nodes[i].name);

		for (j = 0; nodes[i].hdrs && nodes[i].hdrs[j]; j++)
			pfprintf(matsp, " %s ",
				 headers_names(nodes[i].hdrs[j]));

		pfprintf(matsp, "\n");
		for (j = 0; nodes[i].jump && nodes[i].jump[j].node; ++j) {
			pp_field_ref(matsp, &nodes[i].jump[j].field, 0,
				     false, NULL);
			if (!nodes[i].jump[j].node)
				pfprintf(matsp, " -> terminal\n");
			else
				pfprintf(matsp, " -> %s\n",
					 graph_names(nodes[i].jump[j].node));
		}
		pfprintf(matsp, "\n");
	}

	mat_stream_flush(matsp);
}

int match_get_field(struct mat_stream *matsp, struct nlattr *nla,
		struct net_mat_field_ref *field)
{
	struct nlattr *ref[NET_MAT_FIELD_REF_MAX+1];
	int err;

	err = nla_parse_nested(ref, NET_MAT_FIELD_REF_MAX,
			       nla, net_mat_field_policy);
	if (err)
		return err;

	if (!ref[NET_MAT_FIELD_REF_INSTANCE] ||
	    !ref[NET_MAT_FIELD_REF_HEADER] ||
	    !ref[NET_MAT_FIELD_REF_FIELD] ||
	    !ref[NET_MAT_FIELD_REF_MASK_TYPE] ||
	    !ref[NET_MAT_FIELD_REF_TYPE])
		return 0;

	field->instance = nla_get_u32(ref[NET_MAT_FIELD_REF_INSTANCE]);
	field->header = nla_get_u32(ref[NET_MAT_FIELD_REF_HEADER]);
	field->field = nla_get_u32(ref[NET_MAT_FIELD_REF_FIELD]);
	field->mask_type = nla_get_u32(ref[NET_MAT_FIELD_REF_MASK_TYPE]);
	field->type = nla_get_u32(ref[NET_MAT_FIELD_REF_TYPE]);

	if (!ref[NET_MAT_FIELD_REF_VALUE])
		goto out;

	switch (field->type) {
	case NET_MAT_FIELD_REF_ATTR_TYPE_U8:
		if (nla_len(ref[NET_MAT_FIELD_REF_VALUE]) < (int)sizeof(__u8)) {
			err = -EINVAL;
			break;
		}
		field->v.u8.value_u8 = nla_get_u8(ref[NET_MAT_FIELD_REF_VALUE]);

		if (!ref[NET_MAT_FIELD_REF_MASK])
			break;

		if (nla_len(ref[NET_MAT_FIELD_REF_MASK]) < (int)sizeof(__u8)) {
			err = -EINVAL;
			break;
		}
		field->v.u8.mask_u8 = nla_get_u8(ref[NET_MAT_FIELD_REF_MASK]);
		break;
	case NET_MAT_FIELD_REF_ATTR_TYPE_U16:
		if (nla_len(ref[NET_MAT_FIELD_REF_VALUE]) < (int)sizeof(__u16)) {
			err = -EINVAL;
			break;
		}
		field->v.u16.value_u16 = nla_get_u16(ref[NET_MAT_FIELD_REF_VALUE]);

		if (!ref[NET_MAT_FIELD_REF_MASK])
			break;

		if (nla_len(ref[NET_MAT_FIELD_REF_MASK]) < (int)sizeof(__u16)) {
			err = -EINVAL;
			break;
		}
		field->v.u16.mask_u16 = nla_get_u16(ref[NET_MAT_FIELD_REF_MASK]);
		break;
	case NET_MAT_FIELD_REF_ATTR_TYPE_U32:
		if (nla_len(ref[NET_MAT_FIELD_REF_VALUE]) < (int)sizeof(__u32)) {
			err = -EINVAL;
			break;
		}
		field->v.u32.value_u32 = nla_get_u32(ref[NET_MAT_FIELD_REF_VALUE]);

		if (!ref[NET_MAT_FIELD_REF_MASK])
			break;

		if (nla_len(ref[NET_MAT_FIELD_REF_MASK]) < (int)sizeof(__u32)) {
			err = -EINVAL;
			break;
		}
		field->v.u32.mask_u32 = nla_get_u32(ref[NET_MAT_FIELD_REF_MASK]);
		break;
	case NET_MAT_FIELD_REF_ATTR_TYPE_U64:
		if (nla_len(ref[NET_MAT_FIELD_REF_VALUE]) < (int)sizeof(__u64)) {
			err = -EINVAL;
			break;
		}
		field->v.u64.value_u64 = nla_get_u64(ref[NET_MAT_FIELD_REF_VALUE]);

		if (!ref[NET_MAT_FIELD_REF_MASK])
			break;

		if (nla_len(ref[NET_MAT_FIELD_REF_MASK]) < (int)sizeof(__u64)) {
			err = -EINVAL;
			break;
		}
		field->v.u64.mask_u64 = nla_get_u64(ref[NET_MAT_FIELD_REF_MASK]);
		break;
	case NET_MAT_FIELD_REF_ATTR_TYPE_IN6:
		if (nla_len(ref[NET_MAT_FIELD_REF_VALUE]) < (int)sizeof(struct in6_addr)) {
			err = -EINVAL;
			break;
		}
		field->v.in6.value_in6 = *((struct in6_addr *)nla_data(ref[NET_MAT_FIELD_REF_VALUE]));

		if (!ref[NET_MAT_FIELD_REF_MASK])
			break;

		if (nla_len(ref[NET_MAT_FIELD_REF_MASK]) < (int)sizeof(struct in6_addr)) {
			err = -EINVAL;
			break;
		}
		field->v.in6.mask_in6 = *((struct in6_addr *)nla_data(ref[NET_MAT_FIELD_REF_MASK]));
		break;
	default:
		err = -EINVAL;
		break;
	}

out:
	pp_field_ref(matsp, field, -1, true, NULL);

	return err;
}

static int
match_get_action_arg(struct net_mat_action_arg *arg, struct nlattr *nl)
{
	struct nlattr *tb[NET_MAT_ACTION_ARG_MAX+1];
	int err;

	err = nla_parse_nested(tb, NET_MAT_ACTION_ARG_MAX, nl,
			       net_mat_action_arg_policy);
	if (err) {
		MAT_LOG(ERR, "Warning, parse error parsing actions %i\n", err);
		return -EINVAL;
	}

	if (!tb[NET_MAT_ACTION_ARG_TYPE])
		return -EINVAL;

	if (tb[NET_MAT_ACTION_ARG_NAME]) {
		int max = nla_len(tb[NET_MAT_ACTION_ARG_NAME]);

		if (max < 0)
			return -EINVAL;

		if (max > NET_MAT_MAX_NAME)
			max = NET_MAT_MAX_NAME;

		arg->name = calloc(1, (unsigned int)max);
		if (!arg->name)
			return -ENOMEM;

		nla_strlcpy(arg->name, tb[NET_MAT_ACTION_ARG_NAME],
			    (unsigned int)max);
	} else {
		arg->name = none;
	}

	arg->type = nla_get_u32(tb[NET_MAT_ACTION_ARG_TYPE]);

	if (!tb[NET_MAT_ACTION_ARG_VALUE])
		return 0;

	switch (arg->type) {
	case NET_MAT_ACTION_ARG_TYPE_U8:
		if (nla_len(tb[NET_MAT_ACTION_ARG_VALUE]) < (int)sizeof(__u8))
			return -EINVAL;
		arg->v.value_u8 = nla_get_u8(tb[NET_MAT_ACTION_ARG_VALUE]);
		break;
	case NET_MAT_ACTION_ARG_TYPE_U16:
		if (nla_len(tb[NET_MAT_ACTION_ARG_VALUE]) < (int)sizeof(__u16))
			return -EINVAL;
		arg->v.value_u16 = nla_get_u16(tb[NET_MAT_ACTION_ARG_VALUE]);
		break;
	case NET_MAT_ACTION_ARG_TYPE_U32:
		if (nla_len(tb[NET_MAT_ACTION_ARG_VALUE]) < (int)sizeof(__u32))
			return -EINVAL;
		arg->v.value_u32 = nla_get_u32(tb[NET_MAT_ACTION_ARG_VALUE]);
		break;
	case NET_MAT_ACTION_ARG_TYPE_U64:
		if (nla_len(tb[NET_MAT_ACTION_ARG_VALUE]) < (int)sizeof(__u64))
			return -EINVAL;
		arg->v.value_u64 = nla_get_u64(tb[NET_MAT_ACTION_ARG_VALUE]);
		break;
	case NET_MAT_ACTION_ARG_TYPE_IN6:
		if (nla_len(tb[NET_MAT_ACTION_ARG_VALUE]) < (int)sizeof(struct in6_addr))
			return -EINVAL;
		arg->v.value_in6 = *((struct in6_addr *)nla_data(tb[NET_MAT_ACTION_ARG_VALUE]));
		break;
	case NET_MAT_ACTION_ARG_TYPE_VARIADIC:
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

int match_get_action(struct mat_stream *matsp, struct nlattr *nl,
		     struct net_mat_action *a)
{
	int rem;
	struct nlattr *signature, *l;
	struct nlattr *action[NET_MAT_ACTION_ATTR_MAX+1];
	struct net_mat_action *act = NULL;
	int err = 0;
	unsigned int count = 0;
	char *name;

	err = nla_parse_nested(action, NET_MAT_ACTION_ATTR_MAX, nl,
			       net_mat_action_policy);
	if (err) {
		MAT_LOG(ERR, "Warning, parse error parsing actions %i\n", err);
		err = -EINVAL;
		goto out;
	}

	if (!action[NET_MAT_ACTION_ATTR_UID])
		goto out;

	if (a) {
		act = a;
	} else {
		act = calloc(1, sizeof(struct net_mat_action));
		if (!act) {
			err = -ENOMEM;
			goto out;
		}
	}

	act->uid = nla_get_u32(action[NET_MAT_ACTION_ATTR_UID]);
	if (action[NET_MAT_ACTION_ATTR_NAME]) {
		name = nla_get_string(action[NET_MAT_ACTION_ATTR_NAME]);
		act->name = strdup(name);
		if (!act->name) {
			err = -ENOMEM;
			goto out;
		}
	} else {
		act->name = strdup(none);
	}

	if (!action[NET_MAT_ACTION_ATTR_SIGNATURE])
		goto done;

	signature = action[NET_MAT_ACTION_ATTR_SIGNATURE];
	rem = nla_len(signature);
	for (l = nla_data(signature); nla_ok(l, rem); l = nla_next(l, &rem))
		count++;

	if (count > 0) {
		act->args = calloc(count + 1, sizeof(struct net_mat_action_arg));
		if (!act->args) {
			err = -ENOMEM;
			goto out;
		}
	}

	count = 0;

	rem = nla_len(signature);
	for (l = nla_data(signature); nla_ok(l, rem); l = nla_next(l, &rem)) {
		err = match_get_action_arg(&act->args[count], l);
		if (err)
			goto out;
		count++;
	}

done:
	pp_action(matsp, act, false);
	if (!a) {
		free(act->args);
		free(act->name);
		free(act);
	}
	return err;
out:
	if (act) {
		free(act->args);
		free(act->name);
		if (!a)
			free(act);
	}
	return err;
}

int match_get_matches(struct mat_stream *matsp, struct nlattr *nl,
		struct net_mat_field_ref **ref)
{
	struct net_mat_field_ref *r;
	struct nlattr *i;
	int rem;
	unsigned int cnt;

	rem = nla_len(nl);
	for (i = nla_data(nl), cnt = 0; nla_ok(i, rem); i = nla_next(i, &rem))
		cnt++;

	r = calloc(cnt + 1, sizeof(struct net_mat_field_ref));
	if (!r)
		return -ENOMEM;

	rem = nla_len(nl);
	for (i = nla_data(nl), cnt = 0; nla_ok(i, rem); i = nla_next(i, &rem), cnt++)
		match_get_field(matsp, i, &r[cnt]);

	if (ref)
		*ref = r;
	return 0;
}

int match_get_actions(struct mat_stream *matsp, struct nlattr *nl,
		struct net_mat_action **actions)
{
	struct net_mat_action *acts;
	unsigned int j = 0;
	int rem;
	struct nlattr *i;

	rem = nla_len(nl);
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem))
		j++;

	acts = calloc(j + 1, sizeof(struct net_mat_action));
	if (!acts)
		return -ENOMEM;

	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem), j++)
		match_get_action(matsp, i, &acts[j]);

	if (actions)
		*actions = acts;
	else
		free(acts);

	return 0;
}

static int
match_get_named_value(struct net_mat_named_value *v, struct nlattr *nl)
{
	struct nlattr *tb[NET_MAT_TABLE_ATTR_VALUE_T_MAX+1];
	int err;

	err = nla_parse_nested(tb, NET_MAT_TABLE_ATTR_VALUE_T_MAX, nl,
			       net_mat_named_value_policy);
	if (err) {
		MAT_LOG(ERR, "Warning, parse error parsing actions %i\n", err);
		return -EINVAL;
	}

	if (!tb[NET_MAT_TABLE_ATTR_VALUE_T_TYPE] ||
	    !tb[NET_MAT_TABLE_ATTR_VALUE_T_UID])
		return -EINVAL;

	if (tb[NET_MAT_TABLE_ATTR_VALUE_T_NAME]) {
		int max = nla_len(tb[NET_MAT_TABLE_ATTR_VALUE_T_NAME]);

		if (max < 0)
			return -EINVAL;

		if (max > NET_MAT_MAX_NAME)
			max = NET_MAT_MAX_NAME;

		v->name = calloc(1, (unsigned int)max);
		if (!v->name)
			return -ENOMEM;

		nla_strlcpy(v->name, tb[NET_MAT_TABLE_ATTR_VALUE_T_NAME],
			    (unsigned int)max);
	} else {
		v->name = none;
	}

	v->uid = nla_get_u32(tb[NET_MAT_TABLE_ATTR_VALUE_T_UID]);
	v->type = nla_get_u32(tb[NET_MAT_TABLE_ATTR_VALUE_T_TYPE]);

	if (tb[NET_MAT_TABLE_ATTR_VALUE_T_WRITE])
		v->write = nla_get_u8(tb[NET_MAT_TABLE_ATTR_VALUE_T_WRITE]);

	if (!tb[NET_MAT_TABLE_ATTR_VALUE_T_TYPE] &&
	    v->type == NET_MAT_NAMED_VALUE_TYPE_NULL)
		return 0;
	else if (!tb[NET_MAT_TABLE_ATTR_VALUE_T_TYPE])
		goto out;

	switch (v->type) {
	case NET_MAT_NAMED_VALUE_TYPE_U8:
		if (nla_len(tb[NET_MAT_TABLE_ATTR_VALUE_T_VALUE]) < (int)sizeof(__u8))
			goto out;
		v->value.u8 = nla_get_u8(tb[NET_MAT_TABLE_ATTR_VALUE_T_VALUE]);
		break;
	case NET_MAT_NAMED_VALUE_TYPE_U16:
		if (nla_len(tb[NET_MAT_TABLE_ATTR_VALUE_T_VALUE]) < (int)sizeof(__u16))
			goto out;
		v->value.u16 = nla_get_u16(tb[NET_MAT_TABLE_ATTR_VALUE_T_VALUE]);
		break;
	case NET_MAT_NAMED_VALUE_TYPE_U32:
		if (nla_len(tb[NET_MAT_TABLE_ATTR_VALUE_T_VALUE]) < (int)sizeof(__u32))
			goto out;
		v->value.u32 = nla_get_u32(tb[NET_MAT_TABLE_ATTR_VALUE_T_VALUE]);
		break;
	case NET_MAT_NAMED_VALUE_TYPE_U64:
		if (nla_len(tb[NET_MAT_TABLE_ATTR_VALUE_T_VALUE]) < (int)sizeof(__u64))
			goto out;
		v->value.u64 = nla_get_u64(tb[NET_MAT_TABLE_ATTR_VALUE_T_VALUE]);
		break;
	default:
		goto out;
	}

	return 0;
out:
	if(v->name != none)
		free(v->name);
	return -EINVAL;
}

int match_get_table(struct mat_stream *matsp, struct nlattr *nl,
		   struct net_mat_tbl *t)
{
	struct nlattr *table[NET_MAT_TABLE_ATTR_MAX+1];
	struct net_mat_field_ref *matches = NULL;
	struct net_mat_named_value *values = NULL;
	__u32 uid, src, apply, size;
	int rem, err = 0;
	unsigned int cnt;
	__u32 *actions = NULL;
	struct nlattr *i;
	char *name;

	err = nla_parse_nested(table, NET_MAT_TABLE_ATTR_MAX, nl,
			       net_mat_table_policy);
	if (err) {
		MAT_LOG(ERR, "Warning parse error rule attribs, abort parse\n");
		return err;
	}

	name = table[NET_MAT_TABLE_ATTR_NAME] ? nla_get_string(table[NET_MAT_TABLE_ATTR_NAME]) : none,
	uid = table[NET_MAT_TABLE_ATTR_UID] ? nla_get_u32(table[NET_MAT_TABLE_ATTR_UID]) : 0;
	if (uid > MAX_TABLES - 1) {
		MAT_LOG(ERR, "Error: table id out of range (max=%d)\n",
			MAX_TABLES - 1);
		return -ERANGE;
	}

	src = table[NET_MAT_TABLE_ATTR_SOURCE] ? nla_get_u32(table[NET_MAT_TABLE_ATTR_SOURCE]) : 0;
	apply = table[NET_MAT_TABLE_ATTR_APPLY] ? nla_get_u32(table[NET_MAT_TABLE_ATTR_APPLY]) : 0;
	size = table[NET_MAT_TABLE_ATTR_SIZE] ? nla_get_u32(table[NET_MAT_TABLE_ATTR_SIZE]) : 0;

	if (table[NET_MAT_TABLE_ATTR_MATCHES])
		match_get_matches(NULL, table[NET_MAT_TABLE_ATTR_MATCHES], &matches);

	if (table[NET_MAT_TABLE_ATTR_ACTIONS]) {
		rem = nla_len(table[NET_MAT_TABLE_ATTR_ACTIONS]);
		for (cnt = 0, i = nla_data(table[NET_MAT_TABLE_ATTR_ACTIONS]);
		     nla_ok(i, rem); i = nla_next(i, &rem))
			cnt++;

		actions = calloc(cnt + 1, sizeof(__u32));
		if (!actions)
			goto out;

		rem = nla_len(table[NET_MAT_TABLE_ATTR_ACTIONS]);
		for (cnt = 0, i = nla_data(table[NET_MAT_TABLE_ATTR_ACTIONS]);
		     nla_ok(i, rem); i = nla_next(i, &rem), cnt++) {
			actions[cnt] = nla_get_u32(i);
		}
	}

	if (table[NET_MAT_TABLE_ATTR_NAMED_VALUES]) {
		rem = nla_len(table[NET_MAT_TABLE_ATTR_NAMED_VALUES]);
		for (cnt = 0, i = nla_data(table[NET_MAT_TABLE_ATTR_NAMED_VALUES]);
		     nla_ok(i, rem);
		     i = nla_next(i, &rem))
			cnt++;

		values = calloc(cnt + 1, sizeof(struct net_mat_named_value));
		if (!values)
			goto out;

		rem = nla_len(table[NET_MAT_TABLE_ATTR_NAMED_VALUES]);
		for (cnt = 0, i = nla_data(table[NET_MAT_TABLE_ATTR_NAMED_VALUES]);
		     nla_ok(i, rem);
		     i = nla_next(i, &rem), cnt++) {
			match_get_named_value(&values[cnt], i);
		}
	}

	t->name = strdup(name);
	if (!t->name)
		goto out;
	t->uid = uid;
	t->source = src;
	t->apply_action = apply;
	t->size = size;

	t->matches = matches;
	t->actions = actions;
	t->attribs = values;

	pp_table(matsp, t);
	return 0;
out:
	if (matches)
		free(matches);
	if (actions)
		free(actions);
	if (values)
		free(values);
	if (t->name) {
		free(t->name);
		t->name = NULL;
	}
	return -ENOMEM;
}

int match_get_tables(struct mat_stream *matsp, struct nlattr *nl,
		      struct net_mat_tbl **t)
{
	struct net_mat_tbl *tables = NULL;
	struct nlattr *i;
	int err, rem;
	unsigned cnt = 0;

	rem = nla_len(nl);
	for (cnt = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem))
		cnt++;

	tables = calloc(cnt + 1, sizeof(struct net_mat_tbl));
	if (!tables)
		return -ENOMEM;

	rem = nla_len(nl);
	for (cnt = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem), cnt++) {
		err = match_get_table(matsp, i, &tables[cnt]);
		if (err)
			goto out;
	}

	if (matsp)
		pfprintf(matsp, "\n");

	if (t)
		*t = tables;

	return 0;
out:
	free(tables);
	return err;
}

int match_get_rules(struct mat_stream *matsp, struct nlattr *attr,
		struct net_mat_rule **rules)
{
	struct net_mat_field_ref *matches = NULL;
	struct net_mat_action *actions = NULL;
	struct net_mat_rule  *f;
	struct nlattr *i;
	int err, rem;
	unsigned int count = 0, idx = 0;

	rem = nla_len(attr);
	for (i = nla_data(attr);  nla_ok(i, rem); i = nla_next(i, &rem))
		count++;

	f = calloc(count + 1, sizeof(struct net_mat_rule));
	if (!f)
		return -EMSGSIZE;

	rem = nla_len(attr);
	for (count = 0, i = nla_data(attr);
	     nla_ok(i, rem); i = nla_next(i, &rem), count++) {
		struct nlattr *rule[NET_MAT_ATTR_MAX+1];

		matches = NULL;
		actions = NULL;

		err = nla_parse_nested(rule, NET_MAT_ATTR_MAX, i,
				       match_table_rule_policy);
		if (err) {
			MAT_LOG(ERR, "Warning: get_rule parse error skipping input.\n");
			continue;
		}

		if (rule[NET_MAT_ATTR_TABLE])
			f[count].table_id = nla_get_u32(rule[NET_MAT_ATTR_TABLE]);

		if (rule[NET_MAT_ATTR_UID])
			f[count].uid = nla_get_u32(rule[NET_MAT_ATTR_UID]);

		if (rule[NET_MAT_ATTR_PRIORITY])
			f[count].priority = nla_get_u32(rule[NET_MAT_ATTR_PRIORITY]);

		if (rule[NET_MAT_ATTR_BYTES])
			f[count].bytes = nla_get_u64(rule[NET_MAT_ATTR_BYTES]);

		if (rule[NET_MAT_ATTR_PACKETS])
			f[count].packets = nla_get_u64(rule[NET_MAT_ATTR_PACKETS]);

		if (rule[NET_MAT_ATTR_MATCHES]) {
			err = match_get_matches(NULL,
					       rule[NET_MAT_ATTR_MATCHES],
					       &matches);
			if (err) {
				MAT_LOG(ERR, "Warning get_rule matches parse error skipping input.\n");
				continue;
			}
		}

		if (rule[NET_MAT_ATTR_ACTIONS]) {
			err = match_get_actions(NULL,
					       rule[NET_MAT_ATTR_ACTIONS],
					       &actions);
			if (err) {
				MAT_LOG(ERR, "Warning get_rule actions parse error skipping input.\n");
				continue;
			}
		}

		f[count].matches = matches;
		f[count].actions = actions;
	}

	pp_rules(matsp, f);
	if (rules)
		*rules = f;
	else {
		for (idx = 0; idx < count; idx++) {
			free(f[idx].matches);
			free(f[idx].actions);
		}
		free(f);
	}
	return 0;
}

unsigned int match_get_rule_errors(struct nlattr *nla)
{
	return nla_get_u32(nla);
}

int
match_get_table_field(struct mat_stream *matsp __unused, struct nlattr *nl,
		struct net_mat_hdr *hdr)
{
	struct nlattr *field[NET_MAT_FIELD_ATTR_MAX+1];
	unsigned int count = 0, idx = 0;
	struct nlattr *i;
	int rem, err = 0;

	/* TBD this couting stuff is a bit clumsy */
	rem = nla_len(nl);
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem))
		count++;

	hdr->fields = calloc(count + 1, sizeof(hdr->fields[0]));
	if (!hdr->fields) {
		MAT_LOG(ERR, "%s: Unable to allocate memory\n", __func__);
		err = -ENOMEM;
		goto out;
	}

	hdr->field_sz = count;

	count = 0;
	rem = nla_len(nl);
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem)) {
		struct net_mat_field *f = &hdr->fields[count];

		if (!f)
			continue;

		err = nla_parse_nested(field, NET_MAT_FIELD_ATTR_MAX, i,
				       match_get_field_policy);
		if (err) {
			MAT_LOG(ERR, "Warning field parse error\n");
			err = -EINVAL;
			goto out;
		}

		f->uid = field[NET_MAT_FIELD_ATTR_UID] ?
			 nla_get_u32(field[NET_MAT_FIELD_ATTR_UID]) : 0;
		f->name = strdup((field[NET_MAT_FIELD_ATTR_NAME] ?
			  nla_get_string(field[NET_MAT_FIELD_ATTR_NAME]) : none));
		f->bitwidth = field[NET_MAT_FIELD_ATTR_BITWIDTH] ?
			      nla_get_u32(field[NET_MAT_FIELD_ATTR_BITWIDTH]) : 0;
		header_fields[hdr->uid][f->uid] = f;
		count++;
	}

	return err;
out:
	for (idx = 0; hdr->fields && idx < count; idx++)
		free(hdr->fields[idx].name);
	free(hdr->fields);
	return err;
}

int match_get_headers(struct mat_stream *matsp, struct nlattr *nl,
		struct net_mat_hdr **hdrs)
{
	unsigned int count = 0;
	struct net_mat_hdr *h = NULL;
	struct nlattr *i;
	int rem;
	int err = 0;

	rem = nla_len(nl);
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem))
		count++;

	h = calloc(count + 1, sizeof(h[0]));
	if (!h) {
		MAT_LOG(ERR, "Unable to allocate memory\n");
		err = -ENOMEM;
		goto out;
	}

	rem = nla_len(nl);
	count = 0;
	for (i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem)) {
		struct nlattr *hdr[NET_MAT_HEADER_ATTR_MAX+1];
		struct net_mat_hdr *header;
		int err;

		err = nla_parse_nested(hdr, NET_MAT_HEADER_ATTR_MAX, i,
				       match_get_header_policy);
		if (err) {
			MAT_LOG(ERR, "Warning header parse error. aborting.\n");
			err = -EINVAL;
			goto out;
		}

		header = calloc(1, sizeof(*header));
		if (!header) {
			MAT_LOG(ERR, "Warning OOM in header parser. aborting.\n");
			err = -ENOMEM;
			goto out;
		}

		header->uid = hdr[NET_MAT_HEADER_ATTR_UID] ?
				nla_get_u32(hdr[NET_MAT_HEADER_ATTR_UID]) : 0;
		header->name =
			strdup(hdr[NET_MAT_HEADER_ATTR_NAME] ?
				nla_get_string(hdr[NET_MAT_HEADER_ATTR_NAME]) : empty);
		match_get_table_field(matsp,
				     hdr[NET_MAT_HEADER_ATTR_FIELDS],
				     header);
		headers[header->uid] = header;
		pp_header(matsp, header);
		h[count] = *header;
		count++;
	}

	if (hdrs)
		*hdrs = h;
	else
		free(h);

	return err;

out:
	free(h);
	return err;
}



static int match_get_jump(struct mat_stream *matsp, struct nlattr *nl,
		struct net_mat_jump_table *j)
{
	struct nlattr *ref[NET_MAT_FIELD_REF_MAX+1];
	int err;

	err = nla_parse_nested(ref, NET_MAT_FIELD_REF_MAX, nl,
			       net_mat_field_policy);
	if (err)
		return err;

	if (!ref[NET_MAT_FIELD_REF_NEXT_NODE])
		return -EINVAL;

	j->node = nla_get_u32(ref[NET_MAT_FIELD_REF_NEXT_NODE]);
	match_get_field(matsp, nl, &j->field);

	pp_jump_table(matsp, j);
	return 0;
}

static int match_get_jump_table(struct mat_stream *matsp, struct nlattr *nl,
		struct net_mat_jump_table **ref)
{
	struct net_mat_jump_table *jump = NULL;
	struct nlattr *i;
	int rem;
	unsigned int j;

	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem))
		j++;
	jump = calloc(j + 1, sizeof(*jump));
	if (!jump)
		return -ENOMEM;
	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); j++, i = nla_next(i, &rem))
		match_get_jump(matsp, i, &jump[j]);

	if (ref)
		*ref = jump;
	else
		free(jump);
	return 0;
}

static int match_get_header_refs(struct nlattr *nl, __u32 **ref)
{
	__u32 *headers;
	int rem;
	unsigned int j;
	struct nlattr *i;

	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem))
		j++;

	headers = calloc(j + 1, sizeof(int));
	if (!headers)
		return -ENOMEM;

	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem), j++)
		headers[j] = nla_get_u32(i);

	if (ref)
		*ref = headers;
	else
		free(headers);
	return 0;
}

int match_get_hdrs_graph(struct mat_stream *matsp, int print, struct nlattr *nl,
		struct net_mat_hdr_node **ref)
{
	struct net_mat_hdr_node *nodes = NULL;
	int rem, err = 0;
	unsigned int j, idx = 0;
	struct nlattr *i;

	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem))
		j++;

	nodes = calloc(j + 1, sizeof(struct net_mat_hdr_node));
	if (!nodes) {
		MAT_LOG(ERR, "%s: Unable to allocate memory\n", __func__);
		err = -ENOMEM;
		goto out;
	}

	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem), j++) {
		struct nlattr *node[NET_MAT_HEADER_NODE_MAX+1];

		err = nla_parse_nested(node, NET_MAT_HEADER_NODE_MAX, i,
				       match_get_hdr_node_policy);
		if (err) {
			MAT_LOG(ERR, "Warning header graph node parse error. aborting.\n");
			err = -EINVAL;
			goto out;
		}

		if (node[NET_MAT_HEADER_NODE_NAME]) {
			char *name;

			name = nla_get_string(node[NET_MAT_HEADER_NODE_NAME]);
			nodes[j].name = strdup(name);
			if (!nodes[j].name) {
				err = -EINVAL;
				goto out;
			}
		}

		if (!node[NET_MAT_HEADER_NODE_UID]) {
			MAT_LOG(ERR, "Warning, missing header node uid attr %i\n", j);
			err = -EINVAL;
			goto out;
		}

		nodes[j].uid = nla_get_u32(node[NET_MAT_HEADER_NODE_UID]);
		graph_nodes[nodes[j].uid] = &nodes[j];

		if (!node[NET_MAT_HEADER_NODE_HDRS])
			continue; /* Not requried for terminating nodes */

		err = match_get_header_refs(node[NET_MAT_HEADER_NODE_HDRS],
					   &nodes[j].hdrs);
		if (err) {
			MAT_LOG(ERR, "Warning header refs parse error. aborting.\n");
			err = -EINVAL;
			goto out;
		}

		if (!node[NET_MAT_HEADER_NODE_JUMP])
			continue;

		err = match_get_jump_table(NULL,
					  node[NET_MAT_HEADER_NODE_JUMP],
					  &nodes[j].jump);
		if (err) {
			MAT_LOG(ERR, "Warning header graph jump parse error. aborting.\n");
			err = -EINVAL;
			goto out;
		}

	}

	if (print == PRINT_GRAPHVIZ)
		ppg_header_graph(matsp, nodes);
	else if (print)
		pp_header_graph(matsp, nodes);
	if (ref)
		*ref = nodes;

	return err;
out:
	for (idx = 0; nodes && idx < j; idx++)
		free(nodes[idx].jump);
	free(nodes);
	return err;
}

int match_get_tbl_graph(struct mat_stream *matsp, int print, struct nlattr *nl,
		struct net_mat_tbl_node **ref)
{
	struct net_mat_tbl_node *nodes = NULL;
	unsigned int j, idx;
	int rem, err = 0;
	struct nlattr *i;

	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem))
		j++;

	nodes = calloc(j + 1, sizeof(struct net_mat_tbl_node));
	if (!nodes) {
		MAT_LOG(ERR, "%s: Unable to allocate memory\n", __func__);
		err = -ENOMEM;
		goto out;
	}

	rem = nla_len(nl);
	for (j = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem), j++) {
		struct net_mat_tbl_node *n = &nodes[j];
		struct nlattr *node[NET_MAT_TABLE_GRAPH_NODE_MAX+1];

		err = nla_parse_nested(node, NET_MAT_TABLE_GRAPH_NODE_MAX, i,
				       match_get_node_policy);
		if (err) {
			MAT_LOG(ERR, "Warning table graph node parse error. aborting.\n");
			err = -EINVAL;
			goto out;
		}

		if (!node[NET_MAT_TABLE_GRAPH_NODE_UID]) {
			MAT_LOG(ERR, "Warning, missing graph node uid\n");
			err = -EINVAL;
			goto out;
		}

		n->uid = nla_get_u32(node[NET_MAT_TABLE_GRAPH_NODE_UID]);

		if (node[NET_MAT_TABLE_GRAPH_NODE_FLAGS])
			n->flags = nla_get_u32(node[NET_MAT_TABLE_GRAPH_NODE_FLAGS]);

		if (!node[NET_MAT_TABLE_GRAPH_NODE_JUMP])
			continue; /* valid for terminating nodes */

		err = match_get_jump_table(NULL,
					  node[NET_MAT_TABLE_GRAPH_NODE_JUMP],
					  &n->jump);
		if (err) {
			MAT_LOG(ERR, "Warning table graph jump parse error. aborting.\n");
			err = -EINVAL;
			goto out;
		}
	}
	if (print == PRINT_GRAPHVIZ)
		ppg_table_graph(matsp, nodes);
	else if (print)
		pp_table_graph(matsp, nodes);
	if (ref)
		*ref = nodes;
	return err;

out:
	for (idx = 0; nodes && idx < j; idx++)
		free(nodes[idx].jump);
	free(nodes);
	return err;
}

static int match_get_port_stats(struct mat_stream *matsp __unused,
			       struct nlattr *nlattr,
			       struct net_mat_port_stats *stats)
{
	struct nlattr *p[NET_MAT_PORT_T_STATS_MAX + 1];
	int err;

	err = nla_parse_nested(p, NET_MAT_PORT_T_STATS_MAX, nlattr, net_mat_port_stats_policy);
	if (err) {
		MAT_LOG(ERR, "Warning parse error on port stats, abort parse\n");
		return err;
	}

	if (p[NET_MAT_PORT_T_STATS_RX]) {
		struct nlattr *s[NET_MAT_PORT_T_STATS_RXTX_MAX + 1];

		err = nla_parse_nested(s, NET_MAT_PORT_T_STATS_RXTX_MAX,
				       p[NET_MAT_PORT_T_STATS_RX],
				       net_mat_port_stats_rxtx_policy);
		if (err) {
			MAT_LOG(ERR, "Warning parse error on port rx stats, abort parse\n");
			return err;
		}

		if (s[NET_MAT_PORT_T_STATS_BYTES])
			stats->rx_bytes = nla_get_u64(s[NET_MAT_PORT_T_STATS_BYTES]);
		if (s[NET_MAT_PORT_T_STATS_PACKETS])
			stats->rx_packets = nla_get_u64(s[NET_MAT_PORT_T_STATS_PACKETS]);
		if (s[NET_MAT_PORT_T_STATS_UNICAST_BYTES])
			stats->rx_unicast_bytes = nla_get_u64(s[NET_MAT_PORT_T_STATS_UNICAST_BYTES]);
		if (s[NET_MAT_PORT_T_STATS_MULTICAST_BYTES])
			stats->rx_multicast_bytes = nla_get_u64(s[NET_MAT_PORT_T_STATS_MULTICAST_BYTES]);
		if (s[NET_MAT_PORT_T_STATS_BROADCAST_BYTES])
			stats->rx_broadcast_bytes = nla_get_u64(s[NET_MAT_PORT_T_STATS_BROADCAST_BYTES]);
		if (s[NET_MAT_PORT_T_STATS_UNICAST_PACKETS])
			stats->rx_unicast_packets = nla_get_u64(s[NET_MAT_PORT_T_STATS_UNICAST_PACKETS]);
		if (s[NET_MAT_PORT_T_STATS_MULTICAST_PACKETS])
			stats->rx_multicast_packets = nla_get_u64(s[NET_MAT_PORT_T_STATS_MULTICAST_PACKETS]);
		if (s[NET_MAT_PORT_T_STATS_BROADCAST_PACKETS])
			stats->rx_broadcast_packets = nla_get_u64(s[NET_MAT_PORT_T_STATS_BROADCAST_PACKETS]);
	}

	if (p[NET_MAT_PORT_T_STATS_TX]) {
		struct nlattr *s[NET_MAT_PORT_T_STATS_RXTX_MAX + 1];

		err = nla_parse_nested(s, NET_MAT_PORT_T_STATS_RXTX_MAX,
				       p[NET_MAT_PORT_T_STATS_TX],
				       net_mat_port_stats_rxtx_policy);
		if (err) {
			MAT_LOG(ERR, "Warning parse error on port tx stats, abort parse\n");
			return err;
		}

		if (s[NET_MAT_PORT_T_STATS_BYTES])
			stats->tx_bytes = nla_get_u64(s[NET_MAT_PORT_T_STATS_BYTES]);
		if (s[NET_MAT_PORT_T_STATS_PACKETS])
			stats->tx_packets = nla_get_u64(s[NET_MAT_PORT_T_STATS_PACKETS]);
		if (s[NET_MAT_PORT_T_STATS_UNICAST_BYTES])
			stats->tx_unicast_bytes = nla_get_u64(s[NET_MAT_PORT_T_STATS_UNICAST_BYTES]);
		if (s[NET_MAT_PORT_T_STATS_MULTICAST_BYTES])
			stats->tx_multicast_bytes = nla_get_u64(s[NET_MAT_PORT_T_STATS_MULTICAST_BYTES]);
		if (s[NET_MAT_PORT_T_STATS_BROADCAST_BYTES])
			stats->tx_broadcast_bytes = nla_get_u64(s[NET_MAT_PORT_T_STATS_BROADCAST_BYTES]);
		if (s[NET_MAT_PORT_T_STATS_UNICAST_PACKETS])
			stats->tx_unicast_packets = nla_get_u64(s[NET_MAT_PORT_T_STATS_UNICAST_PACKETS]);
		if (s[NET_MAT_PORT_T_STATS_MULTICAST_PACKETS])
			stats->tx_multicast_packets = nla_get_u64(s[NET_MAT_PORT_T_STATS_MULTICAST_PACKETS]);
		if (s[NET_MAT_PORT_T_STATS_BROADCAST_PACKETS])
			stats->tx_broadcast_packets = nla_get_u64(s[NET_MAT_PORT_T_STATS_BROADCAST_PACKETS]);
	}

	return 0;
}

static int match_get_port_vlan(struct mat_stream *matsp __unused,
			       struct nlattr *nlattr,
			       struct net_mat_port_vlan *vlan)
{
	struct nlattr *p[NET_MAT_PORT_T_VLAN_MAX + 1];
	int err;

	err = nla_parse_nested(p, NET_MAT_PORT_T_VLAN_MAX, nlattr, net_mat_port_vlan_policy);
	if (err) {
		MAT_LOG(ERR, "Warning parse error on port vlan, abort parse\n");
		return err;
	}

	if (p[NET_MAT_PORT_T_VLAN_DEF_VLAN])
		vlan->def_vlan = nla_get_u32(p[NET_MAT_PORT_T_VLAN_DEF_VLAN]);

	if (p[NET_MAT_PORT_T_VLAN_DROP_TAGGED])
		vlan->drop_tagged = nla_get_u32(p[NET_MAT_PORT_T_VLAN_DROP_TAGGED]);

	if (p[NET_MAT_PORT_T_VLAN_DROP_UNTAGGED])
		vlan->drop_untagged = nla_get_u32(p[NET_MAT_PORT_T_VLAN_DROP_UNTAGGED]);

	if (p[NET_MAT_PORT_T_VLAN_DEF_PRIORITY])
		vlan->def_priority = nla_get_u32(p[NET_MAT_PORT_T_VLAN_DEF_PRIORITY]);

	if (p[NET_MAT_PORT_T_VLAN_MEMBERSHIP]) {
		const struct nlattr *attr = p[NET_MAT_PORT_T_VLAN_MEMBERSHIP];
		__u8 *data;

		if (nla_len(attr) < (MAX_VLAN / 8)) {
			printf("%s: length error expected %i got %i\n", __func__, MAX_VLAN / 8, nla_len(attr));
			return -NLE_RANGE;
		}

		if (nla_type(attr) != NET_MAT_PORT_T_VLAN_MEMBERSHIP) {
			printf("%s: unexpected type %i\n", __func__, nla_type(attr));
			return -EINVAL;
		}

		data = nla_data(p[NET_MAT_PORT_T_VLAN_MEMBERSHIP]);
		memcpy(vlan->vlan_membership_bitmask, data, MAX_VLAN / 8);
	}

	return 0;
}

int match_get_port(struct mat_stream *matsp, struct nlattr *nlattr,
		 struct net_mat_port *port)
{
	struct nlattr *p[NET_MAT_PORT_T_MAX + 1];
	int err;

	err = nla_parse_nested(p, NET_MAT_PORT_T_MAX, nlattr, net_mat_port_policy);
	if (err) {
		MAT_LOG(ERR, "Warning parse error rule attribs, abort parse\n");
		return err;
	}

	if (p[NET_MAT_PORT_T_ID])
		port->port_id = nla_get_u32(p[NET_MAT_PORT_T_ID]);

	if (p[NET_MAT_PORT_T_PHYS_ID])
		port->port_phys_id = nla_get_u32(p[NET_MAT_PORT_T_PHYS_ID]);

	if (p[NET_MAT_PORT_T_TYPE])
		port->type = nla_get_u32(p[NET_MAT_PORT_T_TYPE]);

	if (p[NET_MAT_PORT_T_STATE])
		port->state = nla_get_u32(p[NET_MAT_PORT_T_STATE]);

	if (p[NET_MAT_PORT_T_SPEED])
		port->speed = nla_get_u32(p[NET_MAT_PORT_T_SPEED]);

	if (p[NET_MAT_PORT_T_MAX_FRAME_SIZE])
		port->max_frame_size =
			nla_get_u32(p[NET_MAT_PORT_T_MAX_FRAME_SIZE]);

	if (p[NET_MAT_PORT_T_MAC_ADDR])
		port->mac_addr = nla_get_u64(p[NET_MAT_PORT_T_MAC_ADDR]);

	if (p[NET_MAT_PORT_T_GLORT])
		port->glort = nla_get_u32(p[NET_MAT_PORT_T_GLORT]);

	if (p[NET_MAT_PORT_T_PCI]) {
		struct net_mat_port_pci *pci;

		if (nla_len(p[NET_MAT_PORT_T_PCI]) < (int)sizeof(struct net_mat_port_pci))
			return -EINVAL;

		pci = nla_data(p[NET_MAT_PORT_T_PCI]);
		memcpy(&port->pci, pci, sizeof(struct net_mat_port_pci));
	}

	if (p[NET_MAT_PORT_T_STATS]) {
		err = match_get_port_stats(matsp, p[NET_MAT_PORT_T_STATS], &port->stats);
		if (err)
			return -EINVAL;
	}

	if (p[NET_MAT_PORT_T_VLAN]) {
		err = match_get_port_vlan(matsp, p[NET_MAT_PORT_T_VLAN], &port->vlan);
		if (err)
			return -EINVAL;
	}

	if (p[NET_MAT_PORT_T_LOOPBACK])
		port->loopback = nla_get_u32(p[NET_MAT_PORT_T_LOOPBACK]);

	if (p[NET_MAT_PORT_T_LEARNING])
		port->learning = nla_get_u32(p[NET_MAT_PORT_T_LEARNING]);

	if (p[NET_MAT_PORT_T_UPDATE_DSCP])
		port->update_dscp = nla_get_u32(p[NET_MAT_PORT_T_UPDATE_DSCP]);

	if (p[NET_MAT_PORT_T_UPDATE_TTL])
		port->update_ttl = nla_get_u32(p[NET_MAT_PORT_T_UPDATE_TTL]);

	if (p[NET_MAT_PORT_T_MCAST_FLOODING])
		port->mcast_flooding = nla_get_u32(p[NET_MAT_PORT_T_MCAST_FLOODING]);

	if (p[NET_MAT_PORT_T_UPDATE_DMAC])
		port->update_dmac = nla_get_u32(p[NET_MAT_PORT_T_UPDATE_DMAC]);

	if (p[NET_MAT_PORT_T_UPDATE_SMAC])
		port->update_smac = nla_get_u32(p[NET_MAT_PORT_T_UPDATE_SMAC]);

	if (p[NET_MAT_PORT_T_UPDATE_VLAN])
		port->update_vlan = nla_get_u32(p[NET_MAT_PORT_T_UPDATE_VLAN]);

	pp_port(matsp, port);
	return 0;
}

int match_get_ports(struct mat_stream *matsp, struct nlattr *nl,
		   struct net_mat_port **p)
{
	struct net_mat_port *ports = NULL;
	struct nlattr *i;
	int err, rem;
	unsigned cnt = 0;

	rem = nla_len(nl);
	for (cnt = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem))
		cnt++;

	ports = calloc(cnt + 1, sizeof(struct net_mat_port));
	if (!ports)
		return -ENOMEM;

	rem = nla_len(nl);
	for (cnt = 0, i = nla_data(nl); nla_ok(i, rem); i = nla_next(i, &rem), cnt++) {
		ports[cnt].vlan.def_priority = NET_MAT_PORT_T_DEF_PRI_UNSPEC;
		err = match_get_port(matsp, i, &ports[cnt]);
		if (err)
			goto out;
	}

	/* terminate the list */
	ports[cnt].port_id = NET_MAT_PORT_ID_UNSPEC;

	if (p)
		*p = ports;
	else
		free(ports);

	return 0;
out:
	free(ports);
	return err;

}

static int match_put_action_args(struct nl_msg *nlbuf,
		struct net_mat_action_arg *args)
{
	struct net_mat_action_arg *this;
	struct nlattr *arg;
	int i, err, cnt = 0;

	for (this = &args[0]; this->type; this++)
		cnt++;

	for (i = 0; i < cnt; i++) {
		arg = nla_nest_start(nlbuf, NET_MAT_ACTION_ARG);
		if (!arg)
			return -ENOMEM;

		if (args[i].name &&
		    nla_put_string(nlbuf, NET_MAT_ACTION_ARG_NAME, args[i].name)) {
			nla_nest_cancel(nlbuf, arg);
			return -EMSGSIZE;
		}

		if (nla_put_u32(nlbuf,
				NET_MAT_ACTION_ARG_TYPE,
				args[i].type)) {
			nla_nest_cancel(nlbuf, arg);
			return -EMSGSIZE;
		}

		switch (args[i].type) {
		case NET_MAT_ACTION_ARG_TYPE_U8:
			err = nla_put_u8(nlbuf,
					 NET_MAT_ACTION_ARG_VALUE,
					 args[i].v.value_u8);
			break;
		case NET_MAT_ACTION_ARG_TYPE_U16:
			err = nla_put_u16(nlbuf,
					  NET_MAT_ACTION_ARG_VALUE,
					  args[i].v.value_u16);
			break;
		case NET_MAT_ACTION_ARG_TYPE_U32:
			err = nla_put_u32(nlbuf,
					  NET_MAT_ACTION_ARG_VALUE,
					  args[i].v.value_u32);
			break;
		case NET_MAT_ACTION_ARG_TYPE_U64:
			err = nla_put_u64(nlbuf,
					  NET_MAT_ACTION_ARG_VALUE,
					  args[i].v.value_u64);
			break;
		case NET_MAT_ACTION_ARG_TYPE_IN6:
			err = nla_put(nlbuf, NET_MAT_ACTION_ARG_VALUE,
					sizeof(struct in6_addr),
					&args[i].v.value_in6.s6_addr32[0]);
			break;
		case NET_MAT_ACTION_ARG_TYPE_NULL:
		case NET_MAT_ACTION_ARG_TYPE_VARIADIC:
		default:
			err = 0;
			break;
		}

		if (err) {
			nla_nest_cancel(nlbuf, arg);
			return -EMSGSIZE;
		}

		nla_nest_end(nlbuf, arg);
	}

	return 0;
}

int match_put_action(struct nl_msg *nlbuf, struct net_mat_action *ref)
{
	struct nlattr *nest;
	int err;
	struct nlattr *action;

	action = nla_nest_start(nlbuf, NET_MAT_ACTION);
	if (!action)
		return -EMSGSIZE;

	if (ref->name && nla_put_string(nlbuf, NET_MAT_ACTION_ATTR_NAME, ref->name))
		return -EMSGSIZE;

	if (nla_put_u32(nlbuf, NET_MAT_ACTION_ATTR_UID, ref->uid))
		return -EMSGSIZE;

	if (ref->args) {
		nest = nla_nest_start(nlbuf, NET_MAT_ACTION_ATTR_SIGNATURE);
		if (!nest)
			return -EMSGSIZE;

		err = match_put_action_args(nlbuf, ref->args);
		if (err)
			return err;
		nla_nest_end(nlbuf, nest);
	}

	nla_nest_end(nlbuf, action);
	return 0;
}

int match_put_actions(struct nl_msg *nlbuf, struct net_mat_action **ref)
{
	struct nlattr *actions;
	int i, err;

	actions = nla_nest_start(nlbuf, NET_MAT_ACTIONS);
	if (!actions)
		return -EMSGSIZE;

	for (i = 0; ref[i] && ref[i]->uid; i++) {
		err = match_put_action(nlbuf, ref[i]);
		if (err)
			return err;
	}
	nla_nest_end(nlbuf, actions);
	return 0;
}

static int match_put_fields(struct nl_msg *nlbuf, struct net_mat_hdr *ref)
{
	struct nlattr *field;
	unsigned int count = ref->field_sz;
	struct net_mat_field *f;

	for (f = ref->fields; count; count--, f++) {
		field = nla_nest_start(nlbuf, NET_MAT_FIELD);
		if (!field)
			return -EMSGSIZE;

		if (nla_put_string(nlbuf, NET_MAT_FIELD_ATTR_NAME, f->name) ||
		    nla_put_u32(nlbuf, NET_MAT_FIELD_ATTR_UID, f->uid) ||
		    nla_put_u32(nlbuf, NET_MAT_FIELD_ATTR_BITWIDTH, f->bitwidth))
			return -EMSGSIZE;

		nla_nest_end(nlbuf, field);
	}

	return 0;
}

int match_put_headers(struct nl_msg *nlbuf, struct net_mat_hdr **ref)
{
	struct nlattr *nest, *hdr, *fields;
	struct net_mat_hdr *this;
	int err, i;

	nest = nla_nest_start(nlbuf, NET_MAT_HEADERS);
	if (!nest)
		return -EMSGSIZE;

	for (i = 0, this = ref[0]; this && this->uid; i++, this = ref[i]) {
		hdr = nla_nest_start(nlbuf, NET_MAT_HEADER);
		if (!hdr)
			return -EMSGSIZE;

		if (nla_put_string(nlbuf, NET_MAT_HEADER_ATTR_NAME, this->name) ||
		    nla_put_u32(nlbuf, NET_MAT_HEADER_ATTR_UID, this->uid))
			return -EMSGSIZE;

		fields = nla_nest_start(nlbuf, NET_MAT_HEADER_ATTR_FIELDS);
		if (!fields)
			return -EMSGSIZE;

		err = match_put_fields(nlbuf, this);
		if (err)
			return err;

		nla_nest_end(nlbuf, fields);
		nla_nest_end(nlbuf, hdr);
	}
	nla_nest_end(nlbuf, nest);

	return 0;
}

int match_put_field_ref(struct nl_msg *nlbuf, struct net_mat_field_ref *ref)
{
	if (nla_put_u32(nlbuf, NET_MAT_FIELD_REF_INSTANCE, ref->instance) ||
	    nla_put_u32(nlbuf, NET_MAT_FIELD_REF_HEADER, ref->header) ||
	    nla_put_u32(nlbuf, NET_MAT_FIELD_REF_FIELD, ref->field) ||
	    nla_put_u32(nlbuf, NET_MAT_FIELD_REF_MASK_TYPE, ref->mask_type) ||
	    nla_put_u32(nlbuf, NET_MAT_FIELD_REF_TYPE, ref->type))
		return -EMSGSIZE;

	if (!ref->type)
		return 0;

	switch (ref->type) {
	case NET_MAT_FIELD_REF_ATTR_TYPE_U8:
		if (nla_put_u8(nlbuf, NET_MAT_FIELD_REF_VALUE, ref->v.u8.value_u8) ||
		    nla_put_u8(nlbuf, NET_MAT_FIELD_REF_MASK, ref->v.u8.mask_u8))
			return -EMSGSIZE;
		break;
	case NET_MAT_FIELD_REF_ATTR_TYPE_U16:
		if (nla_put_u16(nlbuf, NET_MAT_FIELD_REF_VALUE, ref->v.u16.value_u16) ||
		    nla_put_u16(nlbuf, NET_MAT_FIELD_REF_MASK, ref->v.u16.mask_u16))
			return -EMSGSIZE;
		break;
	case NET_MAT_FIELD_REF_ATTR_TYPE_U32:
		if (nla_put_u32(nlbuf, NET_MAT_FIELD_REF_VALUE, ref->v.u32.value_u32) ||
		    nla_put_u32(nlbuf, NET_MAT_FIELD_REF_MASK, ref->v.u32.mask_u32))
			return -EMSGSIZE;
		break;
	case NET_MAT_FIELD_REF_ATTR_TYPE_U64:
		if (nla_put_u64(nlbuf, NET_MAT_FIELD_REF_VALUE, ref->v.u64.value_u64) ||
		    nla_put_u64(nlbuf, NET_MAT_FIELD_REF_MASK, ref->v.u64.mask_u64))
			return -EMSGSIZE;
		break;
	case NET_MAT_FIELD_REF_ATTR_TYPE_IN6:
		if (nla_put(nlbuf, NET_MAT_FIELD_REF_VALUE,
				sizeof(struct in6_addr), &ref->v.in6.value_in6.s6_addr32[0]) ||
		    nla_put(nlbuf, NET_MAT_FIELD_REF_MASK,
				sizeof(struct in6_addr), &ref->v.in6.mask_in6.s6_addr32[0]))
			return -EMSGSIZE;
		break;
	default:
		break;
	}

	return 0;
}

int match_put_matches(struct nl_msg *nlbuf, struct net_mat_field_ref *ref,
		int type)
{
	struct nlattr *matches, *field;
	int i;

	matches = nla_nest_start(nlbuf, type);
	if (!matches)
		return -EMSGSIZE;

	for (i = 0; ref[i].header; i++) {
		field = nla_nest_start(nlbuf, NET_MAT_FIELD_REF);
		if (match_put_field_ref(nlbuf, &ref[i]))
			return -EMSGSIZE;
		nla_nest_end(nlbuf, field);
	}
	nla_nest_end(nlbuf, matches);
	return 0;
}

int match_put_rule_error(struct nl_msg *nlbuf, __u32 err)
{
	return nla_put_u32(nlbuf, NET_MAT_RULES_ERROR, err);
}

int match_put_rule(struct nl_msg *nlbuf, struct net_mat_rule *ref)
{
	int err;
	struct nlattr *rule, *actions;

	rule = nla_nest_start(nlbuf, NET_MAT_RULE);
	if (!rule)
		return -EMSGSIZE;

	if (nla_put_u32(nlbuf, NET_MAT_ATTR_TABLE, ref->table_id))
		goto nla_put_failure;
	if (nla_put_u32(nlbuf, NET_MAT_ATTR_UID, ref->uid))
		goto nla_put_failure;
	if (nla_put_u32(nlbuf, NET_MAT_ATTR_PRIORITY, ref->priority))
		goto nla_put_failure;
	if (nla_put_u64(nlbuf, NET_MAT_ATTR_BYTES, ref->bytes))
		goto nla_put_failure;
	if (nla_put_u64(nlbuf, NET_MAT_ATTR_PACKETS, ref->packets))
		goto nla_put_failure;

	if (ref->matches) {
		err = match_put_matches(nlbuf, ref->matches,
				       NET_MAT_ATTR_MATCHES);
		if (err)
			goto nla_put_failure;
	}

	if (ref->actions) {
		int i;

		actions = nla_nest_start(nlbuf, NET_MAT_ATTR_ACTIONS);
		if (!actions)
			goto nla_put_failure;

		for (i = 0; ref->actions[i].uid; i++) {
			err = match_put_action(nlbuf, &ref->actions[i]);
			if (err)
				goto nla_put_failure;
		}
		nla_nest_end(nlbuf, actions);
	}

	nla_nest_end(nlbuf, rule);
	return 0;

nla_put_failure:
	nla_nest_cancel(nlbuf, rule);
	return -EMSGSIZE;
}

int match_put_rules(struct nl_msg *nlbuf, struct net_mat_rule *ref)
{
	struct nlattr *rules;
	int err, i = 0;

	rules = nla_nest_start(nlbuf, NET_MAT_RULES);
	if (!rules)
		return -EMSGSIZE;
	for (i = 0; ref[i].uid; i++) {
		err = match_put_rule(nlbuf, &ref[i]);
		if (err) {
			MAT_LOG(ERR, "Warning put rule error aborting\n");
			return err;
		}
	}

	nla_nest_end(nlbuf, rules);

	return 0;
}

static int
match_put_named_value(struct nl_msg *nlbuf, struct net_mat_named_value *ref)
{
	if (nla_put_u32(nlbuf, NET_MAT_TABLE_ATTR_VALUE_T_UID, ref->uid) ||
	    nla_put_u32(nlbuf, NET_MAT_TABLE_ATTR_VALUE_T_TYPE, ref->type) ||
	    nla_put_u8(nlbuf, NET_MAT_TABLE_ATTR_VALUE_T_WRITE, ref->write))
		return -EMSGSIZE;

	if (ref->name &&
	    nla_put_string(nlbuf, NET_MAT_TABLE_ATTR_VALUE_T_NAME, ref->name))
		return -EMSGSIZE;

	switch (ref->type) {
	case NET_MAT_NAMED_VALUE_TYPE_U8:
		if (nla_put_u8(nlbuf, NET_MAT_TABLE_ATTR_VALUE_T_VALUE, ref->value.u8))
			return -EMSGSIZE;
		break;
	case NET_MAT_NAMED_VALUE_TYPE_U16:
		if (nla_put_u16(nlbuf, NET_MAT_TABLE_ATTR_VALUE_T_VALUE, ref->value.u16))
			return -EMSGSIZE;
		break;
	case NET_MAT_NAMED_VALUE_TYPE_U32:
		if (nla_put_u32(nlbuf, NET_MAT_TABLE_ATTR_VALUE_T_VALUE, ref->value.u32))
			return -EMSGSIZE;
		break;
	case NET_MAT_NAMED_VALUE_TYPE_U64:
		if (nla_put_u64(nlbuf, NET_MAT_TABLE_ATTR_VALUE_T_VALUE, ref->value.u64))
			return -EMSGSIZE;
		break;
	case NET_MAT_NAMED_VALUE_TYPE_NULL:
	default:
		break;
	}

	return 0;
}

static int
match_put_named_values(struct nl_msg *nlbuf, struct net_mat_named_value *ref)
{
	struct nlattr *values, *v;
	int i;

	values = nla_nest_start(nlbuf, NET_MAT_TABLE_ATTR_NAMED_VALUES);
	if (!values)
		return -EMSGSIZE;

	for (i = 0; ref[i].uid; i++) {
		v = nla_nest_start(nlbuf, NET_MAT_TABLE_ATTR_NAMED_VALUE);
		if (match_put_named_value(nlbuf, &ref[i]))
			return -EMSGSIZE;
		nla_nest_end(nlbuf, v);
	}
	nla_nest_end(nlbuf, values);
	return 0;
}

int match_put_table(struct nl_msg *nlbuf, struct net_mat_tbl *ref)
{
	struct nlattr *actions;
	__u32 *aref;
	int err;

	if (ref->name && nla_put_string(nlbuf, NET_MAT_TABLE_ATTR_NAME, ref->name))
		return -EMSGSIZE;

	if (nla_put_u32(nlbuf, NET_MAT_TABLE_ATTR_UID, ref->uid) ||
	    nla_put_u32(nlbuf, NET_MAT_TABLE_ATTR_SOURCE, ref->source) ||
	    nla_put_u32(nlbuf, NET_MAT_TABLE_ATTR_APPLY, ref->apply_action) ||
	    nla_put_u32(nlbuf, NET_MAT_TABLE_ATTR_SIZE, ref->size))
		return -EMSGSIZE;

	if (ref->matches) {
		err = match_put_matches(nlbuf, ref->matches,
				       NET_MAT_TABLE_ATTR_MATCHES);
		if (err)
			return err;
	}

	if (ref->actions) {
		actions = nla_nest_start(nlbuf, NET_MAT_TABLE_ATTR_ACTIONS);
		if (!actions)
			return -EMSGSIZE;

		for (aref = ref->actions; *aref; aref++) {
			if (nla_put_u32(nlbuf, NET_MAT_ACTION_ATTR_UID, *aref))
				return -EMSGSIZE;
		}
		nla_nest_end(nlbuf, actions);
	}

	if (ref->attribs) {
		err = match_put_named_values(nlbuf, ref->attribs);
		if (err)
			return err;
	}
	return 0;
}

int match_put_tables(struct nl_msg *nlbuf, struct net_mat_tbl *ref)
{
	struct nlattr *nest, *t;
	int i, err = 0;

	nest = nla_nest_start(nlbuf, NET_MAT_TABLES);
	if (!nest)
		return -EMSGSIZE;

	for (i = 0; ref[i].uid > 0; i++) {
		t = nla_nest_start(nlbuf, NET_MAT_TABLE);
		err = match_put_table(nlbuf, &ref[i]);
		if (err)
			return err;
		nla_nest_end(nlbuf, t);
	}
	nla_nest_end(nlbuf, nest);
	return 0;
}

int match_put_table_graph(struct nl_msg *nlbuf, struct net_mat_tbl_node **ref)
{
	struct nlattr *nodes, *node, *jump, *entry;
	int i = 0, j = 0, err;

	nodes = nla_nest_start(nlbuf, NET_MAT_TABLE_GRAPH);
	if (!nodes)
		return -EMSGSIZE;

	for (i = 0; ref[i]; i++) {
		node = nla_nest_start(nlbuf, NET_MAT_TABLE_GRAPH_NODE);
		if (!node)
			return -EMSGSIZE;

		if (nla_put_u32(nlbuf, NET_MAT_TABLE_GRAPH_NODE_UID, ref[i]->uid) ||
		    nla_put_u32(nlbuf, NET_MAT_TABLE_GRAPH_NODE_FLAGS, ref[i]->flags))
			return -EMSGSIZE;

		jump = nla_nest_start(nlbuf, NET_MAT_TABLE_GRAPH_NODE_JUMP);
		if (!jump)
			return -EMSGSIZE;

		for (j = 0; ref[i]->jump[j].node || ref[i]->jump[j].field.instance; j++) {
			entry = nla_nest_start(nlbuf, NET_MAT_JUMP_ENTRY);
			if (!entry)
				return -EMSGSIZE;

			if (nla_put_u32(nlbuf, NET_MAT_FIELD_REF_NEXT_NODE, ref[i]->jump[j].node))
				return -EMSGSIZE;

			err = match_put_field_ref(nlbuf, &ref[i]->jump[j].field);
			if (err)
				return -EMSGSIZE;

#if 0
			err = match_put_field_value(nlbuf, &ref[i]->jump[j]);
			if (err)
				return err;
#endif

			nla_nest_end(nlbuf, entry);
		}

		nla_nest_end(nlbuf, jump);
		nla_nest_end(nlbuf, node);
	}

	nla_nest_end(nlbuf, nodes);
	return 0;
}

static int net_mat_put_header_node(struct nl_msg *nlbuf,
				    struct net_mat_hdr_node *node)
{
	struct nlattr *hdrs, *jumps, *entry;
	int i, err;

	if (nla_put_string(nlbuf, NET_MAT_HEADER_NODE_NAME, node->name) ||
	    nla_put_u32(nlbuf, NET_MAT_HEADER_NODE_UID, node->uid))
		return -EMSGSIZE;

	/* Insert the set of headers that get extracted at this node */
	hdrs = nla_nest_start(nlbuf, NET_MAT_HEADER_NODE_HDRS);
	if (!hdrs)
		return -EMSGSIZE;
	for (i = 0; node->hdrs[i]; i++) {
		if (nla_put_u32(nlbuf, NET_MAT_HEADER_NODE_HDRS_VALUE,
				node->hdrs[i])) {
			nla_nest_cancel(nlbuf, hdrs);
			return -EMSGSIZE;
		}
	}
	nla_nest_end(nlbuf, hdrs);

	/* Then give the jump table to find next header node in graph */
	jumps = nla_nest_start(nlbuf, NET_MAT_HEADER_NODE_JUMP);
	if (!jumps)
		return -EMSGSIZE;

	for (i = 0; node->jump[i].node; i++) {
		entry = nla_nest_start(nlbuf, NET_MAT_JUMP_ENTRY);
		if (!entry)
			return -EMSGSIZE;

		if (nla_put_u32(nlbuf, NET_MAT_FIELD_REF_NEXT_NODE, node->jump[i].node))
			return -EMSGSIZE;

		err = match_put_field_ref(nlbuf, &node->jump[i].field);
		if (err)
			return -EMSGSIZE;

#if 0
		err = match_put_field_value(nlbuf, &ref[i]->jump[j]);
		if (err)
			return err;
#endif

		nla_nest_end(nlbuf, entry);
	}
	nla_nest_end(nlbuf, jumps);

	return 0;
}

int match_put_header_graph(struct nl_msg *nlbuf,
			  struct net_mat_hdr_node **g)
{
	struct nlattr *nodes, *node;
	int err, i;

	nodes = nla_nest_start(nlbuf, NET_MAT_HEADER_GRAPH);
	if (!nodes)
		return -EMSGSIZE;

	for (i = 0; g[i]; i++) {
		node = nla_nest_start(nlbuf, NET_MAT_HEADER_GRAPH_NODE);
		if (!node)
			return -EMSGSIZE;
		err = net_mat_put_header_node(nlbuf, g[i]);
		if (err)
			return -EMSGSIZE;

		nla_nest_end(nlbuf, node);
	}

	nla_nest_end(nlbuf, nodes);
	return 0;
}

static int match_put_port_pci(struct nl_msg *nlbuf,
			     struct net_mat_port_pci *pci)
{
	int err;

	err = nla_put(nlbuf, NET_MAT_PORT_T_PCI, sizeof(struct net_mat_port_pci), pci);
	if (err)
		return -EMSGSIZE;
	return 0;
}

int match_put_port(struct nl_msg *nlbuf, struct net_mat_port *p)
{
	struct nlattr *stats, *tx_stats, *rx_stats;
	int err;

	err = match_put_port_pci(nlbuf, &p->pci);
	if (err)
		return -EMSGSIZE;

	if (nla_put_u32(nlbuf, NET_MAT_PORT_T_ID, p->port_id))
		return -EMSGSIZE;

	if (nla_put_u32(nlbuf, NET_MAT_PORT_T_PHYS_ID, p->port_phys_id))
		return -EMSGSIZE;

	if ((p->type && nla_put_u32(nlbuf, NET_MAT_PORT_T_TYPE, p->type)) ||
	    (p->state && nla_put_u32(nlbuf, NET_MAT_PORT_T_STATE, p->state)) ||
	    (p->speed && nla_put_u32(nlbuf, NET_MAT_PORT_T_SPEED, p->speed)))
		return -EMSGSIZE;

	if (p->max_frame_size &&
	    nla_put_u32(nlbuf, NET_MAT_PORT_T_MAX_FRAME_SIZE,
	                p->max_frame_size))
		return -EMSGSIZE;

	if (p->mac_addr && nla_put_u64(nlbuf, NET_MAT_PORT_T_MAC_ADDR, p->mac_addr))
		return -EMSGSIZE;

	if (p->loopback && nla_put_u32(nlbuf, NET_MAT_PORT_T_LOOPBACK, p->loopback))
		return -EMSGSIZE;

	if (p->glort && nla_put_u32(nlbuf, NET_MAT_PORT_T_GLORT, p->glort))
		return -EMSGSIZE;

	if (nla_put_u32(nlbuf, NET_MAT_PORT_T_LEARNING, p->learning))
		return -EMSGSIZE;

	if (nla_put_u32(nlbuf, NET_MAT_PORT_T_UPDATE_DSCP, p->update_dscp))
		return -EMSGSIZE;

	if (nla_put_u32(nlbuf, NET_MAT_PORT_T_UPDATE_TTL, p->update_ttl))
		return -EMSGSIZE;

	if (nla_put_u32(nlbuf, NET_MAT_PORT_T_MCAST_FLOODING, p->mcast_flooding))
		return -EMSGSIZE;

	if (nla_put_u32(nlbuf, NET_MAT_PORT_T_UPDATE_DMAC, p->update_dmac))
		return -EMSGSIZE;

	if (nla_put_u32(nlbuf, NET_MAT_PORT_T_UPDATE_SMAC, p->update_smac))
		return -EMSGSIZE;

	if (nla_put_u32(nlbuf, NET_MAT_PORT_T_UPDATE_VLAN, p->update_vlan))
		return -EMSGSIZE;

	stats = nla_nest_start(nlbuf, NET_MAT_PORT_T_STATS);
	if (!stats)
		return -EMSGSIZE;

	tx_stats = nla_nest_start(nlbuf, NET_MAT_PORT_T_STATS_TX);
	if ((p->stats.tx_bytes && nla_put_u64(nlbuf, NET_MAT_PORT_T_STATS_BYTES, p->stats.tx_bytes)) ||
	    (p->stats.tx_packets && nla_put_u64(nlbuf, NET_MAT_PORT_T_STATS_PACKETS, p->stats.tx_packets)) ||
	    (p->stats.tx_unicast_bytes && nla_put_u64(nlbuf, NET_MAT_PORT_T_STATS_UNICAST_BYTES, p->stats.tx_unicast_bytes)) ||
	    (p->stats.tx_multicast_bytes && nla_put_u64(nlbuf, NET_MAT_PORT_T_STATS_MULTICAST_BYTES, p->stats.tx_multicast_bytes)) ||
	    (p->stats.tx_broadcast_bytes && nla_put_u64(nlbuf, NET_MAT_PORT_T_STATS_BROADCAST_BYTES, p->stats.tx_broadcast_bytes)) ||
	    (p->stats.tx_unicast_packets && nla_put_u64(nlbuf, NET_MAT_PORT_T_STATS_UNICAST_PACKETS, p->stats.tx_unicast_packets)) ||
	    (p->stats.tx_multicast_packets && nla_put_u64(nlbuf, NET_MAT_PORT_T_STATS_MULTICAST_PACKETS, p->stats.tx_multicast_packets)) ||
	    (p->stats.tx_broadcast_packets && nla_put_u64(nlbuf, NET_MAT_PORT_T_STATS_BROADCAST_PACKETS, p->stats.tx_broadcast_packets)))
		return -EMSGSIZE;
	nla_nest_end(nlbuf, tx_stats);

	rx_stats = nla_nest_start(nlbuf, NET_MAT_PORT_T_STATS_RX);
	if ((p->stats.rx_bytes && nla_put_u64(nlbuf, NET_MAT_PORT_T_STATS_BYTES, p->stats.rx_bytes)) ||
	    (p->stats.rx_packets && nla_put_u64(nlbuf, NET_MAT_PORT_T_STATS_PACKETS, p->stats.rx_packets)) ||
	    (p->stats.rx_unicast_bytes && nla_put_u64(nlbuf, NET_MAT_PORT_T_STATS_UNICAST_BYTES, p->stats.rx_unicast_bytes)) ||
	    (p->stats.rx_multicast_bytes && nla_put_u64(nlbuf, NET_MAT_PORT_T_STATS_MULTICAST_BYTES, p->stats.rx_multicast_bytes)) ||
	    (p->stats.rx_broadcast_bytes && nla_put_u64(nlbuf, NET_MAT_PORT_T_STATS_BROADCAST_BYTES, p->stats.rx_broadcast_bytes)) ||
	    (p->stats.rx_unicast_packets && nla_put_u64(nlbuf, NET_MAT_PORT_T_STATS_UNICAST_PACKETS, p->stats.rx_unicast_packets)) ||
	    (p->stats.rx_multicast_packets && nla_put_u64(nlbuf, NET_MAT_PORT_T_STATS_MULTICAST_PACKETS, p->stats.rx_multicast_packets)) ||
	    (p->stats.rx_broadcast_packets && nla_put_u64(nlbuf, NET_MAT_PORT_T_STATS_BROADCAST_PACKETS, p->stats.rx_broadcast_packets)))
		return -EMSGSIZE;
	nla_nest_end(nlbuf, rx_stats);

	nla_nest_end(nlbuf, stats);

	stats = nla_nest_start(nlbuf, NET_MAT_PORT_T_VLAN);
	if (!stats)
		return -EMSGSIZE;

	if (nla_put_u32(nlbuf, NET_MAT_PORT_T_VLAN_DEF_VLAN, p->vlan.def_vlan))
		return -EMSGSIZE;

	if (nla_put_u32(nlbuf, NET_MAT_PORT_T_VLAN_DROP_TAGGED, p->vlan.drop_tagged))
		return -EMSGSIZE;

	if (nla_put_u32(nlbuf, NET_MAT_PORT_T_VLAN_DROP_UNTAGGED, p->vlan.drop_untagged))
		return -EMSGSIZE;

	if (nla_put_u32(nlbuf, NET_MAT_PORT_T_VLAN_DEF_PRIORITY, p->vlan.def_priority))
		return -EMSGSIZE;

	if (nla_put(nlbuf, NET_MAT_PORT_T_VLAN_MEMBERSHIP, 512, p->vlan.vlan_membership_bitmask))
		return -EMSGSIZE;

	nla_nest_end(nlbuf, stats);

	return err;
}

int match_put_ports(struct nl_msg *nlbuf,
		   struct net_mat_port *p)
{
	struct nlattr *ports, *port;
	int err, i;

	ports = nla_nest_start(nlbuf, NET_MAT_PORTS);
	if (!ports)
		return -EMSGSIZE;

	for (i = 0; (p[i].port_id != NET_MAT_PORT_ID_UNSPEC) ||
	            (p[i].pci.bus > 0) || (p[i].mac_addr > 0); i++) {
		port = nla_nest_start(nlbuf, NET_MAT_PORT);
		if (!port)
			return -EMSGSIZE;

		err = match_put_port(nlbuf, &p[i]);
		if (err)
			return -EMSGSIZE;


		nla_nest_end(nlbuf, port);
	}

	nla_nest_end(nlbuf, ports);
	return 0;
}

#if HAVE_NLA_NEST_CANCEL == 0
void nla_nest_cancel(struct nl_msg *msg, const struct nlattr *attr)
{
	const struct nlmsghdr *msghdr = nlmsg_hdr(msg);
	uint32_t *len;
	ssize_t del;

	/* length is the first field in nlmsghdr */
	len = (uint32_t *)(uintptr_t)msghdr;

	del = (char *)nlmsg_tail(msghdr) - (const char *)attr;
	if (del < 0)
		MAT_LOG(EMERG, "Error: %s() invalid nest\n", __func__);
	else {
		*len -= (uint32_t)del;
		memset(nlmsg_tail(msghdr), 0, (size_t)del);
	}
}
#endif /* HAVE_NLA_NEST_CANCEL == 0 */
