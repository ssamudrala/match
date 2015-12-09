/*******************************************************************************

  Netlink wrapper routines
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
#include <unistd.h>
#include <inttypes.h>

#include <netinet/in.h>
#include <arpa/inet.h>

#include <getopt.h>

#include <libnl3/netlink/netlink.h>
#include <libnl3/netlink/socket.h>
#include <libnl3/netlink/genl/genl.h>
#include <libnl3/netlink/genl/ctrl.h>

#include <linux/if_ether.h>

#include "if_match.h"
#include "matchlib.h"
#include "matchlib_nl.h"
#include "matlog.h"
#include "matstream.h"


struct match_msg {
	void *msg;
	struct nl_msg *nlbuf;
	uint32_t seq;
};

static int verbose = 0;
static struct mat_stream *matsp = NULL;

static struct nla_policy match_get_tables_policy[NET_MAT_MAX+1] = {
	[NET_MAT_IDENTIFIER_TYPE]	= { .type = NLA_U32 },
	[NET_MAT_IDENTIFIER]		= { .type = NLA_U32 },
	[NET_MAT_TABLES]		= { .type = NLA_NESTED },
	[NET_MAT_HEADERS]		= { .type = NLA_NESTED },
	[NET_MAT_ACTIONS] 		= { .type = NLA_NESTED },
	[NET_MAT_HEADER_GRAPH]		= { .type = NLA_NESTED },
	[NET_MAT_TABLE_GRAPH] 		= { .type = NLA_NESTED },
	[NET_MAT_RULES]			= { .type = NLA_NESTED },
	[NET_MAT_RULES_ERROR]		= { .type = NLA_U32 },
	[NET_MAT_PORTS]			= { .type = NLA_NESTED },
};

void match_nl_set_verbose(int new_verbose)
{
	verbose = new_verbose;
}

void match_nl_set_streamer(struct mat_stream *streamer)
{
	matsp = streamer;
}

static void match_nl_free_msg(struct match_msg *msg)
{
	if(msg) {
		if (msg->nlbuf)
			nlmsg_free(msg->nlbuf);
		else
			free(msg->msg);
		free(msg);
	}
}

static struct match_msg *match_nl_wrap_msg(struct nlmsghdr *buf)
{
	struct match_msg *msg;

	msg = (struct match_msg *) malloc(sizeof(struct match_msg));
	if (msg) {
		msg->msg = buf;
		msg->nlbuf = NULL;
	}

	return msg;
}

static struct match_msg *match_nl_wrap_nl_msg(struct nl_msg *nlmsg)
{
	struct match_msg *msg;

	msg = malloc(sizeof(*msg));
	if (msg) {
		msg->nlbuf = nlmsg;
		msg->msg = nlmsg_hdr(nlmsg);
	}

	return msg;
}

static struct match_msg *match_nl_alloc_msg(uint8_t type, uint32_t pid,
					    int flags, int size, int family)
{
	struct match_msg *msg;
	static uint32_t seq = 1;

	msg = (struct match_msg *) malloc(sizeof(struct match_msg));
	if (!msg)
		return NULL;

	msg->nlbuf = nlmsg_alloc();

	msg->msg = genlmsg_put(msg->nlbuf, 0, seq, family, (int)size, flags,
			       type, NET_MAT_GENL_VERSION);

	msg->seq = seq++;

	if (pid) {
		struct nl_msg *nl_msg = msg->nlbuf;
		struct sockaddr_nl nladdr = {
			.nl_family = AF_NETLINK,
			.nl_pid = pid,
			.nl_groups = 0,
		};

		nlmsg_set_dst(nl_msg, &nladdr);
	}
	return msg;
}


struct nl_sock *match_nl_get_socket(void)
{
	struct nl_sock *nsd = nl_socket_alloc();

	nl_connect(nsd, NETLINK_GENERIC);

	return nsd;
}

uint32_t match_pid_lookup(void)
{
	FILE *fd = fopen(MATCHLIB_PID_FILE, "r");
	uint32_t pid;
	int err;

	if (!fd) {
		MAT_LOG(ERR, "no hardware support, daemon is not listening\n");
		return 0;
	}

	err = fscanf(fd, "%" SCNu32 "", &pid);
	if (err < 0) {
		MAT_LOG(ERR, "Error: pid not found\n");
		fclose(fd);
		return 0;
	}

	fclose(fd);
	return pid;
}


static void match_nl_handle_error(struct nlmsgerr *errmsg)
{
	MAT_LOG(ERR, "Error processing request: %s\n",
		strerror(errmsg->error));
}


typedef int (* match_nl_msg_composer_fn_t)(struct match_msg *msg, void *composer_arg);
typedef int (* match_nl_msg_handler_fn_t)(struct match_msg *msg, void *handler_arg);

struct match_nl_recvmsg_msg_cb_adapter_ctxt {
	match_nl_msg_handler_fn_t handler;
	void *handler_arg;
	int handler_err;
};

static int match_nl_recvmsg_msg_cb_adapter(struct nl_msg *nlmsg, void *arg)
{
	struct match_nl_recvmsg_msg_cb_adapter_ctxt *ctxt = arg;
	int err;
	struct match_msg *msg;
	int type;
	struct genlmsghdr *glm;


	if (!arg) {
		return NL_STOP;
	}
	ctxt->handler_err = 0;

	if (!nlmsg) {
		return NL_STOP;
	}

	if (!ctxt->handler) {
		return NL_OK;
	}

	msg = match_nl_wrap_msg(nlmsg_hdr(nlmsg));
	if (!msg) {
		MAT_LOG(ERR, "Error: Could not allocate match msg\n");
		return NL_SKIP;
	}
	type = ((struct nlmsghdr *)msg->msg)->nlmsg_type;

	/*
	 * Note the NLMSG_ERROR is overloaded
	 * Its also used to deliver ACKs
	 */
	if (type == NLMSG_ERROR) {
		struct nlmsgerr *errm = nlmsg_data(msg->msg);

		if (errm->error) {
			match_nl_handle_error(errm);
			match_nl_free_msg(msg);
			return NL_OK;
		}

		match_nl_free_msg(msg);
		return NL_OK;
	}

	glm = nlmsg_data(msg->msg);
	type = glm->cmd;

	if (type < 0 || type > NET_MAT_CMD_MAX) {
		MAT_LOG(ERR, "Received message of unknown type %d\n", type);
		match_nl_free_msg(msg);
		return NL_OK;
	}

	msg = match_nl_wrap_nl_msg(nlmsg);
	if (!msg) {
		MAT_LOG(ERR, "Error: Could not allocate match msg\n");
		return NL_SKIP;
	}
	/*
	 * We need to protect the nl_msg passed from libnl from double free
	 * as handler calls match_nl_free_msg when it is done with the msg and
	 * match_nl_free_msg calls nlmsg_free internally.
	 * Libnl, however, expects to control the lifetime of nl_msg.
	 * nlmsg_get increases the reference count.
	 */
	nlmsg_get(nlmsg);

	err = ctxt->handler(msg, ctxt->handler_arg);
	ctxt->handler_err = err;

	return NL_OK;
}


static int match_nl_recvmsg_err_cb(struct sockaddr_nl *nla __unused,
				   struct nlmsgerr *errm, void *arg)
{
	struct match_nl_recvmsg_msg_cb_adapter_ctxt *ctxt = arg;


	if (!arg) {
		return NL_STOP;
	}
	ctxt->handler_err = 0;

	if (!errm)
		return -EINVAL;

	if (errm->error) {
		match_nl_handle_error(errm);
		ctxt->handler_err = errm->error;

		return NL_STOP;
	}

	return NL_OK;
}


static int
match_nl_send_and_recv(struct nl_sock *nsd, uint8_t cmd, uint32_t pid,
		       unsigned int ifindex, int family,
		       match_nl_msg_composer_fn_t composer, void *composer_arg,
		       match_nl_msg_handler_fn_t handler, void *handler_arg
	)
{
	struct match_msg *msg;
	sigset_t bs;
	int err;
	struct match_nl_recvmsg_msg_cb_adapter_ctxt adapter_ctxt;
	int nlerr;


	msg = match_nl_alloc_msg(cmd, pid, NLM_F_REQUEST|NLM_F_ACK, 0, family);
	if (!msg) {
		MAT_LOG(ERR, "Error: Allocation failure\n");
		return -ENOMEM;
	}

	if (nla_put_u32(msg->nlbuf,
			NET_MAT_IDENTIFIER_TYPE,
			NET_MAT_IDENTIFIER_IFINDEX)
	    || nla_put_u32(msg->nlbuf, NET_MAT_IDENTIFIER, ifindex)) {
		MAT_LOG(ERR, "Error: Identifier put failed\n");
		match_nl_free_msg(msg);
		return -EMSGSIZE;
	}

	if (composer) {
		err = composer(msg, composer_arg);
		if (err < 0) {
			MAT_LOG(ERR, "Error: Composing %d msg for ifindex %u failed\n",
				cmd, ifindex);
			match_nl_free_msg(msg);
			return err;
		}
	}

	nl_send_auto(nsd, msg->nlbuf);
	match_nl_free_msg(msg);

	/* message sent handle recv */
	sigemptyset(&bs);
	sigaddset(&bs, SIGINT);
	sigprocmask(SIG_UNBLOCK, &bs, NULL);

	adapter_ctxt.handler = handler;
	adapter_ctxt.handler_arg = handler_arg;
	adapter_ctxt.handler_err = 0;

	nlerr = nl_socket_modify_cb(nsd, NL_CB_VALID, NL_CB_CUSTOM,
				    match_nl_recvmsg_msg_cb_adapter, &adapter_ctxt);
	if (NLE_SUCCESS != nlerr) {
		MAT_LOG(ERR, "Error: nl_socket_modify_cb() failed(%d)\n", -nlerr);
	}

	nlerr = nl_socket_modify_err_cb(nsd, NL_CB_CUSTOM,
					match_nl_recvmsg_err_cb, &adapter_ctxt);
	if (NLE_SUCCESS != nlerr) {
		MAT_LOG(ERR, "Error: nl_socket_modify_err_cb() failed(%d)\n", -nlerr);
	}

	nl_socket_disable_seq_check(nsd);
	nlerr = nl_recvmsgs_default(nsd);
	if (NLE_SUCCESS != nlerr) {
		MAT_LOG(ERR, "Error: nl_recvmsgs_default() failed(%d)\n", -nlerr);
	}

	sigprocmask(SIG_BLOCK, &bs, NULL);

	return adapter_ctxt.handler_err;
}


static int match_nl_table_cmd_to_type(struct mat_stream *matsp __unused,
				      int valid, struct nlattr *tb[])
{
	unsigned int type;

	if (!tb[NET_MAT_IDENTIFIER_TYPE]) {
		MAT_LOG(ERR,
			"Warning: received rule msg without identifier type!\n");
		return -EINVAL;
	}
	if (!tb[NET_MAT_IDENTIFIER]) {
		MAT_LOG(ERR,
			"Warning: received rule msg without identifier!\n");
		return -EINVAL;
	}

	if (valid > 0 && !tb[valid]) {
		MAT_LOG(ERR, "Warning: received cmd without valid attribute expected %i\n", valid);
		return -ENOMSG;
	}

	if (nla_len(tb[NET_MAT_IDENTIFIER_TYPE]) < (int)sizeof(type)) {
		MAT_LOG(ERR, "Warning: invalid identifier type len\n");
		return -EINVAL;
	}

	type = nla_get_u32(tb[NET_MAT_IDENTIFIER_TYPE]);

	switch (type) {
	case NET_MAT_IDENTIFIER_IFINDEX:
		break;
	default:
		MAT_LOG(ERR, "Warning: unknown interface identifier type %i\n", type);
		break;
	}

	return 0;
}


struct get_headers_handler_args {
	struct net_mat_hdr *hdrs;
};

static int handle_get_headers(struct match_msg *msg, void *handler_arg)
{
	struct get_headers_handler_args *args = handler_arg;
	struct nlmsghdr *nlh;
	struct nlattr *tb[NET_MAT_MAX+1];
	struct net_mat_hdr *hdrs = NULL;
	int err;

	if (!handler_arg)
		return -EINVAL;

	args->hdrs = NULL;

	if (!msg)
		return -EINVAL;

	nlh = msg->msg;

	err = genlmsg_parse(nlh, 0, tb,
			    NET_MAT_MAX, match_get_tables_policy);
	if (err < 0) {
		MAT_LOG(ERR, "Warning: unable to parse get headers msg\n");
		goto out;
	}

	if (match_nl_table_cmd_to_type(matsp,
				       NET_MAT_HEADERS, tb))
		goto out;

	if (tb[NET_MAT_HEADERS])
		match_get_headers(matsp,
				  tb[NET_MAT_HEADERS], &hdrs);

	args->hdrs = hdrs;
out:
	match_nl_free_msg(msg);
	return 0;
}

struct net_mat_hdr *match_nl_get_headers(struct nl_sock *nsd, uint32_t pid,
					 unsigned int ifindex, int family)
{
	uint8_t cmd = NET_MAT_TABLE_CMD_GET_HEADERS;
	struct get_headers_handler_args args = {.hdrs = NULL};
	int err;


	err = match_nl_send_and_recv(nsd, cmd, pid, ifindex, family,
				     /*composer*/ NULL, NULL,
				     handle_get_headers, &args);
	/* TODO handle error propagated from handler */
	(void)err;

	return args.hdrs;
}


struct get_actions_handler_args {
	struct net_mat_action *actions;
};

static int handle_get_actions(struct match_msg *msg, void *handler_arg)
{
	struct get_actions_handler_args *args = handler_arg;
	struct nlmsghdr *nlh;
	struct nlattr *tb[NET_MAT_MAX+1];
	struct net_mat_action *actions = NULL;
	int err;


	if (!handler_arg)
		return -EINVAL;

	args->actions = NULL;

	if (!msg)
		return -EINVAL;

	nlh = msg->msg;
	err = genlmsg_parse(nlh, 0, tb,
			    NET_MAT_MAX, match_get_tables_policy);
	if (err < 0) {
		MAT_LOG(ERR, "Warning: unable to parse get actions msg\n");
		goto out;
	}

	if (match_nl_table_cmd_to_type(matsp,
				       NET_MAT_ACTIONS, tb))
		goto out;

	if (tb[NET_MAT_ACTIONS])
		match_get_actions(matsp,
				  tb[NET_MAT_ACTIONS], &actions);
	args->actions = actions;
out:
	match_nl_free_msg(msg);
	return 0;
}

struct net_mat_action *match_nl_get_actions(struct nl_sock *nsd, uint32_t pid,
					    unsigned int ifindex, int family)
{
	uint8_t cmd = NET_MAT_TABLE_CMD_GET_ACTIONS;
	struct get_actions_handler_args args = {.actions = NULL};
	int err;


	err = match_nl_send_and_recv(nsd, cmd, pid, ifindex, family,
				     /*composer*/ NULL, NULL,
				     handle_get_actions, &args);
	/* TODO handle error propagated from handler */
	(void)err;

	return args.actions;
}


struct get_tables_handler_args {
	struct net_mat_tbl *tables;
};

static int handle_get_tables(struct match_msg *msg, void *handler_arg)
{
	struct get_tables_handler_args *args = handler_arg;
	struct nlmsghdr *nlh;
	struct nlattr *tb[NET_MAT_MAX+1];
	struct net_mat_tbl *tables = NULL;
	int err;

	if (!handler_arg)
		return -EINVAL;

	args->tables = NULL;

	if (!msg)
		return -EINVAL;

	nlh = msg->msg;

	err = genlmsg_parse(nlh, 0, tb,
			    NET_MAT_MAX, match_get_tables_policy);
	if (err < 0) {
		MAT_LOG(ERR, "Warning: unable to parse get tables msg\n");
		goto out;
	}

	if (match_nl_table_cmd_to_type(matsp,
				       NET_MAT_TABLES, tb))
		goto out;

	if (tb[NET_MAT_TABLES])
		match_get_tables(matsp,
				 tb[NET_MAT_TABLES], &tables);
	args->tables = tables;
out:
	match_nl_free_msg(msg);
	return 0;
}

struct net_mat_tbl *match_nl_get_tables(struct nl_sock *nsd, uint32_t pid,
					unsigned int ifindex, int family)
{
	uint8_t cmd = NET_MAT_TABLE_CMD_GET_TABLES;
	struct get_tables_handler_args args = {.tables = NULL};
	int err;


	err = match_nl_send_and_recv(nsd, cmd, pid, ifindex, family,
				     /*composer*/ NULL, NULL,
				     handle_get_tables, &args);
	/* TODO handle error propagated from handler */
	(void)err;

	return args.tables;
}


struct get_hdr_graph_handler_args {
	struct net_mat_hdr_node *hdr_nodes;
};

static int handle_get_hdr_graph(struct match_msg *msg, void *handler_arg)
{
	struct get_hdr_graph_handler_args *args = handler_arg;
	struct nlmsghdr *nlh;
	struct nlattr *tb[NET_MAT_MAX+1];
	struct net_mat_hdr_node *hdr_nodes = NULL;
	int err;

	if (!handler_arg)
		return -EINVAL;

	args->hdr_nodes = NULL;

	if (!msg)
		return -EINVAL;

	nlh = msg->msg;

	err = genlmsg_parse(nlh, 0, tb,
			    NET_MAT_MAX, match_get_tables_policy);
	if (err < 0) {
		MAT_LOG(ERR, "Warning: unable to parse get header graph msg\n");
		goto out;
	}

	if (match_nl_table_cmd_to_type(matsp,
				       NET_MAT_HEADER_GRAPH, tb))
		goto out;

	if (tb[NET_MAT_HEADER_GRAPH])
		match_get_hdrs_graph(matsp, verbose,
				     tb[NET_MAT_HEADER_GRAPH],
				     &hdr_nodes);
	args->hdr_nodes = hdr_nodes;
out:
	match_nl_free_msg(msg);
	return 0;
}

struct net_mat_hdr_node *match_nl_get_hdr_graph(struct nl_sock *nsd,
						uint32_t pid,
						unsigned int ifindex,
						int family)
{
	uint8_t cmd = NET_MAT_TABLE_CMD_GET_HDR_GRAPH;
	struct get_hdr_graph_handler_args args = {.hdr_nodes = NULL};
	int err;


	err = match_nl_send_and_recv(nsd, cmd, pid, ifindex, family,
				     /*composer*/ NULL, NULL,
				     handle_get_hdr_graph, &args);
	/* TODO handle error propagated from handler */
	(void)err;

	return args.hdr_nodes;
}


struct get_tbl_graph_handler_args {
	struct net_mat_tbl_node *tbl_nodes;
};

static int handle_get_tbl_graph(struct match_msg *msg, void *handler_arg)
{
	struct get_tbl_graph_handler_args *args = handler_arg;
	struct nlmsghdr *nlh;
	struct nlattr *tb[NET_MAT_MAX+1];
	struct net_mat_tbl_node *tbl_nodes = NULL;
	int err;

	if (!handler_arg)
		return -EINVAL;

	args->tbl_nodes = NULL;

	if (!msg)
		return -EINVAL;

	nlh = msg->msg;

	err = genlmsg_parse(nlh, 0, tb,
			    NET_MAT_MAX, match_get_tables_policy);
	if (err < 0) {
		MAT_LOG(ERR, "Warning: unable to parse get table graph msg\n");
		goto out;
	}

	if (match_nl_table_cmd_to_type(matsp,
				       NET_MAT_TABLE_GRAPH, tb))
		goto out;

	if (tb[NET_MAT_TABLE_GRAPH])
		match_get_tbl_graph(matsp, verbose,
				    tb[NET_MAT_TABLE_GRAPH], &tbl_nodes);
	args->tbl_nodes = tbl_nodes;
out:
	match_nl_free_msg(msg);
	return 0;
}

struct net_mat_tbl_node *match_nl_get_tbl_graph(struct nl_sock *nsd,
						uint32_t pid,
						unsigned int ifindex,
						int family)
{
	uint8_t cmd = NET_MAT_TABLE_CMD_GET_TABLE_GRAPH;
	struct get_tbl_graph_handler_args args = {.tbl_nodes = NULL};
	int err;


	err = match_nl_send_and_recv(nsd, cmd, pid, ifindex, family,
				     /*composer*/ NULL, NULL,
				     handle_get_tbl_graph, &args);
	/* TODO handle error propagated from handler */
	(void)err;

	return args.tbl_nodes;
}


static int compose_set_del_rules(struct match_msg *msg, void *arg)
{
	struct net_mat_rule *rule = arg;
	int err = 0;
	struct nlattr *rules;


	err = match_put_rule_error(msg->nlbuf, NET_MAT_RULES_ERROR_ABORT);
	if (err) {
		return err;
	}

	rules = nla_nest_start(msg->nlbuf, NET_MAT_RULES);
	if (!rules) {
		return -EMSGSIZE;
	}
	match_put_rule(msg->nlbuf, rule);
	nla_nest_end(msg->nlbuf, rules);

	return 0;
}

static int handle_set_del_rules(struct match_msg *msg, void *handler_arg __unused)
{
	struct nlmsghdr *nlh;
	struct nlattr *tb[NET_MAT_MAX+1];
	int err = 0;


	if (!msg)
		return -EINVAL;

	nlh = msg->msg;
	err = genlmsg_parse(nlh, 0, tb, NET_MAT_MAX, match_get_tables_policy);
	if (err < 0) {
		MAT_LOG(ERR, "Warning: unable to parse set rules msg\n");
		match_nl_free_msg(msg);
		return err;
	}

	err = match_nl_table_cmd_to_type(matsp, 0, tb);
	if (err) {
		match_nl_free_msg(msg);
		return err;
	}

	if (tb[NET_MAT_RULES]) {
		MAT_LOG(ERR, "Failed to set:\n");
		match_get_rules(matsp, tb[NET_MAT_RULES], NULL);
		match_nl_free_msg(msg);
		return -EINVAL;
	}
	match_nl_free_msg(msg);
	return 0;
}

int match_nl_set_del_rules(struct nl_sock *nsd, uint32_t pid,
			   unsigned int ifindex, int family,
			   struct net_mat_rule *rule, uint8_t cmd)
{
	int err = 0;

	pp_rule(matsp, rule);

	err = match_nl_send_and_recv(nsd, cmd, pid, ifindex, family,
				     compose_set_del_rules, rule,
				     handle_set_del_rules, NULL);
	return err;
}


struct get_rules_args {
	uint32_t tableid;
	uint32_t min;
	uint32_t max;
};

static int compose_get_rules(struct match_msg *msg, void *composer_arg)
{
	struct get_rules_args *args = composer_arg;
	uint32_t tableid = args->tableid;
	uint32_t min = args->min;
	uint32_t max = args->max;
	struct nlattr *rules;
	int err = 0;


	err = match_put_rule_error(msg->nlbuf, NET_MAT_RULES_ERROR_ABORT);
	if (err)
		return err;

	rules = nla_nest_start(msg->nlbuf, NET_MAT_RULES);
	if (!rules) {
		MAT_LOG(ERR, "Error: get_rules attributes failed\n");
		return -EMSGSIZE;
	}
	err = nla_put_u32(msg->nlbuf, NET_MAT_TABLE_RULES_TABLE, tableid);
	if (err) {
		MAT_LOG(ERR, "Error: invalid table\n");
		return -EMSGSIZE;
	}
	if (min > 0) {
		err = nla_put_u32(msg->nlbuf, NET_MAT_TABLE_RULES_MINPRIO,
                                min);
		if (err) {
			MAT_LOG(ERR, "Error: invalid min parameter\n");
			return -EMSGSIZE;
		}
	}
	if (max > 0) {
		err = nla_put_u32(msg->nlbuf, NET_MAT_TABLE_RULES_MAXPRIO,
                                max);
		if (err) {
			MAT_LOG(ERR, "Error: invalid min parameter\n");
			return -EMSGSIZE;
		}
	}
	nla_nest_end(msg->nlbuf, rules);

	return 0;
}

struct get_rules_handler_args {
	struct net_mat_rule *rules;
};

static int handle_get_rules(struct match_msg *msg, void *handler_arg)
{
	struct get_rules_handler_args *args = handler_arg;
	struct nlmsghdr *nlh;
	struct nlattr *tb[NET_MAT_MAX+1];
	struct net_mat_rule *rule = NULL;
	int err = 0;

	if (!handler_arg)
		return -EINVAL;

	args->rules = NULL;

	if (!msg)
		return -EINVAL;

	nlh = msg->msg;
	err = genlmsg_parse(nlh, 0, tb, NET_MAT_MAX, match_get_tables_policy);
	if (err < 0) {
		MAT_LOG(ERR, "Warning: unable to parse get rules msg\n");
		goto out;
	}

	if (match_nl_table_cmd_to_type(matsp,
				       NET_MAT_RULES, tb))
		goto out;

	if (tb[NET_MAT_RULES]) {
		err = match_get_rules(matsp, tb[NET_MAT_RULES], &rule);
		if (err)
			goto out;
	}
	args->rules = rule;
out:
	match_nl_free_msg(msg);
	return 0;
}

struct net_mat_rule *match_nl_get_rules(struct nl_sock *nsd, uint32_t pid,
					unsigned int ifindex, int family,
					uint32_t tableid, uint32_t min, uint32_t max)
{
	int err = 0;
	uint8_t cmd = NET_MAT_TABLE_CMD_GET_RULES;
	struct get_rules_args args;
	struct get_rules_handler_args handler_args = {.rules = NULL};

	args.tableid = tableid;
	args.min = min;
	args.max = max;

	err = match_nl_send_and_recv(nsd, cmd, pid, ifindex, family,
				     compose_get_rules, &args,
				     handle_get_rules, &handler_args);
	/* TODO handle error propagated from handler */
	(void)err;

	return handler_args.rules;
}


static int compose_set_port(struct match_msg *msg, void *arg)
{
	struct net_mat_port *port = arg;
	struct nlattr *nest, *nest1;


	nest = nla_nest_start(msg->nlbuf, NET_MAT_PORTS);
	if (!nest) {
		return -EMSGSIZE;
	}
	nest1 = nla_nest_start(msg->nlbuf, NET_MAT_PORTS);
	match_put_port(msg->nlbuf, port);
	nla_nest_end(msg->nlbuf, nest1);
	nla_nest_end(msg->nlbuf, nest);
	return 0;
}

static int handle_set_port(struct match_msg *msg, void *handler_arg __unused)
{
	struct nlattr *tb[NET_MAT_MAX+1];
	struct nlmsghdr *nlh;
	int err = 0;


	if (!msg)
		return -EINVAL;

	nlh = msg->msg;
	err = genlmsg_parse(nlh, 0, tb, NET_MAT_MAX, match_get_tables_policy);
	if (err < 0) {
		MAT_LOG(ERR, "Warning: unable to parse set port msg\n");
		match_nl_free_msg(msg);
		return err;
	}

	err = match_nl_table_cmd_to_type(matsp, 0, tb);
	if (err) {
		match_nl_free_msg(msg);
		return err;
	}

	if (tb[NET_MAT_PORTS]) {
		MAT_LOG(ERR, "Failed to set:\n");
		match_get_ports(matsp, tb[NET_MAT_PORTS], NULL);
		match_nl_free_msg(msg);
		return -EINVAL;
	}
	match_nl_free_msg(msg);
	return 0;
}

int match_nl_set_port(struct nl_sock *nsd, uint32_t pid,
		      unsigned int ifindex, int family,
		      struct net_mat_port *port)
{
	uint8_t cmd = NET_MAT_PORT_CMD_SET_PORTS;
	int err = 0;


	err = match_nl_send_and_recv(nsd, cmd, pid, ifindex, family,
				     compose_set_port, port,
				     handle_set_port, NULL);
	return err;
}


struct get_ports_args {
	uint32_t min;
	uint32_t max;
};

static int compose_get_ports(struct match_msg *msg, void *composer_arg)
{
	struct get_ports_args *args = composer_arg;
	uint32_t min = args->min;
	uint32_t max = args->max;
	struct nlattr *ports;
	int err = 0;


	err = match_put_rule_error(msg->nlbuf, NET_MAT_RULES_ERROR_ABORT);
	if (err)
		return err;

	ports = nla_nest_start(msg->nlbuf, NET_MAT_PORTS);
	if (!ports) {
		MAT_LOG(ERR, "Error: get_port attributes failed\n");
		return -EMSGSIZE;
	}
	if (min != NET_MAT_PORT_ID_UNSPEC) {
		err = nla_put_u32(msg->nlbuf, NET_MAT_PORT_MIN_INDEX,
                                min);
		if (err)
			return -EMSGSIZE;
	}
	if (max != NET_MAT_PORT_ID_UNSPEC) {
		err = nla_put_u32(msg->nlbuf, NET_MAT_PORT_MAX_INDEX,
                                max);
		if (err)
			return -EMSGSIZE;
	}
	nla_nest_end(msg->nlbuf, ports);

	return 0;
}

struct get_ports_handler_args {
	struct net_mat_port *ports;
};

static int handle_get_ports(struct match_msg *msg, void *handler_arg)
{
	struct get_ports_handler_args *args = handler_arg;
	struct nlmsghdr *nlh;
	struct nlattr *tb[NET_MAT_MAX+1];
	struct net_mat_port *port = NULL;
	int err = 0;

	if (!handler_arg)
		return -EINVAL;

	args->ports = NULL;

	if (!msg)
		return -EINVAL;

	nlh = msg->msg;
	err = genlmsg_parse(nlh, 0, tb, NET_MAT_MAX, match_get_tables_policy);
	if (err < 0) {
		MAT_LOG(ERR, "Warning: unable to parse get rules msg\n");
		goto out;
	}

	if (match_nl_table_cmd_to_type(matsp,
				       NET_MAT_PORTS, tb))
		goto out;

	if (tb[NET_MAT_PORTS]) {
		err = match_get_ports(matsp, tb[NET_MAT_PORTS], &port);
		if (err)
			goto out;
	}
	args->ports = port;
out:
	match_nl_free_msg(msg);
	return 0;
}

struct net_mat_port *match_nl_get_ports(struct nl_sock *nsd, uint32_t pid,
					unsigned int ifindex, int family,
					uint32_t min, uint32_t max)
{
	int err = 0;
	uint8_t cmd = NET_MAT_PORT_CMD_GET_PORTS;
	struct get_ports_args args;
	struct get_ports_handler_args handler_args = {.ports = NULL};

	args.min = min;
	args.max = max;

	err = match_nl_send_and_recv(nsd, cmd, pid, ifindex, family,
				     compose_get_ports, &args,
				     handle_get_ports, &handler_args);
	/* TODO handle error propagated from handler */
	(void)err;

	return handler_args.ports;
}


static int compose_create_update_destroy_table(struct match_msg *msg, void *arg)
{
	struct net_mat_tbl *table = arg;
	struct nlattr *nest, *nest1;


	nest = nla_nest_start(msg->nlbuf, NET_MAT_TABLES);
	if (!nest) {
		return -EMSGSIZE;
	}
	nest1 = nla_nest_start(msg->nlbuf, NET_MAT_TABLE);
	match_put_table(msg->nlbuf, table);
	nla_nest_end(msg->nlbuf, nest1);
	nla_nest_end(msg->nlbuf, nest);
	return 0;
}

static int handle_create_update_destroy_table(struct match_msg *msg, void *handler_arg __unused)
{
	struct nlmsghdr *nlh;
	struct nlattr *tb[NET_MAT_MAX+1];
	int err = 0;


	if (!msg)
		return -EINVAL;

	nlh = msg->msg;
	err = genlmsg_parse(nlh, 0, tb, NET_MAT_MAX, match_get_tables_policy);
	if (err < 0) {
		MAT_LOG(ERR, "Warning: unable to parse create table msg\n");
		match_nl_free_msg(msg);
		return err;
	}
	match_nl_free_msg(msg);
	return 0;
}

int match_nl_create_update_destroy_table(struct nl_sock *nsd, uint32_t pid,
					 unsigned int ifindex, int family,
					 struct net_mat_tbl *table, uint8_t cmd)
{
	int err = 0;


	err = match_nl_send_and_recv(nsd, cmd, pid, ifindex, family,
				     compose_create_update_destroy_table, table,
				     handle_create_update_destroy_table, NULL);
	return err;
}


uint32_t match_nl_find_header(struct net_mat_hdr *hdr,
			     struct net_mat_hdr *search)
{
	uint32_t i, j;

	for (i = 0; search[i].uid; i++) {
		if (hdr->field_sz != search[i].field_sz)
			continue;

		for (j = 0; j < hdr->field_sz; j++) {
			if (hdr->fields[j].bitwidth != search[i].fields[j].bitwidth)
				continue;
		}

		if (j == hdr->field_sz)
			return search[i].uid;
	}
	return 0;
}

uint32_t match_nl_find_action_by_name(char *name, struct net_mat_action *acts)
{
	uint32_t i;

	for (i = 0; acts[i].uid; i++) {
		if (strcmp(name, acts[i].name) == 0)
			return acts[i].uid;
	}

	return 0;
}

uint32_t match_nl_find_instance(struct net_mat_hdr_node *graph,
			       uint32_t uid, uint32_t next)
{
	uint32_t i, j;

	for (i = 0; graph[i].uid; i++) {
		if (graph[i].uid < next)
			continue;

		for (j = 0; graph[i].hdrs[j]; j++) {
			if (graph[i].hdrs[j] != uid)
				continue;

			return graph[i].uid;
		}
	}

	return 0;
}

uint32_t match_nl_find_table_with_action(struct net_mat_tbl *tbls,
					uint32_t action, uint32_t next)
{
	uint32_t i, j;

	for (i = 0; tbls[i].uid; i++) {
		if (i < next)
			continue;

		for (j = 0; tbls[i].actions[j]; j++) {
			if (tbls[i].actions[j] == action)
				return tbls[i].uid;
		}
	}

	return 0;
}




static int compose_get_port(struct match_msg *msg, void *arg)
{
	struct net_mat_port *ports = arg;
	int err;

	err = match_put_ports(msg->nlbuf, ports);
	if (err) {
		return -EMSGSIZE;
	}

	return 0;
}


struct get_port_handler_args {
	uint8_t cmd;
	uint32_t port_id;
	uint32_t glort;
};

static int handle_get_port(struct match_msg *msg, void *handler_arg)
{
	struct get_port_handler_args *args = handler_arg;
	struct nlmsghdr *nlh;
	struct nlattr *tb[NET_MAT_MAX+1];
	struct net_mat_port *port_query = NULL;
	uint8_t cmd;
	uint32_t *port_id;
	uint32_t *glort;
	int err;


	if (!handler_arg)
		return -EINVAL;
	cmd = args->cmd;
	port_id = &args->port_id;
	glort = &args->glort;

	if (!msg)
		return -EINVAL;

	nlh = msg->msg;
	err = genlmsg_parse(nlh, 0, tb,
			    NET_MAT_MAX, match_get_tables_policy);
	if (err < 0) {
		MAT_LOG(ERR, "Warning: unable to parse pci to lport msg\n");
		match_nl_free_msg(msg);
		return -EINVAL;
	}

	if (match_nl_table_cmd_to_type(matsp, NET_MAT_PORTS, tb)) {
		match_nl_free_msg(msg);
		return -EINVAL;
	}

	if (tb[NET_MAT_PORTS]) {
		err = match_get_ports(matsp,
				      tb[NET_MAT_PORTS], &port_query);
		if (err) {
			match_nl_free_msg(msg);
			return -EINVAL;
		}
	}

	if (!port_query) {
		match_nl_free_msg(msg);
		return -EINVAL;
	}

	if (cmd == NET_MAT_PORT_CMD_GET_LPORT)
		*port_id = port_query[0].port_id;
	else if (cmd == NET_MAT_PORT_CMD_GET_PHYS_PORT)
		*port_id = port_query[0].port_phys_id;

	if (glort)
		*glort = port_query[0].glort;

	match_nl_free_msg(msg);
	free(port_query);
	return 0;
}

static int match_nl_get_port(struct nl_sock *nsd, uint32_t pid,
			     unsigned int ifindex, int family, uint8_t cmd,
			     struct net_mat_port *ports,
			     uint32_t *port_id, uint32_t *glort)
{
	int err = 0;
	struct get_port_handler_args handler_args = {.cmd = cmd};


	err = match_nl_send_and_recv(nsd, cmd, pid, ifindex, family,
				     compose_get_port, ports,
				     handle_get_port, &handler_args);
	if (!err) {
		if ((cmd == NET_MAT_PORT_CMD_GET_LPORT)
		    || (cmd == NET_MAT_PORT_CMD_GET_PHYS_PORT))
			*port_id = handler_args.port_id;

		if (glort)
			*glort = handler_args.glort;
	}

	return err;
}

int match_nl_pci_lport(struct nl_sock *nsd, uint32_t pid,
		      unsigned int ifindex, int family,
		      uint8_t bus, uint8_t device, uint8_t function,
		      uint32_t *lport, uint32_t *glort)
{
	struct net_mat_port port = {.pci = {0},
	                            .port_id = NET_MAT_PORT_ID_UNSPEC,
				    .mac_addr = 0, .port_phys_id = 0};
	struct net_mat_port ports[2] = {{0}, {0}};
	int err;

	ports[0] = ports[1] = port;

	ports[0].pci.bus = bus;
	ports[0].pci.device = device;
	ports[0].pci.function = function;

	err = match_nl_get_port(nsd, pid, ifindex, family,
			NET_MAT_PORT_CMD_GET_LPORT, ports, lport, glort);

	return err;
}

int match_nl_mac_lport(struct nl_sock *nsd, uint32_t pid,
		     unsigned int ifindex, int family,
		     uint64_t mac, uint32_t *lport,
		     uint32_t *glort)
{
	struct net_mat_port port = {.pci = {0},
	                            .port_id = NET_MAT_PORT_ID_UNSPEC,
				    .mac_addr = 0, .port_phys_id = 0};
	struct net_mat_port ports[2] = {{0}, {0}};
	int err;

	ports[0] = ports[1] = port;

	ports[0].mac_addr = mac;

	err = match_nl_get_port(nsd, pid, ifindex, family,
			NET_MAT_PORT_CMD_GET_LPORT, ports, lport, glort);

	return err;
}

int match_nl_lport_to_phys_port(struct nl_sock *nsd, uint32_t pid,
				unsigned int ifindex, int family,
				uint32_t lport, uint32_t *phys_port,
				uint32_t *glort)
{
	struct net_mat_port port = {.pci = {0},
	                            .port_id = NET_MAT_PORT_ID_UNSPEC,
				    .mac_addr = 0, .port_phys_id = 0};
	struct net_mat_port ports[2] = {{0}, {0}};
	int err;

	ports[0] = ports[1] = port;

	ports[0].port_id = lport;

	err = match_nl_get_port(nsd, pid, ifindex, family,
			NET_MAT_PORT_CMD_GET_PHYS_PORT,
			ports, phys_port, glort);

	return err;
}
