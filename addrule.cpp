#include <vector>
#include <arpa/inet.h>
#include <libmnl/libmnl.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <iostream>
#include <unistd.h>
#include "iptable_rule.h"
#include <cstring>

const int expr_name = 0;
const int expr_base = 1;

// struct rule_operation;

// struct nat_operation {
//   uint32_t source_min_reg;
//   uint32_t source_max_reg;
//   uint32_t source_protocol_min_reg;
//   uint32_t source_protocol_max_reg;
//   uint32_t family;
//   uint32_t type; // Source nat is 0, dest nat is 1
//   uint32_t flags;
// };

// struct rule_expression {
//   uint32_t flags;
//   uint32_t family;
//   const char* table_name;
//   const char* chain_name;
//   uint64_t handle_id;
//   uint64_t pos;
//   std::vector<rule_operation> expression_list;
// };

// struct rule_operation
// {
//   const char* name;
//   uint32_t flags;
//   std::vector<void*> data;
// };

void make_batch_header(char* buf, uint16_t type, uint32_t seq)
{
    nlmsghdr* hdr;
    nfgenmsg* msg;

    hdr = mnl_nlmsg_put_header(buf);
    hdr->nlmsg_flags = NLM_F_REQUEST;
    hdr->nlmsg_seq = seq;
    hdr->nlmsg_type = type;

    msg = reinterpret_cast<nfgenmsg*>(mnl_nlmsg_put_extra_header(hdr, sizeof(*msg)));
    msg->nfgen_family = AF_UNSPEC;
    msg->res_id = NFNL_SUBSYS_NFTABLES;
    msg->version = NFNETLINK_V0;
}

struct nlmsghdr* make_header(char* buf, uint16_t cmd, uint16_t fam, uint16_t type, uint32_t seq)
{
    nlmsghdr* hdr;
    nfgenmsg* msg;

    hdr = mnl_nlmsg_put_header(buf);
    hdr->nlmsg_flags = NLM_F_REQUEST | type;
    hdr->nlmsg_seq = seq;
    hdr->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | cmd;

    msg = reinterpret_cast<nfgenmsg*>(mnl_nlmsg_put_extra_header(hdr, sizeof(*msg)));
    msg->nfgen_family = fam;
    msg->version = NFNETLINK_V0;
    msg->res_id = 0;

    return hdr;
}

// rule_expression* make_expr_payload(const char* payload_type)
// {
//   rule_expression* expressions;
//   rule_operation* ops;

//   //ops = get_expr_structure(payload_type);

//   return expressions;
// }

// void build_expr_data(nlmsghdr* nlh, rule_operation* op)
// {
//   if (strcmp(op->name, "nat") == 0)
//   {
//     std::cout << "Compiling nat args" << std::endl;
//     nat_operation* nat_op = reinterpret_cast<nat_operation*>(&op->data[0]);
//     mnl_attr_put_u32(nlh, NFTA_NAT_TYPE, htonl(nat_op->type));
//     mnl_attr_put_u32(nlh, NFTA_NAT_FAMILY, htonl(nat_op->family));
//     mnl_attr_put_u32(nlh, NFTA_NAT_REG_ADDR_MIN,  htonl(nat_op->source_min_reg));
//     mnl_attr_put_u32(nlh, NFTA_NAT_REG_ADDR_MAX, htonl(nat_op->source_max_reg));
//     mnl_attr_put_u32(nlh, NFTA_NAT_REG_PROTO_MIN, htonl(nat_op->source_protocol_min_reg));
//     mnl_attr_put_u32(nlh, NFTA_NAT_REG_PROTO_MAX, htonl(nat_op->source_protocol_max_reg));
//     mnl_attr_put_u32(nlh, NFTA_NAT_FLAGS, htonl(nat_op->flags));
//   }
// }


// void create_rule_payload(nlmsghdr* nlh, rule_expression* rule)
// {
//   nlattr* nest, *nested_nest;
//   nlattr* double_nested_nest;
//   if (strcmp(rule->table_name, "") != 0)
//   {
//     mnl_attr_put_strz(nlh, NFTA_RULE_TABLE, rule->table_name);
//   }
//   if (strcmp(rule->chain_name,  "") != 0)
//   {
//     mnl_attr_put_strz(nlh, NFTA_RULE_CHAIN, rule->chain_name);
//   }
//   if (rule->family !=  0)
//   {
//     mnl_attr_put_u32(nlh, NFTA_RULE_UNSPEC,  rule->family);
//   }
//   if (rule->handle_id != 0)
//   {
//     std::cout << "HERE"  << std::endl;
//     mnl_attr_put_u64(nlh, NFTA_RULE_HANDLE, htobe64(rule->handle_id));
//   }
//   if (rule->pos != 0)
//   {
//     mnl_attr_put_u64(nlh, NFTA_RULE_POSITION, htobe64(rule->pos));
//   }
//   if (rule->expression_list.size() > 0)
//   {
//     std::cout << "Nest here" << std::endl;
//     nest = mnl_attr_nest_start(nlh, NFTA_RULE_EXPRESSIONS);
//     for(rule_operation op : rule->expression_list)
//     {
//       nested_nest = mnl_attr_nest_start(nlh, NFTA_LIST_ELEM);
//       mnl_attr_put_strz(nlh, NFTA_EXPR_NAME, op.name);
//       double_nested_nest = mnl_attr_nest_start(nlh, NFTA_EXPR_DATA);
//       build_expr_data(nlh, &op);
//       mnl_attr_nest_end(nlh, double_nested_nest);
//       mnl_attr_nest_end(nlh, nested_nest);
//     }
//     (void) mnl_attr_nest_end(nlh, nest);
//   }
// }


int main()
{
  iptable_rule rule;
  std::string table = "filter";
  rule.set_data(RULE_TABLE, reinterpret_cast<void*>(&table), sizeof(table));
  std::string chain = "alpaca";
  rule.set_data(RULE_CHAIN, reinterpret_cast<void*>(&chain), sizeof(chain));
  uint32_t fam = NFPROTO_IPV4;
  rule.set_data(RULE_FAMILY, reinterpret_cast<void*>(&fam), sizeof(fam));
  mnl_socket* nl = mnl_socket_open(NETLINK_NETFILTER);
  uint32_t portno, seq, rule_seq;
  char buf[MNL_SOCKET_BUFFER_SIZE];
  mnl_nlmsg_batch* batch;
  seq = time(nullptr);
  batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
  make_batch_header(reinterpret_cast<char*>(mnl_nlmsg_batch_current(batch)), NFNL_MSG_BATCH_BEGIN, seq++);
  mnl_nlmsg_batch_next(batch);

  rule_seq = seq;
  nlmsghdr* nlh = make_header(reinterpret_cast<char*>(mnl_nlmsg_batch_current(batch)), NFT_MSG_NEWRULE, 
      NFPROTO_IPV4, NLM_F_CREATE | NLM_F_ACK | NLM_F_APPEND, seq++);
  // rule_expression r;
  // (void) memset(&r, 0, sizeof(r));
  // r.table_name = "filter";
  // r.chain_name = "alpaca";
  // r.family = NFPROTO_IPV4;
  // rule_operation expr;
  // (void) memset(&expr, 0, sizeof(expr));
  // expr.name = "counter";
  // r.expression_list.push_back(expr);
  // expr.name = "log";
  // r.expression_list.push_back(expr);
  //create_rule_payload(nlh, &r);
  std::vector<uint8_t> data;
  rule.add_expression("log", 0, data);
  rule.add_expression("counter", 0, data);
  rule.build_nlmsg_payload(nlh);

  mnl_nlmsg_batch_next(batch);
  make_batch_header(reinterpret_cast<char*>(mnl_nlmsg_batch_current(batch)), NFNL_MSG_BATCH_END, seq++);
  mnl_nlmsg_batch_next(batch);

  mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID);

  portno = mnl_socket_get_portid(nl);
  
  if(mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch)) < 0)
  {
    std::cerr << "Failed to send msg" << std::endl;
    return -1;
  }

  int resp = mnl_socket_recvfrom(nl, buf, sizeof(buf));
  if (resp < 0)
  {
    std::cerr << "Failed to get msg" << std::endl;
  }
  while (resp > 0)
  {
    resp = mnl_cb_run(buf, resp, rule_seq, portno, nullptr, nullptr);
    if (resp <= 0)
    {
      break;
    }
    resp = mnl_socket_recvfrom(nl, buf, sizeof(buf));
  }
  if(resp == -1)
  {
    std::cerr << "Error: " << strerror(errno) << std::endl;
  }

  mnl_socket_close(nl);

}
