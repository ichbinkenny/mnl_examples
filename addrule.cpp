#include <bits/stdint-uintn.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <linux/netfilter/nf_tables_compat.h>
#include <vector>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <libmnl/libmnl.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nf_tables_compat.h>
#include <iostream>
#include <unistd.h>
#include "iptable_rule.h"
#include "rule_expressions/counter_expression.h"
#include "rule_expressions/log_expression.h"
#include "rule_expressions/meta_expression.h"
#include "rule_expressions/payload_expression.h"
#include "rule_expressions/comparison_expression.h"
#include "rule_expressions/reject_expression.h"
#include "rule_expressions/match_expression.h"
#include <cstring>

const int expr_name = 0;
const int expr_base = 1;

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
  // payload_expression payload(NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1, offsetof(iphdr, protocol), sizeof(uint8_t));
  // rule.add_expression(&payload);
  // uint32_t proto = IPPROTO_ICMP;
  // comparison_expression cmp(NFT_REG_1, NFT_CMP_EQ, &proto, sizeof(uint8_t));
  // rule.add_expression(&cmp);
  // payload_expression icmp_payload(NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_2, offsetof(iphdr, protocol), sizeof(uint8_t));
  // uint32_t proto = IPPROTO_ICMP;
  // comparison_expression icmp_cmp(NFT_REG_2, NFT_CMP_EQ, &proto, sizeof(uint8_t));
  // reject_expression reject(NFT_REJECT_ICMP_UNREACH, 0);
  // counter_expression counter;
  // rule.add_expression(&icmp_payload);
  // rule.add_expression(&icmp_cmp);
  // rule.add_expression(&counter);
  // rule.add_expression(&reject);

  //Complex rule example
  // meta_expression mexpr(NFT_META_IIFTYPE, NFT_REG_1);
  // uint32_t daddr = offsetof(ethhdr, h_dest);
  // uint32_t mproto = IPPROTO_ETHERNET;
  // comparison_expression mcmp(NFT_REG_1, NFT_CMP_EQ, &mproto, sizeof(mproto));
  // meta_expression meta_expr(NFT_META_IIFNAME, NFT_REG_3);
  // const char* iifname = "enp3s0";
  // meta_expression out_meta_expr(NFT_META_OIFNAME, NFT_REG_4);
  // const char* oifname = "enp3s0";
  // comparison_expression oifcmp(NFT_REG_4, NFT_CMP_EQ, oifname, strlen(oifname));
  // comparison_expression meta_cmp(NFT_REG_3, NFT_CMP_EQ, iifname, strlen(iifname));
  // meta_expression ether_link(NFT_META_IIFTYPE, NFT_REG_2);
  // uint32_t ether_type = 0x01;
  // comparison_expression ether_cmp(NFT_REG_2, NFT_CMP_EQ, &ether_type, sizeof(ether_type));
  // payload_expression ether_payload(NFT_PAYLOAD_LL_HEADER, NFT_REG_2, offsetof(ethhdr, h_source), sizeof(ether_addr));
  // ether_addr* saddr = ether_aton("aa:cc:ee:aa:cc:ee");
  // comparison_expression mac_cmp(NFT_REG_2, NFT_CMP_EQ, saddr, sizeof(*saddr));

  // rule.add_expression(&mexpr);
  // rule.add_expression(&mcmp);
  // rule.add_expression(&meta_expr);
  // rule.add_expression(&meta_cmp);
  // rule.add_expression(&out_meta_expr);
  // rule.add_expression(&oifcmp);
  // rule.add_expression(&ether_link);
  // rule.add_expression(&ether_cmp);
  // rule.add_expression(&ether_payload);
  // //rule.add_expression(&match);
  // rule.add_expression(&mac_cmp);

  //Layer 2 match on dest
  meta_expression eth_meta(NFT_META_IIFTYPE, NFT_REG_1);
  uint32_t ether = 0x01;
  comparison_expression eth_cmp(NFT_REG_1, NFT_CMP_EQ, &ether, sizeof(ether));
  payload_expression eth_payload(NFT_PAYLOAD_LL_HEADER, NFT_REG_1, offsetof(ethhdr, h_dest), sizeof(ether_addr));
  ether_addr* daddr = ether_aton("d4:d2:52:8d:97:d5");
  comparison_expression mac_cmp(NFT_REG_1, NFT_CMP_EQ, daddr, sizeof(ether_addr));
  payload_expression src_payload(NFT_PAYLOAD_LL_HEADER, NFT_REG_2, offsetof(ethhdr, h_source), sizeof(ether_addr));
  ether_addr* saddr = ether_aton("d4:d2:52:8d:97:d5");
  comparison_expression src_mac_cmp(NFT_REG_2, NFT_CMP_EQ, saddr, sizeof(ether_addr));
  counter_expression counter;

  rule.add_expression(&eth_meta);
  rule.add_expression(&eth_cmp);
  rule.add_expression(&eth_payload);
  rule.add_expression(&mac_cmp);
  rule.add_expression(&src_payload);
  rule.add_expression(&src_mac_cmp);
  rule.add_expression(&counter);
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
