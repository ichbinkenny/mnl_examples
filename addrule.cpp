#include <bits/stdint-uintn.h>
#include <linux/if_ether.h>
#include <netinet/ether.h>
#include <linux/netfilter/nf_tables_compat.h>
#include <vector>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nf_tables_compat.h>
#include <iostream>
#include <unistd.h>
#include "iptable_rule.h"
#include "iptable_helpers.h"
#include "netfilter_table_controller.h"
#include "rule_expressions/counter_expression.h"
#include "rule_expressions/log_expression.h"
#include "rule_expressions/meta_expression.h"
#include "rule_expressions/payload_expression.h"
#include "rule_expressions/comparison_expression.h"
#include "rule_expressions/reject_expression.h"
#include "rule_expressions/match_expression.h"
#include "rule_expressions/bitwise_expression.h"
#include <cstring>

const int expr_name = 0;
const int expr_base = 1;

int rule_cb(char* buf, size_t len, uint32_t seq, int port)
{
  return DONE;
}

int main()
{
  iptable_rule rule;
  std::string table = "filter";
  rule.set_data(RULE_TABLE, reinterpret_cast<void*>(&table), sizeof(table));
  std::string chain = "input";
  rule.set_data(RULE_CHAIN, reinterpret_cast<void*>(&chain), sizeof(chain));
  uint32_t fam = NFPROTO_IPV4;
  rule.set_data(RULE_FAMILY, reinterpret_cast<void*>(&fam), sizeof(fam));
  uint32_t portno, seq, rule_seq;
  char buf[8192];
  message_batch* batch;
  seq = time(nullptr);
  batch = iptable_helpers::start_batch(buf, sizeof(buf));
  iptable_helpers::create_batch_header(batch->current_message, NFNL_MSG_BATCH_BEGIN, seq++);
  iptable_helpers::batch_create_next_message(batch);

  rule_seq = seq;
  nlmsghdr* nlh = iptable_helpers::create_nfnl_subsys_header(batch->current_message, NFT_MSG_NEWRULE, 
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
  // meta_expression eth_meta(NFT_META_IIFTYPE, NFT_REG_1);
  // uint32_t ether = 0x01;
  // comparison_expression eth_cmp(NFT_REG_1, NFT_CMP_EQ, &ether, sizeof(ether));
  // payload_expression eth_payload(NFT_PAYLOAD_LL_HEADER, NFT_REG_1, offsetof(ethhdr, h_dest), sizeof(ether_addr));
  // ether_addr* daddr = ether_aton("d4:d2:52:8d:97:d5");
  // comparison_expression mac_cmp(NFT_REG_1, NFT_CMP_EQ, daddr, sizeof(ether_addr));
  // payload_expression src_payload(NFT_PAYLOAD_LL_HEADER, NFT_REG_2, offsetof(ethhdr, h_source), sizeof(ether_addr));
  // ether_addr* saddr = ether_aton("d4:d2:52:8d:97:d5");
  // comparison_expression src_mac_cmp(NFT_REG_2, NFT_CMP_EQ, saddr, sizeof(ether_addr));
  // counter_expression counter;

  // rule.add_expression(&eth_meta);
  // rule.add_expression(&eth_cmp);
  // rule.add_expression(&eth_payload);
  // rule.add_expression(&mac_cmp);
  // rule.add_expression(&src_payload);
  // rule.add_expression(&src_mac_cmp);
  // rule.add_expression(&counter);

  // Begin Levi's ultimate rule tests
  // Layer 2 VLAN ID
  // meta_expression vlan_meta(NFT_META_IIFTYPE, NFT_REG_1);
  // uint32_t ether_type = 0x01;
  // comparison_expression ether_type_cmp(NFT_REG_1, NFT_CMP_EQ, &ether_type, sizeof(ether_type));
  // payload_expression vlan_payload(NFT_PAYLOAD_LL_HEADER, NFT_REG_1, 0, sizeof(uint16_t));
  // uint32_t mask = 0xff0f;
  // uint32_t xor_val = 0;
  // bitwise_expression vlan_bwise(NFT_REG_1, NFT_REG_1, sizeof(uint32_t), &mask, sizeof(mask), &xor_val, sizeof(xor_val));
  // uint32_t data = 0;
  // comparison_expression vlan_cmp(NFT_REG_1, NFT_CMP_NEQ, &data, sizeof(data));
  // counter_expression counter;
  // rule.add_expression(&vlan_meta);
  // rule.add_expression(&ether_type_cmp);
  // rule.add_expression(&vlan_payload);
  // rule.add_expression(&vlan_bwise);
  // rule.add_expression(&vlan_cmp);
  // rule.add_expression(&counter);

  //Layer 3 IPv4
  payload_expression ipv4_payload(NFT_PAYLOAD_NETWORK_HEADER, NFT_REG_1, offsetof(iphdr, saddr), sizeof(uint32_t));
  in_addr saddr;
  inet_aton("8.8.8.8", &saddr);
  comparison_expression ipv4_cmp(NFT_REG_1, NFT_CMP_EQ, &saddr, sizeof(in_addr));
  counter_expression counter;

  rule.add_expression(&ipv4_payload);
  rule.add_expression(&ipv4_cmp);
  rule.add_expression(&counter);
  rule.build_nlmsg_payload(nlh);
  iptable_helpers::batch_create_next_message(batch);
  iptable_helpers::create_batch_header(batch->current_message, NFNL_MSG_BATCH_END, seq++);
  iptable_helpers::batch_create_next_message(batch);

  netfilter_table_controller controller;

  controller.setup();

  portno = controller.getport();
  
  if(controller.send(batch->data_buf, batch->size) < 0)
  {
    std::cerr << "Failed to send msg" << std::endl;
    return -1;
  }

  int resp = controller.recv(buf, sizeof(buf));
  if (resp < 0)
  {
    std::cerr << "Failed to get msg" << std::endl;
  }
  while (resp > 0)
  {
    resp = rule_cb(buf, resp, rule_seq, portno);
    if (resp <= 0)
    {
      break;
    }
    resp = controller.recv(buf, sizeof(buf));
  }
  if(resp == -1)
  {
    std::cerr << "Error: " << strerror(errno) << std::endl;
  }

  controller.cleanup();

}
