#include <string.h>
#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <iostream>
#include <unistd.h>

#include "iptable_helpers.h"
#include "netfilter_table_controller.h"

int chain_cb(char* buf, size_t len, uint32_t seq, int port)
{
  return DONE;
}

int main()
{
  char buf[8192];
  uint32_t portno, seq, chain_seq;
  message_batch* batch;
  seq = time(nullptr);
  batch = iptable_helpers::start_batch(buf, sizeof(buf));
  iptable_helpers::create_batch_header(batch->current_message, NFNL_MSG_BATCH_BEGIN, seq++);
  iptable_helpers::batch_create_next_message(batch);

  chain_seq = seq;

  nlmsghdr* hdr = iptable_helpers::create_nfnl_subsys_header(batch->current_message, NFT_MSG_NEWCHAIN, NFPROTO_NETDEV, NLM_F_CREATE | NLM_F_ACK, seq++);
  iptable_helpers::put(hdr, NFTA_CHAIN_TABLE, strlen("filter") + 1, "filter");
  iptable_helpers::put(hdr, NFTA_CHAIN_NAME, strlen("input") + 1, "input");
  nlattr* nest = iptable_helpers::begin_nest(hdr, NFTA_CHAIN_HOOK);
  uint32_t hook = htonl(NF_INET_LOCAL_IN);
  iptable_helpers::put(hdr, NFTA_HOOK_HOOKNUM, sizeof(hook), &hook);
  uint32_t hook_prio = htonl(0);
  iptable_helpers::put(hdr, NFTA_HOOK_PRIORITY, sizeof(hook_prio), &hook_prio);
  iptable_helpers::end_nest(hdr, nest);
  iptable_helpers::batch_create_next_message(batch);

  iptable_helpers::create_batch_header(batch->current_message, NFNL_MSG_BATCH_END, seq++);
  iptable_helpers::batch_create_next_message(batch);

  netfilter_table_controller controller;
  portno = controller.getport();

  controller.setup();

  if (controller.send(batch->data_buf, batch->size) < 0)
  {
    std::cerr << "Failed to send data" << std::endl;
    return -1;
  }
  iptable_helpers::end_batch(batch);
  int resp = controller.recv(buf, sizeof(buf));
  if(resp < 0)
  {
    std::cerr << "Failed to recv" << std::endl;
  }

  while (resp > 0)
  {
    resp = chain_cb(buf, resp, chain_seq, portno);
    if (resp <= 0)
    {
      break;
    }
    resp = controller.recv(buf, sizeof(buf));
  }

  if( resp == -1)
  {
    std::cerr << "Something happened... " << strerror(errno) << std::endl;
  }

  controller.cleanup();

}
