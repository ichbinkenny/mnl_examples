#include <netinet/in.h>
#include "netfilter_table_controller.h"
#include <iostream>
#include <sys/socket.h>
#include "iptable_helpers.h"
#include <linux/netfilter/nfnetlink.h>
#include <string.h>

int main()
{

  const char* table_name = "filter";
  uint32_t flags = htonl(0);

  char buf[8192];
  netfilter_table_controller controller;
  sockaddr_nl addr;
  if(!controller.setup())
  {
    std::cerr << "failed to bind" << std::endl;
    return -1;
  }

  uint32_t seq = time(nullptr), port, table_seq;

  message_batch* batch = iptable_helpers::start_batch(buf, sizeof(buf));
  iptable_helpers::create_batch_header(batch->current_message,  NFNL_MSG_BATCH_BEGIN, seq++);
  iptable_helpers::batch_create_next_message(batch);

  table_seq = seq;
  nlmsghdr* nlh = iptable_helpers::create_nfnl_subsys_header(batch->current_message, NFT_MSG_NEWTABLE, NFPROTO_NETDEV, NLM_F_ACK | NLM_F_CREATE, seq++);
  iptable_helpers::put(nlh, NFTA_TABLE_NAME, strlen(table_name) + 1 , table_name);
  iptable_helpers::put(nlh, NFTA_TABLE_FLAGS, sizeof(uint32_t), &flags);
  iptable_helpers::batch_create_next_message(batch);

  iptable_helpers::create_batch_header(batch->current_message, NFNL_MSG_BATCH_END, seq++);
  iptable_helpers::batch_create_next_message(batch);

  controller.setup();

  if (controller.send(batch->data_buf, batch->size) >= 0)
  {
    //iptable_helpers::end_batch(batch); // free the batch resource
    port = controller.getport();
    int recvd = controller.recv(buf, sizeof(buf));
    if ( recvd > -1 )
    {
      std::cout << "First recv works!" << std::endl;
      while ( recvd > 0 )
      {
        recvd = controller.add_table_cb(buf, recvd, table_seq, port);
        if (recvd <= 0)
        {
          break;
        }
        recvd = controller.recv(buf, sizeof(buf));
      }
    }
  }


  controller.cleanup();
  return 0;
}