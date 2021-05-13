#include <linux/netfilter/nf_tables.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <iostream>
#include <unistd.h>
#include <string.h>
#include "netfilter_table_controller.h"



int main()
{
  char buf[8192];
  netfilter_table_controller controller;
  sockaddr_nl addr;
  addr.nl_family = AF_NETLINK;
  socklen_t len = sizeof(addr);
  if(!controller.setup())
  {
    std::cerr << "failed to bind" << std::endl;
    return -1;
  }
  std::cout << "Port: " << controller.getport() << std::endl;
  controller.get_tables(buf);

}