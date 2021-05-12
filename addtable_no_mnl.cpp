#include <linux/netfilter/nf_tables.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <iostream>
#include <unistd.h>
#include <string.h>

int main()
{
  int sockfd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_NETFILTER);
  if(sockfd < 0)
  {
    std::cerr << "Failed to open socket" << std::endl;
    return -1;
  } 
  sockaddr_nl addr;
  addr.nl_family = AF_NETLINK;
  addr.nl_pid = getpid();
  addr.nl_groups = 0;
  if(bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
  {
    std::cerr << "Failed to bind: " << strerror(errno) << std::endl;
    return -2;
  }
  char buf[8192];
  nlmsghdr* nlh = reinterpret_cast<nlmsghdr*>(buf);
  nlh->nlmsg_len = NLMSG_ALIGN(sizeof(nlmsghdr));
  nlh->nlmsg_type = NFT_MSG_GETTABLE;
  nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;

  nfgenmsg* gen = reinterpret_cast<nfgenmsg*>(nlh + nlh->nlmsg_len);
  gen->nfgen_family = AF_NETLINK;
  gen->version = NFNETLINK_V0;
  gen->res_id = 0;

  sockaddr_nl out = {
    .nl_family = AF_NETLINK,
  };

  int resp = sendto(sockfd, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&out), sizeof(out));

  if(resp >= 0)
  {
    std::cout << "Sent message" << std::endl;
  }

  socklen_t len = sizeof(sockaddr_nl);
  getsockname(sockfd, reinterpret_cast<sockaddr*>(&addr), &len);
  int portno = addr.nl_pid;

  std::cout << "Port number: " << portno << std::endl;

  close(sockfd);
}