#include <string.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <libmnl/libmnl.h>
#include <iostream>
#include <unistd.h>

nlmsghdr* make_header(char* buf, uint16_t action, uint16_t family, uint16_t flags, uint32_t seq_num)
{
  nlmsghdr* hdr;
  nfgenmsg* gen;
  hdr = mnl_nlmsg_put_header(buf);
  hdr->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | action;
  hdr->nlmsg_seq = seq_num;
  hdr->nlmsg_flags = NLM_F_REQUEST | flags;

  gen = static_cast<nfgenmsg*>(mnl_nlmsg_put_extra_header(hdr, sizeof(*gen)));
  gen->nfgen_family = family;
  gen->version = NFNETLINK_V0;
  gen->res_id = 0;
  
  return hdr;
}

void make_batch_header(char* buf, uint16_t type, uint32_t seq_num)
{
  nlmsghdr* hdr;
  nfgenmsg* gen;
  hdr = mnl_nlmsg_put_header(buf);
  hdr->nlmsg_type = type;
  hdr->nlmsg_seq = seq_num;
  hdr->nlmsg_flags = NLM_F_REQUEST;
  gen = static_cast<nfgenmsg*>(mnl_nlmsg_put_extra_header(hdr, sizeof(*gen)));
  gen->nfgen_family = AF_UNSPEC;
  gen->version = NFNETLINK_V0;
  gen->res_id = NFNL_SUBSYS_NFTABLES;
}

int main()
{
  char buf[MNL_SOCKET_BUFFER_SIZE];
  uint32_t portno, seq, chain_seq;
  mnl_nlmsg_batch* batch;
  seq = time(nullptr);
  batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
  make_batch_header(reinterpret_cast<char*>(mnl_nlmsg_batch_current(batch)), NFNL_MSG_BATCH_BEGIN, seq++);
  mnl_nlmsg_batch_next(batch);

  chain_seq = seq;

  nlmsghdr* hdr = make_header(reinterpret_cast<char*>(mnl_nlmsg_batch_current(batch)), NFT_MSG_DELCHAIN, NFPROTO_IPV4, NLM_F_ACK, seq++);
  mnl_attr_put_strz(hdr, NFTA_CHAIN_TABLE, "filter");
  mnl_attr_put_strz(hdr, NFTA_CHAIN_NAME, "alpaca");
  mnl_nlmsg_batch_next(batch);

  make_batch_header(reinterpret_cast<char*>(mnl_nlmsg_batch_current(batch)), NFNL_MSG_BATCH_END, seq++);
  mnl_nlmsg_batch_next(batch);

  mnl_socket* nl = mnl_socket_open(NETLINK_NETFILTER);
  mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID);
  portno = mnl_socket_get_portid(nl);

  if (mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch)) < 0)
  {
    std::cerr << "Failed to send data" << std::endl;
    return -1;
  }
  mnl_nlmsg_batch_stop(batch);
  int resp = mnl_socket_recvfrom(nl, buf, sizeof(buf));
  if(resp < 0)
  {
    std::cerr << "Failed to recv" << std::endl;
  }

  while (resp > 0)
  {
    resp = mnl_cb_run(buf, resp, chain_seq, portno, NULL, NULL);
    if (resp <= 0)
    {
      break;
    }
    resp = mnl_socket_recvfrom(nl, buf, sizeof(buf));
  }

  if( resp == -1)
  {
    std::cerr << "Something happened... " << strerror(errno) << std::endl;
  }

  mnl_socket_close(nl);

}
