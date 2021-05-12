#include <string.h>
#include <libmnl/libmnl.h>
#include <list>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <libnftnl/rule.h>
#include <iostream>
#include <unistd.h>

struct rule {
  uint32_t flags;
  uint32_t family;
  const char* table_name;
  const char* chain_name;
  uint64_t handle_id;
  uint64_t pos;

  std::list expressions_list;
};

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

void create_rule_payload()



int main()
{
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
      NFPROTO_IPV4, NLM_F_CREATE | NLM_F_ACK, seq++);
  mnl_attr_put_strz(nlh, 1, "filter");
  mnl_attr_put_strz(nlh, 2, "alpaca");
  mnl_attr_put_u32(nlh, 0, NFPROTO_IPV4); //family
  create_rule_payload();

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
