#include <libmnl/libmnl.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <iostream>
#include <unistd.h>

nlmsghdr* make_header(char* buf, uint16_t cmd, uint16_t family, uint16_t flags, uint32_t seq)
{
  nlmsghdr* hdr;
  nfgenmsg* gen;

  hdr = mnl_nlmsg_put_header(buf);
  hdr->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | cmd;
  hdr->nlmsg_flags = NLM_F_REQUEST | flags;
  hdr->nlmsg_seq = seq;

  gen = reinterpret_cast<nfgenmsg*>(mnl_nlmsg_put_extra_header(hdr, sizeof(nfgenmsg)));
  gen->nfgen_family = family;
  gen->version = NFNETLINK_V0;
  gen->res_id = 0;

  return hdr;
}

int chain_cb(const nlattr* attr, void* data)
{
  const nlattr** tb = static_cast<const nlattr**>(data);
  int type = mnl_attr_get_type(attr);
  
  tb[type] = attr;
  return MNL_CB_OK;
}

int table_cb(const nlmsghdr* hdr, void* data)
{
  struct nlattr* tb[NFTA_CHAIN_MAX + 1] = {};
  nfgenmsg* gen = static_cast<nfgenmsg*>(mnl_nlmsg_get_payload(hdr));

  if (mnl_attr_parse(hdr, sizeof(*gen), chain_cb, tb) < 0)
  {
    return MNL_CB_ERROR;
  }

  if(tb[NFTA_CHAIN_NAME])
  {
    std::cout << "CHAIN FOUND: " << mnl_attr_get_str(tb[NFTA_CHAIN_NAME]) << std::endl;
  }
  
  return MNL_CB_OK;

}



int main()
{
  mnl_socket* nl;
  nlmsghdr* nlh;
  char buf[MNL_SOCKET_BUFFER_SIZE];
  uint32_t seq, portid;
  seq = time(nullptr);

  nlh = make_header(buf, NFT_MSG_GETCHAIN, NFPROTO_IPV4, NLM_F_DUMP, seq);

  nl = mnl_socket_open(NETLINK_NETFILTER);
  mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID);
  portid = mnl_socket_get_portid(nl);

  if (mnl_socket_sendto(nl, nlh, nlh->nlmsg_len) < 0)
  {
    std::cerr << "Failed to send data" << std::endl;
    return -1;
  }

  int ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
  while (ret > 0)
  {
    ret = mnl_cb_run(buf, ret, seq, portid, table_cb, nullptr);
    if(ret <=0)
    {
      break;
    }
    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
  }
  if (ret == -1)
  {
    std::cerr << "Error in recv" << std::endl;
  }

  mnl_socket_close(nl);

}
