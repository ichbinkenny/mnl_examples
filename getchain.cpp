#include <libmnl/libmnl.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <iostream>
#include <unistd.h>
#include "iptable_helpers.h"
#include "netfilter_table_controller.h"

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

data_status get_chain_info(nlmsghdr* hdr)
{
  struct nlattr* tb[NFTA_CHAIN_MAX + 1] = {};
  nfgenmsg* gen = reinterpret_cast<nfgenmsg*>(iptable_helpers::get_nlmsg_payload(hdr));

  if (mnl_attr_parse(hdr, sizeof(*gen), chain_cb, tb) < 0)
  {
    return ERR;
  }

  if(tb[NFTA_CHAIN_NAME])
  {
    std::cout << "TABLE: " << mnl_attr_get_str(tb[NFTA_TABLE_NAME]) << " CHAIN FOUND: " << mnl_attr_get_str(tb[NFTA_CHAIN_NAME]) << std::endl;
  }
  
  return DONE;

}

data_status parse_chain_data(char* buf, size_t len, uint32_t seq, int port)
{
    nlmsghdr* hdr = reinterpret_cast<nlmsghdr*>(buf);
    data_status status = DONE;
    while (iptable_helpers::nlmsg_valid(hdr, len))
    {
        if ( hdr->nlmsg_flags & NLM_F_DUMP_INTR)
        {
            // The dump was interrupted. Return an error.
            status = ERR;
            break;
        }
        if(hdr->nlmsg_type >= NLMSG_MIN_TYPE)
        {
          get_chain_info(hdr);
        }
        hdr = iptable_helpers::next_nlmsg(hdr, &len);
    }
    return status;
}

int main()
{
  char buf[8192];
    netfilter_table_controller controller;
    uint32_t port, seq = time(nullptr), fam = NFPROTO_IPV4;
    nlmsghdr* hdr = iptable_helpers::create_nfnl_subsys_header(buf, NFT_MSG_GETCHAIN, fam, NLM_F_DUMP, seq);
    controller.setup();
    if (controller.send(hdr, hdr->nlmsg_len) < 0) 
    {
        return -1;
    }
    port = controller.getport();
    int resp = controller.recv(buf, sizeof(buf));
    if ( resp < 0 )
    {
        std::cerr << "Failed to recv too" << std::endl;
    }
    while ( resp > 0 )
    {
        resp = parse_chain_data(buf, resp, seq, port);
        if ( resp <= DONE )
        {
            break;
        }
        resp = controller.recv(buf, sizeof(buf));
    }
    if ( resp == ERR)
    {
        std::cout << "Failed" << std::endl;
    }
    controller.cleanup();

}
