#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <unistd.h>
#include <ctime>
#include <iostream>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include "iptable_helpers.h"
#include "netfilter_table_controller.h"

data_status attribute_cb(nlattr* attr, nlmsghdr* nlh, char* data_buf)
{
    data_status status = OK;
    nlattr** table = reinterpret_cast<nlattr**>(data_buf);
    table[attr->nla_type & NLA_TYPE_MASK] = attr;
    return status;
}

data_status parse_nlmsg_attributes(nlmsghdr* nlh, uint32_t offset, char* data_buf)
{
  data_status status = OK;
  nlattr* attr = reinterpret_cast<nlattr*>(iptable_helpers::get_payload_from_offset(nlh, offset));
  for (attr;
        iptable_helpers::is_attribute_valid(attr, iptable_helpers::get_message_payload_ending(nlh) - reinterpret_cast<char*>(attr));
        attr = iptable_helpers::next_nlattr(attr))
        {
            if ((status = attribute_cb(attr, nlh, data_buf)) <= DONE) 
            {
                break;
            }
        }
  return status;
}

void get_table_info(nlmsghdr* nlh)
{
    nlattr* tb[NFTA_TABLE_MAX + 1];
    nfgenmsg* gen = reinterpret_cast<nfgenmsg*>(iptable_helpers::get_nlmsg_payload(nlh));
    parse_nlmsg_attributes(nlh, sizeof(*gen), reinterpret_cast<char*>(tb));
    std::cout << "Table name: " << iptable_helpers::get_attribute_payload(tb[NFTA_TABLE_NAME]) << std::endl;
}

int parse_table_data(char* buf, size_t len, uint32_t seq, int port)
{
    nlmsghdr* hdr = reinterpret_cast<nlmsghdr*>(buf);
    int status = DONE;
    while (iptable_helpers::nlmsg_valid(hdr, len))
    {
        if ( hdr->nlmsg_flags & NLM_F_DUMP_INTR)
        {
            // The dump was interrupted. Return an error.
            status = ERR;
            break;
        }
        if ( hdr->nlmsg_type >= NLMSG_MIN_TYPE){
            get_table_info(hdr);
        }
        nlmsghdr* test = iptable_helpers::next_nlmsg(hdr, &len);
        hdr = test;//mnl_nlmsg_next(hdr, (int*)&len);
    }
    return status;
}

int main()
{
    char buf[8192];
    netfilter_table_controller controller;
    uint32_t port, seq = time(nullptr), fam = NFPROTO_IPV4;
    nlmsghdr* hdr = iptable_helpers::create_nfnl_subsys_header(buf, NFT_MSG_GETTABLE, fam, NLM_F_DUMP, seq);
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
        resp = parse_table_data(buf, resp, seq, port);
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