#include <iostream>
#include <linux/netfilter.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink_conntrack.h>
#include <unistd.h>
#include <linux/rtnetlink.h>
#include <libmnl/libmnl.h>
#include <linux/fib_rules.h>
#include <linux/lwtunnel.h>
#include <string.h>

using namespace std;
  
int table_attrs_cb(const struct nlattr* attr, void* data)
{
    const struct nlattr **table = reinterpret_cast<const nlattr**>(data);
    int type = mnl_attr_get_type(attr);
    if(mnl_attr_type_valid(attr, NFTA_TABLE_MAX) < 0)
    {
        return MNL_CB_OK;
    }
    table[type] = attr;
    return MNL_CB_OK;
}

int data_callback(const struct nlmsghdr* nlh, void* data)
{
    nlattr* table[NFTA_TABLE_MAX + 1] = {};
    nfgenmsg* nfg = reinterpret_cast<nfgenmsg*>(mnl_nlmsg_get_payload(nlh));

    if(mnl_attr_parse(nlh, sizeof(*nfg), table_attrs_cb, table) < 0)
    {
        return MNL_CB_ERROR;
    }

    if(table[NFTA_TABLE_NAME])
    { 
        std::cout << "Found table: " << mnl_attr_get_str(table[NFTA_TABLE_NAME]) << std::endl;
    }

    std::cout << "Got here" << std::endl;
    

    
    return MNL_CB_OK;
}

int main()
{
    mnl_socket* nl;
    uint32_t seq;
    nl = mnl_socket_open(NETLINK_NETFILTER);
    if(nl == nullptr)
    {
        cout << "Failed to create socket!" << std::endl;
        return -1;
    }
    if(mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
    {
        cout << "Failed to bind socket!" << std::endl;
        mnl_socket_close(nl);
        return -2;
    }
    char buf[MNL_SOCKET_BUFFER_SIZE];
    nlmsghdr* nlh = mnl_nlmsg_put_header(buf);
    nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8 ) | NFT_MSG_GETTABLE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_seq = seq = time(NULL);
    nfgenmsg* nfm = reinterpret_cast<nfgenmsg*>(mnl_nlmsg_put_extra_header(nlh, sizeof(struct nfgenmsg)));
    nfm->nfgen_family = NFPROTO_IPV4;
    nfm->version = NFNETLINK_V0;
    nfm->res_id = 0;
    cout << "Sending request" << std::endl;
    int res = mnl_socket_sendto(nl, nlh, nlh->nlmsg_len);
    if(res == -1)
    {
        cout << "Failed to send message. Err: " << strerror(errno) << endl;
        mnl_socket_close(nl);
        return -3;
    }
    cout << "Request sent." << endl;
    uint32_t portid = mnl_socket_get_portid(nl);
    cout << "Packet sent on port: " << portid << endl;
    std::cout << "Parsing response" << endl;
while(true)
    {
        res = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        if(res == -1)
        {
            cout << "Failed to receive info! Err: " << strerror(errno) << endl;
            return -5;
        }
        res = mnl_cb_run(buf, res, seq, portid, data_callback, nullptr);
        if(res == -1)
        {
            cout << "Failed to run attribute callback. Err: " << strerror(errno) << endl;
            return -6;
        }
        else if(res <= MNL_CB_STOP)
        {
            break;
        }
    } 
    mnl_socket_close(nl);
    return 0;
}

