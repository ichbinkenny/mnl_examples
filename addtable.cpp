#include <iostream>
#include <arpa/inet.h>
#include <linux/socket.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <unistd.h>
#include <string.h>
#include <libmnl/libmnl.h>

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

struct nlmsghdr* make_table_header(char* buf, uint16_t cmd, uint16_t fam, uint16_t type, uint32_t seq)
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

void make_table_payload(nlmsghdr* hdr, const char* name, uint32_t flags)
{
    mnl_attr_put_strz(hdr, NFTA_TABLE_NAME, name);
    mnl_attr_put_u32(hdr, NFTA_TABLE_FLAGS, flags);
}

int main()
{
    mnl_socket* nl;
    char buf[MNL_SOCKET_BUFFER_SIZE];
    struct nlmsghdr* nlh;
    uint32_t port, seq, table_seq;
    mnl_nlmsg_batch* batch;
    int ret;
    const char* table_name = "filter";

    seq = time(nullptr);
    batch = mnl_nlmsg_batch_start(buf, sizeof(buf));
    make_batch_header(reinterpret_cast<char*>(mnl_nlmsg_batch_current(batch)), NFNL_MSG_BATCH_BEGIN, seq++);

    mnl_nlmsg_batch_next(batch);

    table_seq = seq;
    nlh = make_table_header(reinterpret_cast<char*>(mnl_nlmsg_batch_current(batch)), NFT_MSG_NEWTABLE, NFPROTO_INET, NLM_F_ACK | NLM_F_CREATE, seq++);
    make_table_payload(nlh, table_name, 0);

    mnl_nlmsg_batch_next(batch);
     
    make_batch_header(reinterpret_cast<char*>(mnl_nlmsg_batch_current(batch)), NFNL_MSG_BATCH_END, seq++);
    mnl_nlmsg_batch_next(batch);

    // begin sending message
    nl = mnl_socket_open(NETLINK_NETFILTER);
    if(nl == nullptr)
    {
        std::cerr << "Failed to open socket" << std::endl;
        return -1;
    }
    if(mnl_socket_bind(nl, 0, MNL_SOCKET_AUTOPID) < 0)
    {
        std::cerr << "Failed to bind" << std::endl;
        mnl_socket_close(nl);
        return -2;
    }
    port = mnl_socket_get_portid(nl);

    // Send message
    if(mnl_socket_sendto(nl, mnl_nlmsg_batch_head(batch), mnl_nlmsg_batch_size(batch)) < 0)
    {
        std::cerr << "Failed to send message" << std::endl;
        mnl_socket_close(nl);
        return -3;
    }
    mnl_nlmsg_batch_stop(batch);

    ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));

    if(ret < 0)
    {
        std::cerr << "Failed to receive message: " << strerror(errno) << std::endl;
    }

    while (ret > 0) 
    {
        ret = mnl_cb_run(buf, ret, table_seq, port, NULL, NULL);
        std::cout << "Ret: " << ret << std::endl;
        if (ret <= 0)
        {
            break;
        }
        ret = mnl_socket_recvfrom(nl, buf, sizeof(buf));
        std::cout << "HERE" << std::endl;
    }
    if (ret == -1)
    {
        std::cerr << "Recv err: " << strerror(errno) << std::endl;
    }
    mnl_socket_close(nl);
    return 0;
    
}
