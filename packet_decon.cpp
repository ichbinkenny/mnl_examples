#include <unistd.h>
#include <linux/socket.h>
#include <linux/netlink.h>
#include <sys/types.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <iostream>
#include <string.h>
#include <libmnl/libmnl.h>

int sock;

int data_attr_cb(const struct nlattr* attr, void* data)
{
    std::cout << "HI MON" << std::endl;
    return MNL_CB_OK;
}

int data_cb(const struct nlmsghdr* nlh, void* data)
{
    struct nlattr *tb[8192] = {};
    struct nfgenmsg* msg = reinterpret_cast<nfgenmsg*>(mnl_nlmsg_get_payload(nlh));
    mnl_attr_parse(nlh, sizeof(*msg), data_attr_cb, tb);
    return MNL_CB_OK;
}

int main()
{
    char buf[MNL_SOCKET_BUFFER_SIZE];
    mnl_socket* sock = mnl_socket_open(NETLINK_NETFILTER);
    int seq;
    if(sock == nullptr)
    {
        std::cerr << "Failed to open socket " << strerror(errno) << std::endl;
        return -1;
    }
    if(mnl_socket_bind(sock, 0, MNL_SOCKET_AUTOPID) < 0)
    {
        std::cerr << "Unable to bind socket: " << strerror(errno) << std::endl;
        mnl_socket_close(sock);
        return -2;
    }
    struct nlmsghdr* msg = mnl_nlmsg_put_header(buf);
    msg->nlmsg_flags = NLM_F_ACK | NLM_F_REQUEST | NLM_F_DUMP;
    msg->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETTABLE;
    msg->nlmsg_seq = seq = time(nullptr);
    nfgenmsg* msgen = reinterpret_cast<nfgenmsg*>(mnl_nlmsg_put_extra_header(msg, sizeof(struct nfgenmsg)));
    msgen->nfgen_family = AF_NETLINK;
    msgen->version = NFNETLINK_V0;
    msgen->res_id = 0;
    int returned;
    if(mnl_socket_sendto(sock, msg, msg->nlmsg_len) < 0)
    {
        std::cerr << "Failed to send message: " << strerror(errno) << std::endl;
        mnl_socket_close(sock);
        return -3;
    }
    std::cout << "Sent message" << std::endl;
    int portid = mnl_socket_get_portid(sock);
    while(true) {
        std::cout << "Receiving message..." << std::endl;
        returned = mnl_socket_recvfrom(sock, buf, sizeof(buf));
        if(returned == -1)
        {
            std::cerr << "Failed to receive message" << std::endl;
            break;
        }
        returned = mnl_cb_run(buf, returned, seq, portid, data_cb, NULL);
        if(returned == -1)
        {
            std::cout << "Callback error" << std::endl;
            break;
        }
        if(returned <= MNL_CB_STOP)
        {
            break;
        }
    }
    std::cout << "Program end" << std::endl;
    mnl_socket_close(sock);
    return 0;

}
