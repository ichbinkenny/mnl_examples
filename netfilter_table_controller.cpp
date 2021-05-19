#include "netfilter_table_controller.h"
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <string.h>
#include <iostream>

netfilter_table_controller::netfilter_table_controller()
{

}

netfilter_table_controller::~netfilter_table_controller()
{
    if ( sockfd > -1 )
    {
        close(sockfd);
    }
}

bool netfilter_table_controller::setup()
{
    bool bound = false;
    sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
    if( sockfd >= 0 )
    {
        sockaddr_nl addr;
        addr.nl_family = AF_NETLINK;
        addr.nl_groups = 0;
        addr.nl_pid = 0;

        socklen_t len = sizeof(addr);

        if(bind(sockfd, reinterpret_cast<sockaddr*>(&addr), len) >= 0){
            bound = true;
        }
    }

    return bound;
}

int netfilter_table_controller::getport()
{
    socklen_t len = sizeof(addr);
    if(getsockname(sockfd, reinterpret_cast<sockaddr*>(&addr), &len) >= 0)
    {
        return addr.nl_pid;
    }
    return -1;
}

int netfilter_table_controller::send(const void *buffer, size_t size)
{
    int status = -1;
    sockaddr_nl test {
        .nl_family = AF_NETLINK,
    };
    status = sendto(sockfd, buffer, size, 0, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));
    return status;
}

int netfilter_table_controller::recv(void* buffer, size_t size)
{
    ssize_t resp;
    sockaddr_nl addr;
    iovec iov = {
        .iov_base = buffer,
        .iov_len = size,
    };
    msghdr msg = {
        .msg_name = &addr,
        .msg_namelen = sizeof(sockaddr_nl),
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = nullptr,
        .msg_controllen = 0,
        .msg_flags = 0,
    };
    resp = recvmsg(sockfd, &msg, 0);
    return resp;
}

void netfilter_table_controller::get_tables(void* buffer)
{
    uint32_t seq = time(nullptr);
    nlmsghdr* hdr = create_header(static_cast<char*>(buffer), NFT_MSG_GETTABLE, AF_INET, NLM_F_ACK | NLM_F_DUMP, seq);
    if(send(hdr, hdr->nlmsg_len) < 0)
    {
        std::cerr << "Failed to send! " << strerror(errno) << std::endl;
    }
    else
    {
        std::cout << "Sent message" << std::endl;
        int resp = recv(buffer, sizeof(buffer));
        if(resp < 0)
        {
            std::cerr << "Failed to recv! " << strerror(errno) << std::endl;
        }
        else
        {
            std::cout << "Recv initial data: " << resp << std::endl;
            while (resp > 0)
            {
                resp = get_table_data(static_cast<char*>(buffer), resp, seq, addr.nl_pid, nullptr);
                if (resp <= 0)
                {
                    std::cout << "Breaking here" << std::endl;
                    break;
                }
                resp = recv(buffer, sizeof(buffer));
            }
        }
    }

}

nlmsghdr* netfilter_table_controller::create_header(char* buffer, uint16_t command, uint16_t family, uint16_t flags, uint32_t seq)
{
    int length = NLMSG_ALIGN(sizeof(nlmsghdr));
    nlmsghdr* nlh = reinterpret_cast<nlmsghdr*>(buffer);
    nlh->nlmsg_len = length;
    (void)memset(nlh, 0, length);
    nlh->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | command;
    nlh->nlmsg_flags = NLM_F_REQUEST | flags;
    nlh->nlmsg_seq = seq;

    // Create NFNetgen message.
    char* additional_space = reinterpret_cast<char*>(nlh) + nlh->nlmsg_len;
    nlh->nlmsg_len += NLMSG_ALIGN(sizeof(nfgenmsg));
    // Set new space to zero
    (void)memset(additional_space, 0, NLMSG_ALIGN(sizeof(nfgenmsg)));
    nfgenmsg* gen = reinterpret_cast<nfgenmsg*>(additional_space);
    gen->nfgen_family = family;
    gen->version = NFNETLINK_V0;
    gen->res_id = 0;

    return nlh;

}

data_status netfilter_table_controller::get_table_data(char* buffer, size_t len, uint32_t seq, int portno, void* data_storage)
{
    std::cout << "GET TABLE DATA" << std::endl;
    data_status status = DONE;
    nlmsghdr* nlh = reinterpret_cast<nlmsghdr*>(buffer);
    while(nlmsg_valid(nlh, len))
    {
        std::cout << "Valid" << std::endl;
        if(portno != nlh->nlmsg_pid)
        {
            errno = ESRCH;
            status = ERR;
        }
        if (nlh->nlmsg_flags & NLM_F_DUMP_INTR)
        {
            errno = EINTR;
            status = ERR;
        }
        if (seq != nlh->nlmsg_seq)
        {
            errno = EPROTO;
            status = ERR;
        }
        if(nlh->nlmsg_type == NLMSG_MIN_TYPE)
        {
            std::cout << "Valid data" << std::endl;
        }
        len -= NLMSG_ALIGN(nlh->nlmsg_len);
        nlh = reinterpret_cast<nlmsghdr*>(nlh + NLMSG_ALIGN(nlh->nlmsg_len));
    }
    std::cout << "END GET TABLE DATA" << std::endl;
    return status;
}

bool netfilter_table_controller::nlmsg_valid(nlmsghdr* nlh, int len)
{
    bool match = len >= static_cast<int>(sizeof(nlmsghdr)) && nlh->nlmsg_len >= sizeof(nlmsghdr) && nlh->nlmsg_len <= len;
    if ( !match ) 
    {
        std::cout << "Match error. " << std::endl;
        if ( len < sizeof(nlmsghdr))
        {
            std::cout << "Len of " << len << " too short for nlmsghdr(" << sizeof(nlmsghdr)  << std::endl;
        }
    }
    return match;
}