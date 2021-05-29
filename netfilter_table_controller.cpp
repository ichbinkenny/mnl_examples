#include <arpa/inet.h>
#include "netfilter_table_controller.h"
#include "iptable_helpers.h"
#include <sys/socket.h>
#include <linux/netfilter/nfnetlink.h>
#include <iostream>
#include <string.h>


netfilter_table_controller::netfilter_table_controller()
{

}

netfilter_table_controller::~netfilter_table_controller()
{
    cleanup();
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

void netfilter_table_controller::cleanup()
{
    if ( this->sockfd >= 0 )
    {
        close(this->sockfd);
    }
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

ssize_t netfilter_table_controller::send(const void *buffer, size_t size)
{
    ssize_t status = -1;
    sockaddr_nl test {
        .nl_family = AF_NETLINK,
    };
    status = sendto(sockfd, buffer, size, 0, reinterpret_cast<sockaddr*>(&test), sizeof(test));
    return status;
}

ssize_t netfilter_table_controller::recv(void* buffer, size_t size)
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
    resp = recvmsg(this->sockfd, &msg, 0);
    return resp;
}

void netfilter_table_controller::add_table(const char* table_name)
{
    uint32_t seq = time(nullptr), table_seq = 0;
    uint32_t table_flags = htonl(0);
    char buffer[8192];
    message_batch* batch = iptable_helpers::start_batch(buffer, sizeof(buffer));
    iptable_helpers::create_batch_header(batch->current_message, NFNL_MSG_BATCH_BEGIN, seq++);
    iptable_helpers::batch_create_next_message(batch);

    table_seq = seq;
    std::cout << "Table seq: " << table_seq << std::endl;
    nlmsghdr* nlh = iptable_helpers::create_nfnl_subsys_header(batch->current_message, NFT_MSG_NEWTABLE, NFPROTO_NETDEV, NLM_F_ACK | NLM_F_CREATE, seq++);
    iptable_helpers::put(nlh, NFTA_TABLE_NAME, strlen("CAT") + 1, "CAT");
    iptable_helpers::put(nlh, NFTA_TABLE_FLAGS, sizeof(table_flags), &table_flags);
    iptable_helpers::batch_create_next_message(batch);

    iptable_helpers::create_batch_header(batch->current_message, NFNL_MSG_BATCH_END, seq++);
    iptable_helpers::batch_create_next_message(batch);

    if ( send(batch->data_buf, batch->size) > 0)
    {
        iptable_helpers::end_batch(batch); // free the batch resources
        int resp = recv(buffer, sizeof(buffer));
        if ( resp < 0 )
        {
            std::cerr << "NO DATA :(" << std::endl;
        }
        else
        {
            int portno = getport();
            while ( resp > 0 )
            {
                resp = add_table_cb(buffer, resp, table_seq, portno);
                if ( resp <= 0 )
                {
                    break;
                }
                resp = recv(buffer, sizeof(buffer));
            }
            if ( resp == ERR)
            {
                std::cerr << " ERROR IN RECV " << std::endl;
            }
            else
            {
                std::cout << " Added table " << std::endl;
            }
        }
    }
    else
    {
        iptable_helpers::end_batch(batch); // free the batch resources
    }

}

data_status netfilter_table_controller::add_table_cb(char* buf, size_t size, uint32_t sequence_num, int port_num)
{
    nlmsghdr* nlh = reinterpret_cast<nlmsghdr*>(buf);
    data_status status = iptable_helpers::nlmsg_valid(nlh, size) ? OK : ERR;
    while (iptable_helpers::nlmsg_valid(nlh, size))
    {
        if ( port_num != nlh->nlmsg_pid )
        {
            status = ERR;
            std::cerr << "Mismatched port ids " << port_num << " resp port was: " << nlh->nlmsg_pid << std::endl;
            break;
        }
        size -= NLMSG_ALIGN(nlh->nlmsg_len);
        nlh = reinterpret_cast<nlmsghdr*>(nlh + NLMSG_ALIGN(nlh->nlmsg_len));
        if ( size == 0 ) 
        {
            status = DONE;
            break;
        }
        else if ( size < 0 )
        {
            status = ERR;
            break;
        }
    }

    return status;
}

void netfilter_table_controller::get_tables()
{
    char buf[8192L];
    uint32_t port, seq = time(nullptr), fam = NFPROTO_NETDEV;
    nlmsghdr* hdr = iptable_helpers::create_nfnl_subsys_header(buf, NFT_MSG_GETTABLE, fam, NLM_F_DUMP, seq);
    if (send(hdr, hdr->nlmsg_len) >= 0)
    {
        port = getport();
        int resp = recv(buf, sizeof(buf));
        if ( resp < 0 )
        {
            std::cerr << "FAILURE 1st" << std::endl;
        }
        while ( resp > 0 )
        {
            resp = get_table_data(buf, resp, seq, port, nullptr);
            if ( resp <= 0)
            {
                break;
            }
            resp = recv(buf, sizeof(buf));
        }
        if ( resp == ERR)
        {
            std::cerr << "FAILURE 2nd" << std::endl;
        }
    }
}

data_status netfilter_table_controller::get_table_data(char* buffer, size_t len, uint32_t seq, int portno, void* data_storage)
{
    nlmsghdr* nlh = reinterpret_cast<nlmsghdr*>(buffer);
    data_status status = iptable_helpers::nlmsg_valid(nlh, len) ? DONE : ERR;
    while(iptable_helpers::nlmsg_valid(nlh, len))
    {
        retrieve_attrs(nlh);
        len -= NLMSG_ALIGN(nlh->nlmsg_len);
        nlh = nlh + NLMSG_ALIGN(nlh->nlmsg_len);
    }

    return status;
}

void netfilter_table_controller::retrieve_attrs(nlmsghdr* nlh)
{
    nlattr* table_data[NFTA_TABLE_MAX + 1];
    nfgenmsg* gen = reinterpret_cast<nfgenmsg*>(nlh + NLMSG_HDRLEN);

}


nlmsghdr* netfilter_table_controller::create_header(char* buffer, uint16_t command, uint16_t family, uint16_t flags, uint32_t seq)
{
    int length = NLMSG_ALIGN(sizeof(nlmsghdr));
    nlmsghdr* nlh = reinterpret_cast<nlmsghdr*>(buffer);
    (void)memset(nlh, 0, length);
    nlh->nlmsg_len = length;
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