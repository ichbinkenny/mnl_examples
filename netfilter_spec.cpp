#include <sys/socket.h>
#include <linux/netlink.h>
#include <unistd.h>
#include <iostream>
#include <string.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>

int sock;

void send_cmd(nlmsghdr* nl, uint32_t groups)
{
    ssize_t ret_val;
    struct msghdr hdr;
    struct iovec iov;
    struct sockaddr_nl addr; 
    (void)memset(&iov, 0, sizeof(iov));
    (void)memset(&hdr, 0, sizeof(hdr));
    (void)memset(&addr, 0, sizeof(addr));

    nl->nlmsg_flags |= NLM_F_ACK;
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = groups;
    hdr.msg_name = reinterpret_cast<void*>(&addr);
    hdr.msg_namelen = sizeof(addr);
    
    hdr.msg_iov = &iov;
    hdr.msg_iovlen = 1;

    iov.iov_base = reinterpret_cast<void*>(&addr);
    iov.iov_len = nl->nlmsg_len;

    ret_val = sendmsg(sock, &hdr, 0);
    if(ret_val < 0)
    {
        std::cerr << "Failed to send message" << std::endl;
        return;
    }
    std::cout << "Sent message" << std::endl;
    char recv_buff[4096];
    struct nlmsghdr* msg;
    bool finished = false;

    iov.iov_base = &recv_buff[0];
    while(!finished)
    {
        iov.iov_len = sizeof(recv_buff);
        ret_val = recvmsg(sock, &hdr, 0);
        if(ret_val <= 0)
        {
            if((errno == EINTR) || (errno == EAGAIN))
            {
                continue;  
            }
            std::cerr << "Failed to receive a response" << std::endl;
            finished = true;
        }
        else
        {
            std::cout << " gt here" << std::endl;
            if(hdr.msg_namelen != sizeof(addr))
            {
                std::cerr << "Invalid size response" << std::endl;
            }
            else if(hdr.msg_flags & MSG_TRUNC)
            {
                std::cerr << "Received truncated message" << std::endl;
            }
            else 
            {
                int status = 0;
                for(msg=reinterpret_cast<struct nlmsghdr*>(&recv_buff[0]); NLMSG_OK(msg, status); msg = NLMSG_NEXT(msg, status))
                {
                    if(msg->nlmsg_type == NLMSG_ERROR)
                    {
                        finished = true;
                        std::cerr << "Error in packet" << std::endl;
                    }
                }
            }
            finished = true;
        }
    }
}

int main()
{
    sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    struct sockaddr_nl addr;
    if(sock < 0)
    {
        return -1;
    }
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = (NFNL_SUBSYS_NFTABLES << 8) | NFT_MSG_GETTABLE; 
    if(bind(sock, reinterpret_cast<sockaddr*>(&addr), static_cast<socklen_t>(sizeof(addr))) < 0)
    {
        return -2;
    }
    std::cout << "Managed to get here" << std::endl;
    socklen_t addr_len = sizeof(addr);
    if(0 > getsockname(sock, reinterpret_cast<sockaddr*>(&addr), &addr_len))
    {
        std::cerr << "Failed to get socket connection" << std::endl;
        return -3;
    }
    struct {
        struct nlmsghdr nl;
    } tablemsg;
    tablemsg.nl.nlmsg_len = sizeof(tablemsg);
    tablemsg.nl.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    tablemsg.nl.nlmsg_type = NFT_MSG_GETTABLE;
    send_cmd(&tablemsg.nl, addr.nl_groups);
    close(sock);
    return 0;
}
