#ifndef __NETFILTER_TABLE_CONTROLLER__
#define __NETFILTER_TABLE_CONTROLLER__
#include <linux/netfilter.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <sys/types.h>

struct nft_ctl_socket {
    int fd;
    sockaddr_nl addr;
};

class netfilter_table_controller 
{
    public:
        netfilter_table_controller();
        virtual ~netfilter_table_controller();
        int send(const void* buffer, size_t size);
        int recv(void* buffer, size_t size);
        int getport();
        bool bind(sockaddr_nl addr, socklen_t len);
    private:
        int sockfd = -1;
        sockaddr_nl addr;
    protected:
};

#endif