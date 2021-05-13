#ifndef __L3_NETFILTER_TABLE_CONTROLLER__
#define __L3_NETFILTER_TABLE_CONTROLLER__
#include <linux/netfilter.h>
#include <linux/netlink.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <linux/netfilter/nf_tables.h>
#include <unistd.h>
#include <cstdint>

struct nft_ctl_socket {
    int fd;
    sockaddr_nl addr;
};

enum data_status {
    ERR = -1, DONE = 0, OK = 1
};

class netfilter_table_controller 
{
    public:
        netfilter_table_controller();
        ~netfilter_table_controller();
        int send(const void* buffer, size_t size);
        int recv(void* buffer, size_t size);
        int getport();
        bool setup();
        void get_tables(void* buffer);
    private:
        int sockfd = -1;
        sockaddr_nl addr;
        nlmsghdr* create_header(char* buffer, uint16_t command, uint16_t family, uint16_t flags, uint32_t seq);
        data_status get_table_data(char* buffer, size_t len, uint32_t seq, int portno, void* data_storage);
        bool nlmsg_valid(nlmsghdr* nlh, int length);
    protected:
};

#endif