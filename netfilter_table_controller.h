#ifndef __L3_NETFILTER_TABLE_CONTROLLER__
#define __L3_NETFILTER_TABLE_CONTROLLER__ 
#include <linux/socket.h>
#include <linux/netfilter.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
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
        ssize_t send(const void* buffer, size_t size);
        ssize_t recv(void* buffer, size_t size);
        int getport();
        bool setup();
        void cleanup();
        void get_tables();
        void add_table(const char* table_name);
        data_status add_table_cb(char* buffer, size_t len, uint32_t seq, int portno);
    private:
        int sockfd = -1;
        sockaddr_nl addr;
        nlmsghdr* create_header(char* buffer, uint16_t command, uint16_t family, uint16_t flags, uint32_t seq);
        data_status get_table_data(char* buffer, size_t len, uint32_t seq, int portno, void* data_storage);
        void retrieve_attrs(nlmsghdr* nlh);
        nfgenmsg* retrieve_payload(nlmsghdr* nlh);
    protected:
};

#endif