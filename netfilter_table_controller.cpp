#include "netfilter_table_controller.h"
#include <unistd.h>
#include <iostream>

netfilter_table_controller::netfilter_table_controller()
{
    sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_NETFILTER);
}

netfilter_table_controller::~netfilter_table_controller()
{
    close(sockfd);
}

bool netfilter_table_controller::bind(sockaddr_nl addr, socklen_t len)
{
    bool bound = false;

    if( sockfd >= 0 )
    {
        if(::bind(sockfd, reinterpret_cast<sockaddr*>(&addr), len) >= 0){
            bound = true;
        }
    }

    return bound;
}

int netfilter_table_controller::getport()
{
    if( sockfd >= 0)
    {
        sockaddr_in addr;
        socklen_t len = sizeof(addr);
        getsockname(sockfd, reinterpret_cast<sockaddr*>(&addr), &len);
        return addr.sin_port;
    }
    return -1;
}

int netfilter_table_controller::send(const void *buffer, size_t size)
{
    int status = -1;
    if( sockfd >= 0)
    {
        status = sendto(sockfd, buffer, sizeof(buffer), 0, reinterpret_cast<sockaddr*>(&dest), sizeof(dest));
    }
    return status;
}

int netfilter_table_controller::recv(void* buffer, size_t size)
{

    return -1;
}