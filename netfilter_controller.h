#ifndef __NETFILTER_CONTROLLER_H__
#define __NETFILTER_CONTROLLER_H__

#include <linux/netlink.h>
#include <linux/netfilter.h>

struct nlmsg_batch
{
	char* buf;
	size_t max_size;
	size_t current_length;
	char* current_message;
	bool has_overflown;
}

class NetfilterController {
	public:
		NetfilterController();
		~NetfilterController();
		nlmsg_batch* start_batch(char* buffer, size_t max_size);
		void end_batch(char* buffer);
	private:		
};


#endif