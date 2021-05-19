#ifndef __IPTABLE_HELPERS_H__
#define __IPTABLE_HELPERS_H__

#include <cstdint>
#include <cstddef>
#include <linux/netlink.h>
class iptable_helpers
{
	public:
		static void netlink_message_put(nlmsghdr* nlh, uint16_t type, size_t length, const void* data);	
		static char* get_message_payload_ending(nlmsghdr* nlh);
		static char* get_attribute_payload(nlattr* attr);
		static void put(nlmsghdr* nlh, uint16_t type, size_t length, const void* data);
	private:

};

#endif