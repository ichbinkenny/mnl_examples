#ifndef __IPTABLE_HELPERS_H__
#define __IPTABLE_HELPERS_H__

#include <cstdint>
#include <cstddef>
#include <linux/netlink.h>

struct message_batch
{
	char* data_buf;
	size_t max_size;
	size_t size;
	char* current_message;
	bool overfilled;
};

class iptable_helpers
{
	public:
		static void netlink_message_put(nlmsghdr* nlh, uint16_t type, size_t length, const void* data);	
		static char* get_message_payload_ending(nlmsghdr* nlh);
		static char* get_attribute_payload(nlattr* attr);
		static void put(nlmsghdr* nlh, uint16_t type, size_t length, const void* data);
		static nlattr* begin_nest(nlmsghdr* nlh, uint16_t flag);
		static void end_nest(nlmsghdr* nlh, nlattr* nest);
		static message_batch* start_batch(char* buffer, size_t max_size);
		static void create_batch_header(char* batch, uint16_t type, uint32_t seq_num);
		static bool batch_create_next_message(message_batch* batch);
		static void end_batch(message_batch* batch);
		static nlmsghdr* create_nfnl_subsys_header(char* buf, uint16_t command, uint16_t protocol, uint16_t flags, uint32_t seq);
		static nlmsghdr* put_header(char* buf);
		static char* put_aux_header(nlmsghdr* nlh, size_t size);
	private:

};

#endif