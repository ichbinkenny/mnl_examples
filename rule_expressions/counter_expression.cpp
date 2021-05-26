#include "counter_expression.h"
#include "../iptable_helpers.h"
#include <endian.h>
#include <linux/netfilter/nf_tables.h>
#include <libmnl/libmnl.h>

counter_expression::counter_expression()
{
	this->name = "counter";	
	this->flags = (1 << NFTA_COUNTER_BYTES) | (1 << NFTA_COUNTER_PACKETS);
	this->bytes_count = 0;
	this->packet_count = 0;
}

counter_expression::~counter_expression()
{

}

void counter_expression::build(nlmsghdr* p_nlh)
{
	if(this->flags & (1 << NFTA_COUNTER_BYTES))
	{
		uint64_t data = htobe64(this->bytes_count);
		mnl_attr_put_u64(p_nlh, NFTA_COUNTER_BYTES, data);
		//iptable_helpers::netlink_message_put(p_nlh, NFTA_COUNTER_BYTES, sizeof(uint64_t), &data);
	}
	if (this->flags & (1 << NFTA_COUNTER_PACKETS))
	{
		uint64_t data = htobe64(this->packet_count);
		mnl_attr_put_u64(p_nlh, NFTA_COUNTER_PACKETS, data);
		//iptable_helpers::netlink_message_put(p_nlh, NFTA_COUNTER_PACKETS, sizeof(uint64_t), &data);
	}
}

void counter_expression::parse(nlattr* p_attr)
{

}

bool counter_expression::same_as(const rule_expression &other)
{
	bool same = false;
	
	return same;
}

const char* counter_expression::get_name()
{
	return this->name.c_str();
}

static int get_info(char* buf, size_t size, int type)
{
	return snprintf(buf, size, "TEST!!!!");
}