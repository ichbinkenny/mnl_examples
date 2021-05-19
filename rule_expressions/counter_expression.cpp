#include "counter_expression.h"
#include "../iptable_helpers.h"
#include <endian.h>
#include <linux/netfilter/nf_tables.h>

counter_expression::counter_expression()
{
	this->name = "counter";	
	this->flags |= (1 << NFTA_COUNTER_BYTES) | (1 << NFTA_COUNTER_PACKETS);
}

counter_expression::~counter_expression()
{

}

void counter_expression::build(nlmsghdr* p_nlh)
{
	if(this->flags & (1 << NFTA_COUNTER_BYTES))
	{
		uint64_t data = htobe64(this->bytes_count);
		iptable_helpers::netlink_message_put(p_nlh, NFTA_COUNTER_BYTES, sizeof(uint64_t), &data);
	}
	if (this->flags & (1 << NFTA_COUNTER_PACKETS))
	{
		uint64_t data = htobe64(this->packet_count);
		iptable_helpers::netlink_message_put(p_nlh, NFTA_COUNTER_PACKETS, sizeof(uint64_t), &data);
	}
}

void counter_expression::parse(nlattr* p_attr)
{

}

bool counter_expression::same_as(const counter_expression &other)
{
	bool same = false;
	if ( this->name == other.name
		&& this->flags == other.flags
		&& this->size == other.size
		&& this->packet_count == other.packet_count
		&& this->bytes_count == other.bytes_count
		&& this->data == other.data)
	{
		same = true;
	}
	return same;
}

const char* counter_expression::get_name()
{
	return this->name.c_str();
}