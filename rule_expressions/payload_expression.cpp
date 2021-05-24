#include "payload_expression.h"
#include "../iptable_helpers.h"
#include <linux/netfilter/nf_tables.h>
#include <linux/netlink.h>
#include <netinet/in.h>

payload_expression::payload_expression()
{
	this->name = "payload";
	this->flags = 0;
}

payload_expression::~payload_expression()
{
	
}

void payload_expression::set_flags(uint32_t flags)
{
	this->flags = flags;
}

void payload_expression::add_flags(uint32_t flags)
{
	this->flags |= flags;
}

void payload_expression::build(nlmsghdr* p_nlh)
{
	if (flags & (1 << NFTA_PAYLOAD_SREG))
	{
		iptable_helpers::put(p_nlh, NFTA_PAYLOAD_SREG, sizeof(nft_registers), reinterpret_cast<const char*>(htonl(this->source)));
	}
	if (flags & (1 << NFTA_PAYLOAD_DREG))
	{
		iptable_helpers::put(p_nlh, NFTA_PAYLOAD_DREG, sizeof(nft_registers), reinterpret_cast<const char*>(htonl(this->dest)));
	}
	if (flags & (1 << NFTA_PAYLOAD_BASE))
	{
		iptable_helpers::put(p_nlh, NFTA_PAYLOAD_BASE, sizeof(nft_payload_bases), reinterpret_cast<const char*>(htonl(this->base)));
	}
	if (flags & (1 << NFTA_PAYLOAD_OFFSET))
	{
		iptable_helpers::put(p_nlh, NFTA_PAYLOAD_OFFSET, sizeof(uint32_t), reinterpret_cast<const char*>(htonl(this->offset)));
	}
	if (flags & (1 << NFTA_PAYLOAD_LEN))
	{
		iptable_helpers::put(p_nlh, NFTA_PAYLOAD_LEN, sizeof(uint32_t), reinterpret_cast<const char*>(htonl(this->length)));
	}
}

void payload_expression::parse(nlattr* p_attr)
{

}

bool payload_expression::same_as(const payload_expression& other)
{
	bool same = false;

	return same;
}

const char* payload_expression::get_name()
{
	return this->name.c_str();
}