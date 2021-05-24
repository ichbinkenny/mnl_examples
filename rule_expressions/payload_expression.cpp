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

void payload_expression::set_data(uint16_t type, const char* data, uint32_t length)
{
	bool success = true;
	switch(type)
	{
		case NFTA_PAYLOAD_SREG:
			this->source = static_cast<nft_registers>(*data);
			break;
		case NFTA_PAYLOAD_DREG:
			this->dest = static_cast<nft_registers>(*data);
			break;
		case NFTA_PAYLOAD_BASE:
			this->base = static_cast<nft_payload_bases>(*data);
			break;
		case NFTA_PAYLOAD_OFFSET:
			this->offset = static_cast<uint32_t>(*data);
			break;
		case NFTA_PAYLOAD_LEN:
			this->length = static_cast<uint32_t>(*data);
			break;
		case NFTA_PAYLOAD_CSUM_TYPE:
			this->csum_type = static_cast<uint32_t>(*data);
			break;
		case NFTA_PAYLOAD_CSUM_OFFSET:
			this->csum_offset = static_cast<uint32_t>(*data);
			break;
		case NFTA_PAYLOAD_CSUM_FLAGS:
			this->csum_flags = static_cast<uint32_t>(*data);
			break;
		default:
			success = false;
			break;
	}
	if (success) 
	{
		add_flags(1 << type);
	}
}

void payload_expression::build(nlmsghdr* p_nlh)
{
	if (flags & (1 << NFTA_PAYLOAD_DREG))
	{
		uint32_t data = htonl(this->dest);
		iptable_helpers::put(p_nlh, NFTA_PAYLOAD_DREG, sizeof(nft_registers), reinterpret_cast<const char*>(&data));
	}
	if (flags & (1 << NFTA_PAYLOAD_BASE))
	{
		uint32_t data = htonl(this->base);
		iptable_helpers::put(p_nlh, NFTA_PAYLOAD_BASE, sizeof(nft_payload_bases), reinterpret_cast<const char*>(&data));
	}
	if (flags & (1 << NFTA_PAYLOAD_OFFSET))
	{
		uint32_t data = htonl(this->offset);
		iptable_helpers::put(p_nlh, NFTA_PAYLOAD_OFFSET, sizeof(uint32_t), reinterpret_cast<const char*>(&data));
	}
	if (flags & (1 << NFTA_PAYLOAD_LEN))
	{
		uint32_t data = htonl(this->length);
		iptable_helpers::put(p_nlh, NFTA_PAYLOAD_LEN, sizeof(uint32_t), reinterpret_cast<const char*>(&data));
	}
}

void payload_expression::parse(nlattr* p_attr)
{

}

bool payload_expression::same_as(const rule_expression& other)
{
	bool same = false;

	return same;
}

const char* payload_expression::get_name()
{
	return this->name.c_str();
}