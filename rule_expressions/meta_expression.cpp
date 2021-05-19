#include "meta_expression.h"
#include "../iptable_helpers.h"
#include <linux/netfilter/nf_tables.h>


meta_expression::meta_expression()
{
	this->name = "meta";
	this->meta_key = NFT_META_IIFNAME;
	this->source = NFT_REG_1;
	this->dest = NFT_REG_2;
	this->flags |= (1<<NFTA_META_KEY) | (1<<NFTA_META_DREG) | (1<<NFTA_META_SREG);
}

meta_expression::~meta_expression()
{

}

void meta_expression::build(nlmsghdr* nlh)
{
	if (this->flags & (1 << NFTA_META_KEY))
	{
		uint32_t data = this->meta_key;
		iptable_helpers::put(nlh, NFTA_META_KEY, sizeof(uint32_t), &data);
	}
	if (this->flags & (1 << NFTA_META_DREG))
	{
		uint32_t data = this->dest;
		iptable_helpers::put(nlh, NFTA_META_DREG, sizeof(uint32_t), &data);
	}
	if (this->flags & (1 << NFTA_META_SREG))
	{
		uint32_t data = this->source;
		iptable_helpers::put(nlh, NFTA_META_SREG, sizeof(uint32_t), &data);
	}
}

void meta_expression::parse(nlattr* attr)
{

}

bool meta_expression::same_as(const meta_expression & other)
{
	bool same = false;
	/// @todo
	return same;
}

const char* meta_expression::get_name()
{
	return this->name.c_str();
}