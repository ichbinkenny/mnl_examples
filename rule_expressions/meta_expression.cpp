#include "meta_expression.h"
#include "../iptable_helpers.h"
#include <linux/netfilter/nf_tables.h>
#include <netinet/in.h>


meta_expression::meta_expression()
{
	this->name = "meta";
}

meta_expression::~meta_expression()
{

}

void meta_expression::build(nlmsghdr* nlh)
{
	if (this->flags & (1 << NFTA_META_KEY))
	{
		uint32_t data = htonl(this->meta_key);
		iptable_helpers::put(nlh, NFTA_META_KEY, sizeof(uint32_t), &data);
	}
	if (this->flags & (1 << NFTA_META_DREG))
	{
		uint32_t data = htonl(this->dest);
		iptable_helpers::put(nlh, NFTA_META_DREG, sizeof(uint32_t), &data);
	}
	if (this->flags & (1 << NFTA_META_SREG))
	{
		uint32_t data = htonl(this->source);
		iptable_helpers::put(nlh, NFTA_META_SREG, sizeof(uint32_t), &data);
	}
}

void meta_expression::parse(nlattr* attr)
{

}

bool meta_expression::same_as(const rule_expression & other)
{
	bool same = false;
	/// @todo
	return same;
}

const char* meta_expression::get_name()
{
	return this->name.c_str();
}