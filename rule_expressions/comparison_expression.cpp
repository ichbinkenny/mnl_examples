#include "comparison_expression.h"
#include "../iptable_helpers.h"
#include <cstdio>
#include <cstring>
#include <netinet/in.h>
#include <iostream>

comparison_expression::comparison_expression()
{
	this->name = "cmp";
}

comparison_expression::comparison_expression(nft_registers reg, nft_cmp_ops operation, const void* p_data, uint32_t data_length)
{
	this->name = "cmp";
	this->source = reg;
	this->operation = operation; // this operation was your idea!!!
	memcpy(data.value, p_data, data_length);
	this->data.length = data_length;
	this->flags = (1 << NFTA_CMP_SREG) | (1 << NFTA_CMP_OP)  | (1 << NFTA_CMP_DATA);
	printf("Created comp rule expr\n");
}

comparison_expression::~comparison_expression()
{
	
}

void comparison_expression::build(nlmsghdr* p_nlh)
{
	if (flags & (1 << NFTA_CMP_SREG))
	{
		uint32_t val = htonl(this->source);
		iptable_helpers::netlink_message_put(p_nlh, NFTA_CMP_SREG, sizeof(source), reinterpret_cast<const void*>(&val));
	}
	if (flags & (1 << NFTA_CMP_OP))
	{
		uint32_t val = htonl(this->operation);
		iptable_helpers::netlink_message_put(p_nlh, NFTA_CMP_OP, sizeof(operation), reinterpret_cast<const void*>(&val));
	}
	if (flags & (1 << NFTA_CMP_DATA))
	{
		nlattr* nest = iptable_helpers::begin_nest(p_nlh, NFTA_CMP_DATA);
		iptable_helpers::put(p_nlh, NFTA_DATA_VALUE, this->data.length, this->data.value);
		iptable_helpers::end_nest(p_nlh, nest);
	}
}

void comparison_expression::parse(nlattr* attr)
{

}

bool comparison_expression::same_as(const rule_expression& other)
{
	bool same = false;

	return same;
}

const char* comparison_expression::get_name()
{
	return this->name.c_str();
}