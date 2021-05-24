#include "comparison_expression.h"
#include <cstdio>
#include <cstring>
#include <netinet/in.h>

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
}

comparison_expression::~comparison_expression()
{
	
}

void comparison_expression::build(nlmsghdr* p_nlh)
{

}

void comparison_expression::parse(nlattr* attr)
{

}

bool comparison_expression::same_as(const comparison_expression& other)
{
	bool same = false;

	return same;
}

const char* comparison_expression::get_name()
{
	return this->name.c_str();
}