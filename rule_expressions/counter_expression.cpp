#include "counter_expression.h"

counter_expression::counter_expression()
{
	this->name = "counter";	
}

counter_expression::~counter_expression()
{

}

void counter_expression::build(nlmsghdr* p_nlh)
{

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