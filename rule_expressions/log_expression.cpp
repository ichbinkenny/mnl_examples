#include "log_expression.h"
#include <cstring>

log_expression::log_expression()
{
	this->name = "log";
}

log_expression::~log_expression()
{

}

void log_expression::build(nlmsghdr* p_nlh)
{

}

void log_expression::parse(nlattr *p_attr)
{

}

const char* log_expression::get_name()
{
	return this->name.c_str();
}

bool log_expression::same_as(const rule_expression& other)
{
	bool same = false;
	// if ( this->flags == other.flags
	// 	&& this->name == other.name
	// 	&& this->size == other.size
	// 	&& this->snap_length == other.snap_length
	// 	&& this->group_id == other.group_id
	// 	&& this->threshold == other.threshold
	// 	&& this->log_level == other.log_level
	// 	&& strcmp(this->prefix, other.prefix) == 0
	// 	&& this->data == other.data)
	// {
	// 	same = true;
	// }
	return same;
}