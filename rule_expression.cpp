#include "rule_expression.h"
#include <linux/netlink.h>

rule_expression::~rule_expression(){}

void rule_expression::build(nlmsghdr* nlh){}

void rule_expression::parse(nlattr* attr){}

bool rule_expression::same_as(const rule_expression& other){
	return false;
}

const char* rule_expression::get_name(){
	return this->name.c_str();
}