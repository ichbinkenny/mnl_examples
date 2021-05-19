#ifndef __RULE_EXPRESSION_H__
#define __RULE_EXPRESSION_H__
#include "rule_operations.h"
#include <string>
#include <cstdint>
#include <linux/netlink.h>
#include <vector>

enum rule_attributes
{
	RULE_FAMILY = 0,
	RULE_TABLE,
	RULE_CHAIN,
	RULE_HANDLE,
	RULE_COMPATABILITY_PROTOCOL,
	RULE_COMPATABILITY_FLAGS,
	RULE_POSITION,
	RULE_USERDATA
};

class rule_expression
{
	public:
		virtual ~rule_expression() = 0;
		virtual void build(nlmsghdr* nlh) = 0;
		virtual void parse(nlattr* attr) = 0;
		virtual bool same_as(const rule_expression& other) = 0;		
		virtual const char* get_name();

	protected:
		std::string name;
		uint32_t flags;
		uint32_t size;
		std::vector<uint8_t> data;
};

#endif