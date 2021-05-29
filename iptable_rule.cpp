#include "iptable_rule.h"
#include "iptable_helpers.h"
#include <iostream>
#include <unistd.h>
#include <string>
#include <cstring>

iptable_rule::iptable_rule()
{
	(void) memset((void*)this, 0, sizeof(*this));
	this->expression_list.clear();
}

iptable_rule::~iptable_rule()
{
 
}

void iptable_rule::set_data(uint16_t attribute, void* data, uint32_t data_length)
{
	switch(attribute)
	{
		case RULE_TABLE:
			this->table = *static_cast<std::string*>(data);
			break;
		case RULE_CHAIN:
			this->chain = *static_cast<std::string*>(data);
			break;
		case RULE_HANDLE:
			this->handle = *static_cast<uint64_t*>(data);
			break;
		case RULE_POSITION:
			this->position = *static_cast<uint64_t*>(data);
			break;
		case RULE_COMPATABILITY_PROTOCOL:
			this->compatability.protocol = *static_cast<uint32_t*>(data);
			break;
		case RULE_COMPATABILITY_FLAGS:
			this->compatability.flags = *static_cast<uint32_t*>(data);
			break;
		case RULE_FAMILY:
			this->family = *static_cast<uint32_t*>(data);
			break;
		case RULE_USERDATA:
			this->user.data = data;
			break;
	}
}

void iptable_rule::add_expression(rule_expression* expr)
{ 
  this->expression_list.push_back(expr);
}

void iptable_rule::test()
{
	std::cout << "TABLE: " << this->table <<  std::endl;
	std::cout << "CHAIN: " << this->chain << std::endl;
	std::cout << "HANDLE: " << this->handle << std::endl;
	std::cout << "POSITION: " << this->position << std::endl;
	std::cout << "COMPATABILITY PROTOCOL: " <<  this->compatability.protocol << std::endl;
	std::cout << "COMPATABILITY FLAGS: " << std::hex << this->compatability.flags << std::endl;
	std::cout << "FAMILY: " << this->family << std::endl;
	std::cout << "DATA Length: " << (this->user.data == nullptr ? "EMPTY" : "Has data!!!") << std::endl;
}

char* iptable_rule::get_message_payload_ending(nlmsghdr* nlh)
{
	return reinterpret_cast<char*>(reinterpret_cast<char*>(nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
}

void iptable_rule::build_nlmsg_payload(nlmsghdr* nlh)
{
	nlattr* nest, *nested_nest, *double_nested_nest;

  if (this->family != 0)
  {
    iptable_helpers::put(nlh, NFTA_RULE_UNSPEC, sizeof(uint32_t), &this->family);
	}
  if (!this->table.empty())
  {
    iptable_helpers::put(nlh, NFTA_RULE_TABLE, strlen(this->table.c_str()) + 1, this->table.c_str()); // +1 is to include null terminator
	}
  if (!this->chain.empty())
  {
    iptable_helpers::put(nlh, NFTA_RULE_CHAIN, strlen(this->chain.c_str()) + 1, this->chain.c_str());
  }
 //  if (!this->position != 0)
 //  {
 //    put(nlh, NFTA_RULE_POSITION, sizeof(uint64_t), reinterpret_cast<void*>(&htobe64(this->position)));
	// }
 //  if (!this->handle != 0)
 //  {
 //    put(nlh, NFTA_RULE_HANDLE, sizeof(uint64_t), reinterpret_cast<void*>(&htobe64(this->handle)));
 //  }
  if(this->expression_list.size() > 0)
  {
    nest = begin_nest(nlh, NFTA_RULE_EXPRESSIONS);
    for( uint8_t i = 0; i <  this->expression_list.size(); ++i)
    {
    	nlattr* nest2 = iptable_helpers::begin_nest(nlh, NFTA_LIST_ELEM);
      iptable_helpers::put(nlh, NFTA_EXPR_NAME, strlen(expression_list.at(i)->get_name()), expression_list.at(i)->get_name());
      double_nested_nest = iptable_helpers::begin_nest(nlh, NFTA_EXPR_DATA);
		  expression_list[i]->build(nlh);
      iptable_helpers::end_nest(nlh, double_nested_nest);
		  iptable_helpers::end_nest(nlh, nest2);
    }
    end_nest(nlh, nest);
  }
}

void iptable_rule::package_expression(nlmsghdr* nlh, rule_expression& expr)
{
  const char* name = expr.get_name();
  iptable_helpers::put(nlh, NFTA_EXPR_NAME, strlen(name), name);
}

nlattr* iptable_rule::begin_nest(nlmsghdr* nlh, uint16_t flag)
{
	nlattr* entry = reinterpret_cast<nlattr*>(get_message_payload_ending(nlh));
	entry->nla_type = NLA_F_NESTED | flag;
	nlh->nlmsg_len += NLMSG_ALIGN(sizeof(nlattr));
	return entry;
}

void iptable_rule::end_nest(nlmsghdr* nlh, nlattr* nest)
{
	nest->nla_len = get_message_payload_ending(nlh) - reinterpret_cast<char*>(nest);
}

void iptable_rule::build_expr(rule_expression* expr, nlmsghdr* nlh)
{

}