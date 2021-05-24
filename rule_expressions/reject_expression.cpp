#include "reject_expression.h"
#include <netinet/in.h>
#include "../iptable_helpers.h"

reject_expression::reject_expression()
{
    this->name = "reject";
    this->flags = 0;
}

reject_expression::~reject_expression()
{

}

void reject_expression::build(nlmsghdr* p_nlh)
{
    if (flags & (1 << NFTA_REJECT_TYPE))
    {
        uint32_t type = htonl(this->type);
        iptable_helpers::put(p_nlh, NFTA_REJECT_TYPE, sizeof(uint32_t), &type);
    }
    if (flags & (1 << NFTA_REJECT_ICMP_CODE))
    {
        uint8_t code = this->icmp_code;
        iptable_helpers::put(p_nlh, NFTA_REJECT_ICMP_CODE, sizeof(uint8_t), &code);
    }
}

void reject_expression::parse(nlattr* attr)
{

}

bool reject_expression::same_as(const rule_expression& other)
{
    bool status = false;

    return status;
}

const char* reject_expression::get_name()
{
    return this->name.c_str();
}