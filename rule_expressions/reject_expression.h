#ifndef __REJECT_EXPRESSION_H__
#define __REJECT_EXPRESSION_H__

#include "../rule_expression.h"
#include <linux/netfilter/nf_tables.h>

class reject_expression : public rule_expression
{
    public: 
        reject_expression();
        reject_expression(uint32_t type, uint8_t code) :
        type(type),
        icmp_code(code){ flags = (1 << NFTA_REJECT_TYPE) | (1 << NFTA_REJECT_ICMP_CODE); name = "reject"; };
        ~reject_expression();

        void build(nlmsghdr* nlh);
        void parse(nlattr* attr);
        bool same_as(const rule_expression& other);
        const char* get_name();

    private:
        uint32_t type;
        uint8_t icmp_code;
};

#endif