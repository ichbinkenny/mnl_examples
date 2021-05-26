#ifndef __BITWISE_EXPRESSION_H__
#define __BITWISE_EXPRESSION_H__

#include "../rule_expression.h"
#include <linux/netfilter/nf_tables.h>
#include "data_register.h"

class bitwise_expression : public rule_expression
{
    public:
        bitwise_expression();
        bitwise_expression(nft_registers src, nft_registers dest, uint32_t len, const void* mask, uint32_t mask_len, const void* xor_reg, uint32_t xor_len);
        ~bitwise_expression();
        void build(nlmsghdr* nlh);
        void parse(nlattr* attr);
        bool same_as(const rule_expression& other);
        const char* get_name();
    private:
        nft_registers   source;
        nft_registers   dest;
        uint32_t        length;
        data_register   mask;
        data_register   xor_register;
        
};

#endif