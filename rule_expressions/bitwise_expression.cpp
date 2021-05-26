#include "bitwise_expression.h"
#include "../iptable_helpers.h"
#include <string.h>
#include <netinet/in.h>

bitwise_expression::bitwise_expression()
{
    this->name = "bitwise";
    this->flags = 0;
}

bitwise_expression::bitwise_expression(nft_registers src, nft_registers dest, uint32_t len, const void* mask, uint32_t mask_len, const void* xor_reg, uint32_t xor_len)
{
    this->name = "bitwise";
    this->flags = (1 << NFTA_BITWISE_SREG) | (1 << NFTA_BITWISE_DREG) | (1 << NFTA_BITWISE_LEN) | (1 << NFTA_BITWISE_MASK) | (1 << NFTA_BITWISE_XOR);
    this->source = src;
    this->dest = dest;
    this->length = len;
    this->mask.length = mask_len;
    this->xor_register.length = xor_len;
    memcpy(this->mask.value, mask, mask_len);
    memcpy(this->xor_register.value, xor_reg, xor_len);
}

bitwise_expression::~bitwise_expression()
{
    
}

void bitwise_expression::build(nlmsghdr* nlh)
{
    if ( flags & (1 << NFTA_BITWISE_SREG))
    {
        uint32_t data = htonl(this->source);
        iptable_helpers::put(nlh, NFTA_BITWISE_SREG, sizeof(data), &data);
    }
    if ( flags & ( 1 << NFTA_BITWISE_DREG ))
    {
        uint32_t data = htonl(this->dest);
        iptable_helpers::put(nlh, NFTA_BITWISE_DREG, sizeof(data), &data);
    }
    if ( flags & ( 1 << NFTA_BITWISE_LEN ))
    {
        uint32_t len = htonl(this->length);
        iptable_helpers::put(nlh, NFTA_BITWISE_LEN, sizeof(len), &len);
    }
    if ( flags & ( 1 << NFTA_BITWISE_MASK ))
    {
        nlattr* mask_nest = iptable_helpers::begin_nest(nlh, NFTA_BITWISE_MASK);
        iptable_helpers::put(nlh, NFTA_DATA_VALUE, this->mask.length, this->mask.value);
        iptable_helpers::end_nest(nlh, mask_nest);
    }
    if ( flags & ( 1 << NFTA_BITWISE_XOR ))
    {
        nlattr* xor_nest = iptable_helpers::begin_nest(nlh, NFTA_BITWISE_XOR);
        iptable_helpers::put(nlh, NFTA_DATA_VALUE, this->xor_register.length, this->xor_register.value);
        iptable_helpers::end_nest(nlh, xor_nest);
    }
}

void bitwise_expression::parse(nlattr* attr)
{
    
}

bool bitwise_expression::same_as(const rule_expression& other)
{
    bool same = false;

    return same;
}

const char* bitwise_expression::get_name()
{
    return this->name.c_str();
}