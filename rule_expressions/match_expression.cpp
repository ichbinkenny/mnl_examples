#include "match_expression.h"
#include "../iptable_helpers.h"
#include <cstring>
#include <linux/netfilter/nf_tables_compat.h>
#include <netinet/in.h>

match_expression::match_expression()
{
    this->name = "match";
    this->flags = 0;
}

match_expression::match_expression(const char* name, uint32_t rev, uint32_t len, const char* data)
{
    this->name = "match";
    (void) memset(this->match_name, 0, sizeof(this->match_name));

    this->flags = (1 << NFTA_MATCH_NAME) | (1 << NFTA_MATCH_REV) | (1 << NFTA_MATCH_INFO);
    this->match_revision = rev;
    this->data_length = len;
    snprintf(this->match_name, sizeof(this->match_name), "%.*s", strlen(name), name);
    this->data = data;
}

match_expression::~match_expression()
{

}

void match_expression::build(nlmsghdr *nlh)
{
    if (flags & (1 << NFTA_MATCH_NAME))
    {
        iptable_helpers::put(nlh, NFTA_MATCH_NAME, strlen(this->match_name), this->match_name);
    }
    if (flags & (1 << NFTA_MATCH_REV))
    {
        uint32_t data = htonl(this->match_revision);
        iptable_helpers::put(nlh, NFTA_MATCH_REV, sizeof(data), &data);
    }
    if (flags & (1 << NFTA_MATCH_INFO))
    {
        iptable_helpers::put(nlh, NFTA_MATCH_INFO, this->data_length, this->data);
    }
}

void match_expression::parse(nlattr *attr)
{

}

bool match_expression::same_as(const rule_expression &other)
{
    bool same = false;

    return same;
}

const char* match_expression::get_name()
{
    return this->name.c_str();
}