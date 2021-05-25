#ifndef __MATCH_EXPRESSION_H__
#define __MATCH_EXPRESSION_H__

#include "../rule_expression.h"
#include <linux/netlink.h>

class match_expression : public rule_expression
{
    public:
        match_expression();
        match_expression(const char* name, uint32_t rev, uint32_t len, const char* data);
        ~match_expression();
        void build(nlmsghdr* nlh);
        void parse(nlattr* attr);
        bool same_as(const rule_expression& other);
        const char* get_name();
    private:
        char match_name[29]; // 29 is from xtables specification
        uint32_t match_revision;
        uint32_t data_length;
        const char* data;
};

#endif