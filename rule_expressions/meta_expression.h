#ifndef __META_EXPRESSION_H__
#define __META_EXPRESSION_H__

#include "../rule_expression.h"
#include <linux/netfilter/nf_tables.h>

class meta_expression : public rule_expression
{
	public:
		meta_expression();
		~meta_expression();
		void build(nlmsghdr* nlh);
		void parse(nlattr* attr);
		bool same_as(const meta_expression& other);		
		const char* get_name();
	private:
		nft_meta_keys meta_key;
		nft_registers dest;
		nft_registers source;
};

#endif