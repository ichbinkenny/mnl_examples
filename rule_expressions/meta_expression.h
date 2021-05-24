#ifndef __META_EXPRESSION_H__
#define __META_EXPRESSION_H__

#include "../rule_expression.h"
#include <linux/netfilter/nf_tables.h>

class meta_expression : public rule_expression
{
	public:
		meta_expression();
		meta_expression(nft_meta_keys key, nft_registers dest) :
		meta_key(key),
		dest(dest) { name = "meta"; flags = (1 << NFTA_META_KEY) | (1 << NFTA_META_DREG); };
		meta_expression(nft_meta_keys key, nft_registers dest, nft_registers source) : 
		meta_key(key),
		dest(dest),
		source(source) { name = "meta"; flags = (1 << NFTA_META_KEY) | (1 << NFTA_META_SREG) | (1 << NFTA_META_DREG);};
		~meta_expression();
		void build(nlmsghdr* nlh);
		void parse(nlattr* attr);
		bool same_as(const rule_expression& other);		
		const char* get_name();
	private:
		nft_meta_keys meta_key;
		nft_registers dest;
		nft_registers source;
};

#endif