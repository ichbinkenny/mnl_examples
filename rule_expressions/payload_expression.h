#ifndef __PAYLOAD_EXPRESSION_H__
#define __PAYLOAD_EXPRESSION_H__

#include "../rule_expression.h"
#include "log_expression.h"
#include <cstdint>
#include <linux/netfilter/nf_tables.h>

class payload_expression :  public rule_expression
{
	public:
		payload_expression();
		payload_expression(nft_payload_bases base, nft_registers dest, uint32_t offset, uint32_t length) : 
		base(base),
		dest(dest),
		offset(offset),
		length(length){ payload_expression();};
		~payload_expression();
		void build(nlmsghdr* p_nlh) override;
		void parse(nlattr* p_attr) override;
		bool same_as(const payload_expression& other);
		const char* get_name() override;
		void set_flags(uint32_t flags);
		void add_flags(uint32_t flags);
	private:
		nft_registers source;
		nft_registers dest;
		nft_payload_bases base;
		uint32_t offset;
		uint32_t length;
		uint32_t csum_type;
		uint32_t csum_offset;
		uint32_t csum_flags;
};

#endif