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
		length(length){ flags = (1 << NFTA_PAYLOAD_BASE) | (1 << NFTA_PAYLOAD_DREG) | (1 << NFTA_PAYLOAD_OFFSET) | (1 << NFTA_PAYLOAD_LEN); length = 0; name = "payload";};
		~payload_expression();
		void build(nlmsghdr* p_nlh) ;
		void parse(nlattr* p_attr) ;
		bool same_as(const rule_expression& other);
		const char* get_name() ;
		void set_flags(uint32_t flags);
		void add_flags(uint32_t flags);
		void set_data(uint16_t type, const char* data, uint32_t length);
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