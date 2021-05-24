#ifndef __COMPARISON_EXPRESSION_H__
#define __COMPARISON_EXPRESSION_H__

#include "../rule_expression.h"
#include <cstdint>
#include <linux/netfilter/nf_tables.h>

union data_register
{
struct {
	uint32_t value[NFT_DATA_VALUE_MAXLEN / sizeof(uint32_t)];
	uint32_t length;
};

struct {
	int verdict;
	const char* chain;
};
};

class comparison_expression : public rule_expression
{
	public:
		comparison_expression();
		comparison_expression(nft_registers reg, nft_cmp_ops operation, const void* p_data, uint32_t data_length);
		~comparison_expression();
		void build(nlmsghdr* nlh);
		void parse(nlattr* attr);
		bool same_as(const comparison_expression& other);
		const char* get_name();
	private:
		data_register data;
		nft_cmp_ops operation;
		nft_registers source;
};

#endif