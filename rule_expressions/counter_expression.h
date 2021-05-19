#ifndef __COUNTER_EXPRESSION_H__
#define __COUNTER_EXPRESSION_H__
#include "../rule_expression.h"
#include <cstdint>

class counter_expression : public rule_expression
{
	public:
		counter_expression();
		~counter_expression();
		void build(nlmsghdr* p_nlh);
		void parse(nlattr* p_attr);
		bool same_as(const counter_expression& other);
		const char* get_name();
	protected:
	private:
		uint64_t packet_count;
		uint64_t bytes_count;
};

#endif