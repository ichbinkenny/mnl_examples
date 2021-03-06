#ifndef __LOG_EXPRESSION_H__
#define __LOG_EXPRESSION_H__

#include "../rule_expression.h"

class log_expression : public rule_expression
{
	public:
		log_expression();
		~log_expression();
		void build(nlmsghdr* p_nlh) override;
		void parse(nlattr* p_attr) override;
		bool same_as(const rule_expression& other) override;
		const char* get_name() override;	
	private:
		uint32_t snap_length;
		uint16_t group_id;
		uint16_t threshold;
		uint32_t log_level;
		const char* prefix;
};

#endif