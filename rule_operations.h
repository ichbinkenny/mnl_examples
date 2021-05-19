#ifndef __RULE_OPERATIONS_H__
#define __RULE_OPERATIONS_H__

#include <cstdint>

class rule_operations 
{
	public:
		virtual ~rule_operations() = 0;
		virtual void compose_expression(uint16_t type, const char* data, uint32_t size) = 0;

};

#endif