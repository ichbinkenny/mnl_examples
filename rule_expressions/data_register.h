#ifndef __DATA_REGISTER_H__
#define __DATA_REGISTER_H__

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

#endif