#ifndef __IPTABLE_RULE__
#define __IPTABLE_RULE__

#include "rule_expression.h"
#include <vector>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nf_tables.h>
#include <cstdint>
#include <string>
#include <memory>

enum expression_payload_flags
{
	PAYLOAD_BASE,
	PAYLOAD_DEST_REG,
	PAYLOAD_SOURCE_REG,
	PAYLOAD_OFFSET,
	PAYLOAD_LENGTH,
	PAYLOAD_CSUM_TYPE,
	PAYLOAD_CSUM_OFFSET,
	PAYLOAD_CSUM_FLAGS,
};

enum netfilter_regs
{
	VERDICT,
	REGISTER_1,
	REGISTER_2,
	REGISTER_3,
	REGISTER_4,
};

enum layer_bases
{
	LinkLayer,
	NetworkLayer,
	TransportLayer,
};

// struct payload_expression 
// {
// 	netfilter_regs source;
// 	netfilter_regs dest;
// 	layer_bases layer;
// 	uint32_t offset;
// 	uint32_t length;
// 	uint32_t sum_type;
// 	uint32_t sum_offset;
// 	uint32_t sum_flags;
// };

class iptable_rule 
{
public:
	iptable_rule();
	virtual ~iptable_rule();
	void set_data(uint16_t attribute, void* data, uint32_t data_length);
	void test();
	char* get_message_payload_ending(nlmsghdr* nlh);
	void build_nlmsg_payload(nlmsghdr* nlh);
	void add_expression(rule_expression& expr);

private:

	std::string table;
	std::string chain;
	uint32_t flags;
	uint32_t family;
	uint64_t handle;
	uint64_t position;
	struct {
		void* data;
		uint32_t length;
	} user;
	struct {
		uint32_t flags;
		uint32_t protocol;
	} compatability;

	std::vector<rule_expression> expression_list;

	nlattr* begin_nest(nlmsghdr* nlh, uint16_t flag);
	void end_nest(nlmsghdr* nlh, nlattr* nest);
	void package_expression(nlmsghdr* nlh, rule_expression& re);
	void create_expression_payload(nlmsghdr* nlh, rule_expression& expr);
};


#endif