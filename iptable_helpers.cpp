#include "iptable_helpers.h"
#include <bits/stdint-uintn.h>
#include <cstddef>
#include <cstring>
#include <linux/netlink.h>

void iptable_helpers::netlink_message_put(nlmsghdr* nlh, uint16_t type, size_t length, const void* data)
{
	nlattr* attr = reinterpret_cast<nlattr*>(get_message_payload_ending(nlh));
	uint16_t payload_size = NLMSG_ALIGN(sizeof(nlattr)) + length;
  attr->nla_type = type;
  attr->nla_len = payload_size;

  // copy data into header
  memcpy(get_attribute_payload(attr),  data, length);
  // align data
  int align = NLMSG_ALIGN(length) - length;
  if (align > 0)
  {
    (void) memset(get_attribute_payload(attr) + length, 0, align);
  }
  nlh->nlmsg_len += NLMSG_ALIGN(payload_size);
}

char* iptable_helpers::get_message_payload_ending(nlmsghdr* nlh)
{
	return reinterpret_cast<char*>(reinterpret_cast<char*>(nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
}

char* iptable_helpers::get_attribute_payload(nlattr* attr)
{
	return reinterpret_cast<char*>(reinterpret_cast<char*>(attr) + NLMSG_ALIGN(sizeof(nlattr)));
}

void iptable_helpers::put(nlmsghdr* nlh, uint16_t type, size_t length, const void* data)
{
	nlattr* attr = reinterpret_cast<nlattr*>(get_message_payload_ending(nlh));
	uint16_t payload_size = NLMSG_ALIGN(sizeof(nlattr)) + length;
  attr->nla_type = type;
  attr->nla_len = payload_size;

  // copy data into header
  memcpy(get_attribute_payload(attr),  data, length);
  // align data
  int align = NLMSG_ALIGN(length) - length;
  if (align > 0)
  {
    (void) memset(get_attribute_payload(attr) + length, 0, align);
  }
  nlh->nlmsg_len += NLMSG_ALIGN(payload_size);
}