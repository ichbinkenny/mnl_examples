#include "iptable_helpers.h"
#include <bits/stdint-uintn.h>
#include <cstddef>
#include <cstring>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <netinet/in.h>

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
  char* result = reinterpret_cast<char*>(reinterpret_cast<char*>(attr) + NLMSG_ALIGN(sizeof(nlattr)));
	return result;
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

nlattr* iptable_helpers::begin_nest(nlmsghdr* nlh, uint16_t flag)
{
  nlattr* entry = reinterpret_cast<nlattr*>(get_message_payload_ending(nlh));
  entry->nla_type = NLA_F_NESTED | flag;
  nlh->nlmsg_len += NLMSG_ALIGN(sizeof(nlattr));
  return entry;
}

void iptable_helpers::end_nest(nlmsghdr* nlh, nlattr* nest)
{
  nest->nla_len = get_message_payload_ending(nlh) - reinterpret_cast<char*>(nest);
}

message_batch* iptable_helpers::start_batch(char* buf, size_t max)
{
  message_batch* batch = new message_batch();
  batch->data_buf = buf;
  batch->max_size = max;
  batch->overfilled = false;
  batch->size = 0;
  batch->current_message = buf;
  return batch;
}

/// Returns if the message fits into the batch or not
bool iptable_helpers::batch_create_next_message(message_batch* batch)
{
  bool status = true;
  nlmsghdr* nlh = reinterpret_cast<nlmsghdr*>(batch->current_message);
  if ((batch->size + nlh->nlmsg_len) > batch->max_size)
  {
    batch->overfilled = true;
    status = false;
  }
  else
  {
    batch->current_message = batch->data_buf + batch->size + nlh->nlmsg_len;
    batch->size += nlh->nlmsg_len;
  }
  return status;
}

void iptable_helpers::create_batch_header(char* buf, uint16_t type, uint32_t seq_num)
{
    nlmsghdr* hdr;
    nfgenmsg* msg;

    hdr = put_header(buf);
    hdr->nlmsg_flags = NLM_F_REQUEST;
    hdr->nlmsg_seq = seq_num;
    hdr->nlmsg_type = type;

    msg = reinterpret_cast<nfgenmsg*>(put_aux_header(hdr, sizeof(*msg)));
    msg->nfgen_family = AF_UNSPEC;
    msg->res_id = NFNL_SUBSYS_NFTABLES;
    msg->version = NFNETLINK_V0;

}

void iptable_helpers::end_batch(message_batch* batch)
{
  delete batch;
}

nlmsghdr* iptable_helpers::create_nfnl_subsys_header(char* buf, uint16_t command, uint16_t protocol, uint16_t flags, uint32_t sequence)
{
  nlmsghdr* hdr;
  nfgenmsg* msg;

  hdr = put_header(buf);
  hdr->nlmsg_flags = NLM_F_REQUEST | flags;
  hdr->nlmsg_seq = sequence;
  hdr->nlmsg_type = (NFNL_SUBSYS_NFTABLES << 8) | command;

  msg = reinterpret_cast<nfgenmsg*>(put_aux_header(hdr, sizeof(*msg)));
  msg->nfgen_family = protocol;
  msg->version = NFNETLINK_V0;
  msg->res_id = 0;

  return hdr;
}

nlmsghdr* iptable_helpers::put_header(char* buf)
{
  nlmsghdr* hdr = reinterpret_cast<nlmsghdr*>(buf);
  int length = NLMSG_ALIGN(sizeof(nlmsghdr));
  (void) memset(buf, 0, length); // make sure to zero out the header area
  hdr->nlmsg_len = length;
  return hdr;
}

char* iptable_helpers::put_aux_header(nlmsghdr* hdr, size_t size)
{
  char* mem_offset = reinterpret_cast<char*>(hdr) + hdr->nlmsg_len; // move to end of header
  hdr->nlmsg_len += NLMSG_ALIGN(size); // update message size to include aux header
  (void) memset(mem_offset, 0 , NLMSG_ALIGN(size)); // prepare space for aux data
  return mem_offset;
}

bool iptable_helpers::nlmsg_valid(nlmsghdr* nlh, int len)
{
    bool match = len >= (int)sizeof(nlmsghdr) &&
	       nlh->nlmsg_len >= sizeof(nlmsghdr) &&
	       (int)nlh->nlmsg_len <= len;
    return match;
}

nlmsghdr* iptable_helpers::next_nlmsg(nlmsghdr* nlh, size_t* len)
{
  *len -= NLMSG_ALIGN(nlh->nlmsg_len);
  return reinterpret_cast<nlmsghdr*>(reinterpret_cast<char*>(nlh) + NLMSG_ALIGN(nlh->nlmsg_len));
}

nlattr* iptable_helpers::next_nlattr(nlattr* attr)
{
  nlattr* next = attr + NLMSG_ALIGN(attr->nla_len);
  return next;
}

char* iptable_helpers::get_payload_from_offset(nlmsghdr* nlh, size_t offset)
{
  return reinterpret_cast<char*>(nlh) + NLMSG_HDRLEN + NLMSG_ALIGN(offset);
}

bool iptable_helpers::is_attribute_valid(nlattr* attr, int length)
{
  return length >= (int)sizeof(nlattr) &&
	       attr->nla_len >= sizeof(nlattr) &&
	       (int)attr->nla_len <= length;
}

char* iptable_helpers::get_nlmsg_payload(nlmsghdr* nlh)
{
  char* ptr = reinterpret_cast<char*>(nlh) + NLMSG_HDRLEN;
  return ptr; 
}
