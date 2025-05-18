#pragma once

#include "jay/buf/struct.h"
#include <ostream>
namespace jay::ip {
template<typename TMsg> 
struct ICMPv4TypeAccessor {
  constexpr static const uint8_t TAG = TMsg::V4_TYPE;
};

struct ICMPEchoRequestMessage : public BufStruct<ICMPEchoRequestMessage> {
  using BufStruct::BufStruct;
  constexpr static const uint8_t V4_TYPE = 8;
  ICMPEchoRequestMessage() : BufStruct<ICMPEchoRequestMessage>(StructWriter({})) {};
  STRUCT_FIELD(ident, 0, uint16_t);
  STRUCT_FIELD(seq_num, 2, uint16_t);
  size_t size() const { return 4; }
  friend std::ostream &operator<<(std::ostream &os, const ICMPEchoRequestMessage &addr) {
    os << "Echo request (ident=" << uint16_t(addr.ident()) << ", seq_num=" << uint16_t(addr.seq_num()) << ")";
    return os;
  }
};

struct ICMPEchoReplyMessage : public BufStruct<ICMPEchoReplyMessage> {
  using BufStruct::BufStruct;
  constexpr static const uint8_t V4_TYPE = 0;
  ICMPEchoReplyMessage() : BufStruct<ICMPEchoReplyMessage>(StructWriter({})) {};

  STRUCT_FIELD(ident, 0, uint16_t);
  STRUCT_FIELD(seq_num, 2, uint16_t);
  size_t size() const { return 4; }
  friend std::ostream &operator<<(std::ostream &os, const ICMPEchoReplyMessage &addr) {
    os << "Echo reply (ident=" << uint16_t(addr.ident()) << ", seq_num=" << uint16_t(addr.seq_num()) << ")";
    return os;
  }
};
}
