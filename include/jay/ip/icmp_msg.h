#pragma once

#include "jay/buf/struct.h"
#include "jay/ip/common.h"
#include "jay/ip/hdr_error.h"
#include <ostream>
namespace jay::ip {
template<typename TMsg> 
struct ICMPv4TypeAccessor {
  constexpr static const uint8_t TAG = TMsg::V4_TYPE;
};
template<typename TMsg> 
struct ICMPv6TypeAccessor {
  constexpr static const uint8_t TAG = TMsg::V6_TYPE;
};

enum class TimeExceededType : uint8_t {
  HOP_LIMIT = 0,
  REASSEMBLY = 1
};

enum class UnreachableReason : uint8_t {
  NETWORK_UNREACHABLE,
  HOST_UNREACHABLE,
  PORT_UNREACHABLE,
  PACKET_TOO_BIG
};

struct ICMPCode {
  ICMPCode(uint8_t code, IPVersion ver) : code(code), ip_ver(ver) {}
  ICMPCode(TimeExceededType timex_code, IPVersion ver) : ip_ver(ver) {
    code = static_cast<uint8_t>(timex_code);
  }

  ICMPCode(UnreachableReason unreach_code, IPVersion ver) : ip_ver(ver) {
    switch (unreach_code) {
      case UnreachableReason::NETWORK_UNREACHABLE:
        code = (ver == IPVersion::V4) ? 0 : 0;
        break;
      case UnreachableReason::HOST_UNREACHABLE:
        code = (ver == IPVersion::V4) ? 1 : 3;
        break;
      case UnreachableReason::PORT_UNREACHABLE:
        code = (ver == IPVersion::V4) ? 3 : 4;
        break;
      case UnreachableReason::PACKET_TOO_BIG:
        code = 4;
        break;
      default:
        code = static_cast<uint8_t>(unreach_code);
    }
  }

  operator TimeExceededType() {
    return TimeExceededType(code);
  }
  operator UnreachableReason() {
    if (ip_ver == IPVersion::V4) {
      switch (code) {
        case 0:
          return UnreachableReason::NETWORK_UNREACHABLE;
        case 1:
          return UnreachableReason::HOST_UNREACHABLE;
        case 3:
          return UnreachableReason::PORT_UNREACHABLE;
        case 4:
          return UnreachableReason::PACKET_TOO_BIG;
      }
    } else {
      switch (code) {
        case 0:
          return UnreachableReason::NETWORK_UNREACHABLE;
        case 3:
          return UnreachableReason::HOST_UNREACHABLE;
        case 4:
          return UnreachableReason::PORT_UNREACHABLE;
      }
    }
    return static_cast<UnreachableReason>(code);
  }
  uint8_t code;
  IPVersion ip_ver;
};

struct ICMPEchoRequestMessage : public BufStruct<ICMPEchoRequestMessage, ICMPHeaderError> {
  using BufStruct::BufStruct;
  constexpr static const uint8_t V4_TYPE = 8;
  constexpr static const uint8_t V6_TYPE = 0x80;
  ICMPEchoRequestMessage() : BufStruct<ICMPEchoRequestMessage, ICMPHeaderError>(StructWriter({})) {};
  STRUCT_FIELD(ident, 0, uint16_t);
  STRUCT_FIELD(seq_num, 2, uint16_t);
  size_t size() const { return 4; }
  friend std::ostream &operator<<(std::ostream &os, const ICMPEchoRequestMessage &addr) {
    os << "Echo request (ident=" << uint16_t(addr.ident()) << ", seq_num=" << uint16_t(addr.seq_num()) << ")";
    return os;
  }
  
  static size_t size_hint() {
    return 4;
  }
};

struct ICMPEchoReplyMessage : public BufStruct<ICMPEchoReplyMessage, ICMPHeaderError> {
  using BufStruct::BufStruct;
  constexpr static const uint8_t V4_TYPE = 0;
  constexpr static const uint8_t V6_TYPE = 0x81;
  ICMPEchoReplyMessage() : BufStruct<ICMPEchoReplyMessage, ICMPHeaderError>(StructWriter({})) {};

  STRUCT_FIELD(ident, 0, uint16_t);
  STRUCT_FIELD(seq_num, 2, uint16_t);
  size_t size() const { return 4; }
  friend std::ostream &operator<<(std::ostream &os, const ICMPEchoReplyMessage &addr) {
    os << "Echo reply (ident=" << uint16_t(addr.ident()) << ", seq_num=" << uint16_t(addr.seq_num()) << ")";
    return os;
  }
  static size_t size_hint() {
    return 4;
  }
};


struct ICMPTimeExceededMessage : public BufStruct<ICMPTimeExceededMessage, ICMPHeaderError> {
  using BufStruct::BufStruct;
  constexpr static const uint8_t V4_TYPE = 11;
  constexpr static const uint8_t V6_TYPE = 0x3;
  ICMPTimeExceededMessage() : BufStruct<ICMPTimeExceededMessage, ICMPHeaderError>(StructWriter({})) {};

  STRUCT_FIELD(_unused, 0, uint32_t);
  size_t size() const {
    return 4;
  }

  friend std::ostream& operator<<(std::ostream& os, const ICMPTimeExceededMessage&) {
    os << "Time exceeded";
    return os;
  }
  static size_t size_hint() {
    return 4;
  }
};

struct ICMPDestinationUnreachableMessage : public BufStruct<ICMPDestinationUnreachableMessage, ICMPHeaderError> {
  using BufStruct::BufStruct;
  constexpr static const uint8_t V4_TYPE = 3;
  constexpr static const uint8_t V6_TYPE = 0x1;
  ICMPDestinationUnreachableMessage() : BufStruct<ICMPDestinationUnreachableMessage, ICMPHeaderError>(StructWriter({})) {};

  STRUCT_FIELD(_unused, 0, uint32_t);
  size_t size() const {
    return 4;
  }

  friend std::ostream& operator<<(std::ostream& os, const ICMPDestinationUnreachableMessage&) {
    os << "Time exceeded";
    return os;
  }
  static size_t size_hint() {
    return 4;
  }
};
}
