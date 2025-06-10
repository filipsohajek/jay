#pragma once
#include "jay/buf/struct.h"
#include "jay/ip/common.h"
#include "jay/ip/hdr_error.h"

namespace jay::ip {
struct MLDQuery : public BufStruct<MLDQuery, ICMPHeaderError> {
  using BufStruct::BufStruct;
  constexpr static const uint8_t V4_TYPE = 255;
  constexpr static const uint8_t V6_TYPE = 130;

  MLDQuery() : BufStruct<MLDQuery, ICMPHeaderError>(StructWriter({})) {};

  STRUCT_FIELD(max_resp_time, 0, uint16_t);
  STRUCT_FIELD(mcast_addr, 4, IPAddr);

  size_t size() const { return 20; }
  friend std::ostream &operator<<(std::ostream &os, const MLDQuery &msg) {
    os << "MLD query: " << IPAddr(msg.mcast_addr()) << " (max_resp_time=" << uint16_t(msg.max_resp_time()) << ")";
    return os;
  }
  static size_t size_hint() {
    return 20;
  }
};
struct MLDReport : public BufStruct<MLDReport, ICMPHeaderError> {
  using BufStruct::BufStruct;
  constexpr static const uint8_t V4_TYPE = 255;
  constexpr static const uint8_t V6_TYPE = 131;

  MLDReport() : BufStruct<MLDReport, ICMPHeaderError>(StructWriter({})) {};

  STRUCT_FIELD(mcast_addr, 4, IPAddr);

  size_t size() const { return 20; }
  friend std::ostream &operator<<(std::ostream &os, const MLDReport &msg) {
    os << "MLD report: " << IPAddr(msg.mcast_addr());
    return os;
  }
  static size_t size_hint() {
    return 20;
  }
};
struct MLDDone : public BufStruct<MLDDone, ICMPHeaderError> {
  using BufStruct::BufStruct;
  constexpr static const uint8_t V4_TYPE = 255;
  constexpr static const uint8_t V6_TYPE = 132;

  MLDDone() : BufStruct<MLDDone, ICMPHeaderError>(StructWriter({})) {};

  STRUCT_FIELD(mcast_addr, 4, IPAddr);

  size_t size() const { return 20; }
  friend std::ostream &operator<<(std::ostream &os, const MLDDone &msg) {
    os << "MLD done: " << IPAddr(msg.mcast_addr());
    return os;
  }
  static size_t size_hint() {
    return 20;
  }
};
};
