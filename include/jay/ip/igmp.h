#pragma once
#include "jay/buf/struct.h"
#include "jay/ip/common.h"

namespace jay::ip {
enum IGMPMessageType : uint8_t {
  MEMBER_QUERY = 0x11,
  V2_MEMBER_REPORT = 0x16,
  LEAVE_GROUP = 0x17,
  V1_MEMBER_REPORT = 0x12
};
struct IGMPHeader : public BufStruct<IGMPHeader> {
  using BufStruct::BufStruct;
  STRUCT_FIELD(type, 0, IGMPMessageType);
  STRUCT_FIELD(max_resp_time, 1, uint8_t);
  STRUCT_FIELD_LE(checksum, 2, uint16_t);
  STRUCT_FIELD(group_addr, 4, IPv4Addr);

  size_t size() const {
    return 8;
  }

  static size_t size_hint() {
    return 8;
  }
  friend std::ostream &operator<<(std::ostream &os, const IGMPHeader &hdr) {
    os << "IGMP: type=";
    switch (hdr.type()) {
      case MEMBER_QUERY:
        os << "member query";
        break;
      case V2_MEMBER_REPORT:
        os << "v2 member report";
        break;
      case LEAVE_GROUP:
        os << "leave group";
        break;
      case V1_MEMBER_REPORT:
        os << "v1 member report";
        break;
    }
    os << ", maximum response time=" << hdr.max_resp_time();
    return os;
  }
};
}
