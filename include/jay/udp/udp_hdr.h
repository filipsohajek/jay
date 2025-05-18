#pragma once

#include "jay/buf/struct.h"
#include <ostream>
namespace jay::udp {
struct UDPHeader : public BufStruct<UDPHeader> {
  using BufStruct::BufStruct;

  STRUCT_FIELD(src_port, 0, uint16_t);
  STRUCT_FIELD(dst_port, 2, uint16_t);
  STRUCT_FIELD(length, 4, uint16_t);
  STRUCT_FIELD_LE(checksum, 6, uint16_t);

  size_t size() const {
    return 8;
  }

  static size_t size_hint() {
    return 8;
  }

  friend std::ostream &operator<<(std::ostream &os, const UDPHeader &addr) {
    os << "UDP: src_port=" << uint16_t(addr.src_port()) << ", dst_port=" << uint16_t(addr.dst_port());
    return os;
  }
};
};
