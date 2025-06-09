#pragma once

#include "jay/buf/variant_struct.h"
#include "jay/ip/v4.h"
#include "jay/ip/v6.h"
namespace jay::ip {
struct IPFragData : public std::variant<IPv4FragData, IPv6FragData>, JointStruct {
  using std::variant<IPv4FragData, IPv6FragData>::variant;
  JOINT_FIELD(identification, uint32_t);
  JOINT_FIELD(more_frags, bool);
  JOINT_FIELD(frag_offset, uint16_t);
};

struct IPRAOption : public std::variant<IPv4RAOption, IPv6RAOption>, JointStruct {
  using std::variant<IPv4RAOption, IPv6RAOption>::variant;
  JOINT_FIELD(value, uint16_t);

  size_t size() const {
    return 2;
  }
};
}
