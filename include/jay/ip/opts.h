#pragma once

#include "jay/buf/variant_struct.h"
#include "jay/ip/v4.h"
namespace jay::ip {
struct IPFragData : public std::variant<IPv4FragData>, JointStruct {
  using std::variant<IPv4FragData>::variant;
  JOINT_FIELD(identification, uint32_t);
  JOINT_FIELD(dont_frag, bool);
  JOINT_FIELD(more_frags, bool);
  JOINT_FIELD(frag_offset, uint16_t);
};

struct IPRAOption : public std::variant<IPv4RAOption>, JointStruct {
  using std::variant<IPv4RAOption>::variant;
  JOINT_FIELD(value, uint16_t);
};
}
