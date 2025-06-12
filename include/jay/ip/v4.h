#pragma once

#include "jay/buf/struct.h"
#include "jay/ip/common.h"
#include "jay/ip/hdr_error.h"
namespace jay::ip {
struct IPv4FragData : public BufStruct<IPv4FragData, IPHeaderError> {
  using BufStruct::BufStruct;
  STRUCT_FIELD(identification, 0, uint16_t);
  STRUCT_BITFIELD(dont_frag, 17, 1, bool);
  STRUCT_BITFIELD(more_frags, 18, 1, bool);
  STRUCT_BITFIELD_MULT(frag_offset, 19, 13, uint16_t, 8);

  IPv4FragData() : BufStruct<IPv4FragData, IPHeaderError>(StructWriter({})) {}

  size_t size() const {
    return 4;
  }

  static size_t size_hint() {
    return 4;
  }
};

struct IPv4RAOption : public BufStruct<IPv4RAOption, IPHeaderError> {
  using BufStruct::BufStruct;
  static const uint8_t UNION_TAG = 0x14;
  IPv4RAOption() : BufStruct<IPv4RAOption, IPHeaderError>(StructWriter({})) {}

  STRUCT_FIELD(value, 0, uint16_t);

  size_t size() const {
    return 2;
  }

  static size_t size_hint() {
    return 2;
  }
};

struct IPv4Option : public BufStruct<IPv4Option, IPHeaderError> {
  using BufStruct::BufStruct;
  STRUCT_BITFIELD(copied, 0, 1, bool);
  STRUCT_BITFIELD(type, 3, 5, uint8_t);
  STRUCT_FIELD(length, 1, uint8_t);
  STRUCT_TAGGED_UNION(option, 2, type(), IPv4RAOption);
  
  static Result<IPv4Option, IPHeaderError> read(StructWriter cur) { 
    auto strct = IPv4Option {cur};
    if (2 > cur.size())
      return ResultError{IPHeaderError::OUT_OF_BOUNDS};
    if (strct.size() > cur.size())
      return ResultError{IPHeaderError::OUT_OF_BOUNDS};
    return strct;
  }

  static Result<IPv4Option, IPHeaderError> construct(StructWriter cur) { 
    auto strct = IPv4Option {cur};
    if (2 > cur.size())
      return ResultError{IPHeaderError::OUT_OF_BOUNDS};
    strct.length() = 2;
    strct.type() = 0;
    strct.copied() = false;

    return strct;
  }

  size_t size() const {
    return 2 + option().size();
  }

  static size_t size_hint() {
    return 2;
  }
};

struct IPFragData;
struct IPRAOption;
struct IPHeader;
struct IPv4Header : public BufStruct<IPv4Header, IPHeaderError> {
  using BufStruct::BufStruct;
  static const size_t MIN_SIZE = 20;
  STRUCT_BITFIELD(version, 0, 4, IPVersion);
  STRUCT_BITFIELD(ihl, 4, 4, size_t);
  STRUCT_BITFIELD(dscp, 8, 6, uint8_t);
  STRUCT_BITFIELD(ecn, 14, 2, uint8_t);
  STRUCT_FIELD(total_len, 2, uint16_t);
private:
  STRUCT_FIELD_LE(total_len_le, 2, uint16_t);
public:
  STRUCT_FIELD(frag_data, 4, IPv4FragData);
  STRUCT_FIELD(ttl, 8, uint8_t);
  STRUCT_FIELD(proto, 9, IPProto);
  STRUCT_FIELD_LE(hdr_csum, 10, uint16_t);
  STRUCT_FIELD(src_addr, 12, IPv4Addr);
  STRUCT_FIELD(dst_addr, 16, IPv4Addr);
  STRUCT_VARARRAY(options, 20, IPv4Option);
public:
  static Result<IPv4Header, ErrorType> read(StructWriter cur);
  static size_t size_hint(size_t opts_size);
  static size_t size_hint(IPHeader& base_hdr, IPFragData* = nullptr);
  static size_t size_hint(IPProto, IPRAOption* = nullptr);
  static Result<IPv4Header, ErrorType> construct(StructWriter cur, size_t opts_size);
  static Result<IPv4Header, ErrorType> construct(StructWriter cur, IPHeader& base_hdr, IPFragData* = nullptr);
  static Result<IPv4Header, ErrorType> construct(StructWriter cur, IPProto, IPRAOption* = nullptr);

  size_t size() const {
    return 4*ihl();
  }

  static size_t size_hint() {
    return MIN_SIZE;
  }
};
}
