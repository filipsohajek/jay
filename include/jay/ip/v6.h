#pragma once

#include "jay/buf/struct.h"
#include "jay/ip/common.h"
#include "jay/ip/hdr_error.h"
namespace jay::ip {

struct IPv6FragData : public BufStruct<IPv6FragData> {
  static const uint8_t NH_TYPE = 44;
  using BufStruct::BufStruct;
  STRUCT_FIELD(next_header, 0, uint8_t);
  STRUCT_BITFIELD_MULT(frag_offset, 16, 13, uint16_t, 8);
  STRUCT_BITFIELD(more_frags, 31, 1, bool);
  STRUCT_FIELD(identification, 4, uint32_t);

  size_t size() const { return 8; }

  static size_t size_hint() { return 8; }
};

struct IPv6RAOption : public BufStruct<IPv6RAOption> {
  using BufStruct::BufStruct;
  static const uint8_t UNION_TAG = 0x5;
  STRUCT_FIELD(value, 0, uint16_t);

  size_t size() const { return 2; }
};

struct IPv6HBHOption : public BufStruct<IPv6HBHOption> {
  using BufStruct::BufStruct;
  STRUCT_FIELD(type, 0, uint8_t);
  STRUCT_FIELD(data_len, 1, uint8_t);
  STRUCT_TAGGED_UNION(data, 2, type(), IPv6RAOption);

  size_t size() const { return 2 + data_len(); }
};

struct IPv6HBHOptions : public BufStruct<IPv6HBHOptions> {
  static const uint8_t NH_TYPE = 0;
  using BufStruct::BufStruct;
  STRUCT_FIELD(next_header, 0, uint8_t);
  STRUCT_BITFIELD_MULT(hdr_len, 8, 8, uint8_t, 8);
  STRUCT_VARARRAY(options, 2, IPv6HBHOption);

  size_t size() const { return 8 + hdr_len(); }
};

struct IPFragData;
struct IPRAOption;
struct IPHeader;
struct IPv6Header : public BufStruct<IPv6Header> {
  using BufStruct::BufStruct;
  static const size_t MIN_SIZE = 40;

  STRUCT_BITFIELD(version, 0, 4, IPVersion);
  STRUCT_BITFIELD(dscp, 4, 6, uint8_t);
  STRUCT_BITFIELD(ecn, 10, 2, uint8_t);
  STRUCT_BITFIELD(flow_label, 12, 20, uint8_t);
  STRUCT_FIELD(payload_len, 4, uint16_t);
  STRUCT_FIELD(next_header, 6, uint8_t);
  STRUCT_FIELD(ttl, 7, uint8_t);
  STRUCT_FIELD(src_addr, 8, IPAddr);
  STRUCT_FIELD(dst_addr, 24, IPAddr);

  using ErrorType = IPHeaderError;

  struct ExtHdrIterator {
    struct EndSentinel {};
    using value_type =
        std::variant<std::monostate, IPv6HBHOptions, IPv6FragData>;

    value_type operator*() {
      switch (next_header) {
      case IPv6HBHOptions::NH_TYPE:
        return IPv6HBHOptions::read(cur).value_or<value_type>(std::monostate());
      case IPv6FragData::NH_TYPE:
        return IPv6FragData::read(cur).value_or<value_type>(std::monostate());
      default:
        return std::monostate();
      }
    }

    ExtHdrIterator &operator++() {
      value_type cur_header = **this;
      if (!cur_header.index())
        return *this;
      next_header = std::visit(
          [](auto &hdr) {
            if constexpr (std::is_same_v<std::decay_t<decltype(hdr)>,
                                         std::monostate>)
              return uint8_t(0);
            else
              return uint8_t(hdr.next_header());
          },
          cur_header);
      return *this;
    }

    ExtHdrIterator operator++(int) {
      auto iter = *this;
      ++(*this);
      return iter;
    }

    bool operator==(const EndSentinel &) { return (**this).index() == 0; }

    StructWriter cur;
    uint8_t next_header;
  };

  ExtHdrIterator exthdr_begin() const {
    return ExtHdrIterator{cur.slice(MIN_SIZE), next_header()};
  }

  ExtHdrIterator exthdr_last() const {
    auto it = exthdr_begin();
    for (; it != exthdr_end(); it++)
      ;
    return it;
  }

  ExtHdrIterator::EndSentinel exthdr_end() const { return {}; }

  static Result<IPv6Header, ErrorType> read(StructWriter cur);
  static size_t size_hint(size_t exthdr_size);
  static Result<IPv6Header, ErrorType> construct(StructWriter cur,
                                                 size_t exthdr_size);
  static size_t size_hint(IPHeader & base_hdr, IPFragData* = nullptr);
  static Result<IPv6Header, ErrorType>
  construct(StructWriter cur, IPHeader &base_hdr, IPFragData* = nullptr);

  static size_t size_hint(IPProto, IPRAOption* = nullptr);
  static Result<IPv6Header, ErrorType>
  construct(StructWriter cur, IPProto proto, IPRAOption* = nullptr);

  size_t exthdr_size() const {
    StructWriter first_cur = exthdr_begin().cur;
    StructWriter last_cur = exthdr_last().cur;

    return last_cur.span().data() - first_cur.span().data();
  }
  
  size_t size() const { return MIN_SIZE + exthdr_size(); }
};
} // namespace jay::ip
