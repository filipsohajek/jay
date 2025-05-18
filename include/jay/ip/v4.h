#pragma once

#include "jay/buf/struct.h"
#include "jay/ip/common.h"
#include "jay/ip/hdr_error.h"
namespace jay::ip {
struct IPv4FragData : public BufStruct<IPv4FragData> {
  using BufStruct::BufStruct;
  STRUCT_FIELD(identification, 0, uint16_t);
  STRUCT_BITFIELD(dont_frag, 17, 1, bool);
  STRUCT_BITFIELD(more_frags, 18, 1, bool);
  STRUCT_BITFIELD_MULT(frag_offset, 19, 13, uint16_t, 8);

  IPv4FragData() : BufStruct<IPv4FragData>(StructWriter({})) {}

  size_t size() const {
    return 4;
  }
};

struct IPv4RAOption : public BufStruct<IPv4RAOption> {
  using BufStruct::BufStruct;
  static const uint8_t UNION_TAG = 0x94;
  IPv4RAOption() : BufStruct<IPv4RAOption>(StructWriter({})) {}

  STRUCT_FIELD(value, 0, uint16_t);

  size_t size() const {
    return 2;
  }
};

struct IPv4UnknownOption : public BufStruct<IPv4UnknownOption> {
  using BufStruct::BufStruct;
  size_t size() const {
    return 0;
  }
};

struct IPv4Option : public BufStruct<IPv4Option> {
  using BufStruct::BufStruct;
  STRUCT_BITFIELD(copied, 1, 1, bool);
  STRUCT_BITFIELD(type, 3, 5, uint8_t);
  STRUCT_FIELD(length, 1, uint8_t);
  STRUCT_TAGGED_UNION(option, 2, type(), IPv4RAOption);
  
  size_t size() const {
    return 2 + length();
  }
};

struct IPFragData;
struct IPRAOption;
struct IPHeader;
struct IPv4Header : public BufStruct<IPv4Header> {
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
  using ErrorType = IPHeaderError;

  static Result<IPv4Header, ErrorType> read(StructWriter cur) {
    IPv4Header hdr{cur};
    if (cur.size() < 4*hdr.ihl())
      return ResultError(IPHeaderError::OUT_OF_BOUNDS);
    cur = cur.span().subspan(0, 4*hdr.ihl());
    hdr.cur = cur;
    if (inet_csum(cur.span()) != 0)
      return ResultError(IPHeaderError::CHECKSUM_ERROR);
    if (hdr.version() != IPVersion::V4)
      return ResultError(IPHeaderError::BAD_VERSION);
    return hdr;
  }

  template<typename ...CArgT>
  static Result<IPv4Header, ErrorType> construct(StructWriter cur, CArgT&& ...args) {
    size_t total_size = size_hint(std::forward<CArgT>(args)...).value();
    cur = cur.span().subspan(0, total_size);
    IPv4Header hdr{cur};
    if (cur.size() != total_size)
      return ResultError(IPHeaderError::OUT_OF_BOUNDS);
    cur.slice(0, MIN_SIZE).reset();
    hdr.version() = IPVersion::V4; 
    hdr.ihl() = cur.span().size() / 4;
    
    std::optional<IPv4Header::ErrorType> error;
    ([&](CArgT arg) {
      if constexpr (std::is_same_v<decltype(arg), IPFragData&>) {
        arg = hdr.frag_data().construct().value();
      } else if constexpr (std::is_same_v<decltype(arg), IPRAOption&>) {
        IPv4Option first_opt = (*hdr.options().begin()).construct().value();
        arg = first_opt.option().set<IPv4RAOption>();
      } else if constexpr (std::is_same_v<std::decay_t<decltype(arg)>, IPHeader>) {
        if (!arg.is_v4()) {
          error = IPHeaderError::BAD_VERSION;
          return;
        }
        IPv4Header v4_hdr = arg.v4();
        if (v4_hdr.options().begin() != v4_hdr.options().end()) {
          error = IPHeaderError::CANNOT_COPY_OPTION; 
          return;
        }
        std::ranges::copy(v4_hdr.cursor().span(), cur.span().begin());
        
        hdr.total_len() = 0;
        hdr.hdr_csum() = 0;
        IPv4FragData frag_data = hdr.frag_data().read().value();
        frag_data.identification() = 0;
        frag_data.frag_offset() = 0;
        frag_data.more_frags() = false;
      } else {
        static_assert(DependentFalse_v<decltype(arg)>, "unknown construction argument for an IPv4 header");
      }
    }(std::forward<CArgT>(args)), ...);
  
    if (error.has_value())
      return ResultError(error.value());
    return hdr;
  }

  void copy_to(IPv4Header& dest) const {
    std::ranges::copy(cur.span().subspan(0, size()), dest.cur.span().begin());
  }

  size_t size() const {
    return 4*ihl();
  }

  uint32_t pseudohdr_sum() const {
    return IPv4Addr(src_addr()).csum() + IPv4Addr(dst_addr()).csum() + uint32_t(IPProto(proto())) + uint16_t(total_len_le() - size()); 
  }

  template<typename ...CArgT>
  static Result<size_t, ErrorType> size_hint(CArgT&&... args) {
    size_t unaligned_size = MIN_SIZE;
    std::optional<IPv4Header::ErrorType> error;
    ([&](CArgT arg) {
      if constexpr (std::is_same_v<decltype(arg), IPFragData&>) {
        unaligned_size += 0;
      } else if constexpr (std::is_same_v<decltype(arg), IPRAOption&>) {
        unaligned_size += 4;
      } else if constexpr (std::is_same_v<std::decay_t<decltype(arg)>, IPHeader>){
        if (!arg.is_v4()) {
          error = IPHeaderError::BAD_VERSION;
          return;
        }
        IPv4Header v4_hdr = arg.v4();
        unaligned_size = v4_hdr.size();
        if (v4_hdr.options().begin() != v4_hdr.options().end()) {
          error = IPHeaderError::CANNOT_COPY_OPTION; 
        }
      } else {
        static_assert(DependentFalse_v<decltype(arg)>, "unknown construction argument for an IPv4 header");
      }
    }(std::forward<CArgT>(args)), ...);
    if (error.has_value())
      return ResultError(error.value());
    return 4 * ((unaligned_size + 3) / 4);
  }
};
}
