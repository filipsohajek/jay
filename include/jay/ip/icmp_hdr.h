#pragma once

#include "jay/buf/struct.h"
#include "jay/ip/common.h"
#include "jay/ip/hdr_error.h"
#include "jay/ip/icmp_msg.h"
#include "jay/ip/mld.h"
#include "jay/ip/ndp.h"

namespace jay::ip {
struct ICMPv4HeaderTag {};
struct ICMPv6HeaderTag {};
struct ICMPHeader : public std::variant<ICMPv4HeaderTag, ICMPv6HeaderTag>,
                    BufStruct<ICMPHeader> {
  using std::variant<ICMPv4HeaderTag, ICMPv6HeaderTag>::variant;
  using BufStruct<ICMPHeader>::BufStruct;
  using ErrorType = ICMPHeaderError;

private:
  ICMPHeader(IPVersion ver, StructWriter cur)
      : std::variant<ICMPv4HeaderTag, ICMPv6HeaderTag>(),
        BufStruct<ICMPHeader>(cur) {
    if (ver == IPVersion::V4)
      this->emplace<ICMPv4HeaderTag>();
    else
      this->emplace<ICMPv6HeaderTag>();
  }

public:
  STRUCT_FIELD_LE(checksum, 2, uint16_t);

private:
  STRUCT_FIELD(type, 0, uint8_t);
  STRUCT_FIELD(_code, 1, uint8_t);
  template <template <typename> typename Accessor> auto message_field() const {
    return TaggedUnionField<decltype(type()), Accessor, ICMPEchoRequestMessage,
                            ICMPEchoReplyMessage, ICMPTimeExceededMessage,
                            ICMPDestinationUnreachableMessage, MLDQuery,
                            MLDReport, MLDDone, NDPRouterSolicitation,
                            NDPRouterAdvertisement, NDPNeighborSolicitation,
                            NDPNeighborAdvertisement>{cur.span().subspan(4),
                                                      type()};
  }

public:
  auto message() {
    if (std::holds_alternative<ICMPv4HeaderTag>(*this)) {
      return message_field<ICMPv4TypeAccessor>().variant();
    } else {
      return message_field<ICMPv6TypeAccessor>().variant();
    }
  }

  ICMPCode code() const { return {_code(), ver()}; }

  template <typename TMsg, typename TCode = uint8_t, typename... CArgT>
  static size_t size_hint(IPVersion, TMsg &, TCode = 0,
                          CArgT &&...constr_args) {
    return 4 + TMsg::size_hint(std::forward<CArgT>(constr_args)...);
  }

  static Result<ICMPHeader, ICMPHeaderError> read(StructWriter cur,
                                                  IPVersion ver) {
    if (cur.size() < 4)
      return ResultError(ICMPHeaderError::OUT_OF_BOUNDS);
    ICMPHeader hdr(ver, cur);
    if (cur.size() < hdr.size())
      return ResultError(ICMPHeaderError::OUT_OF_BOUNDS);

    return hdr;
  }

  static size_t size_hint() { return 4; }

  template <typename TMsg, typename TCode = uint8_t, typename... CArgT>
  static Result<ICMPHeader, ICMPHeaderError>
  construct(StructWriter cur, IPVersion ver, TMsg &message, TCode code = 0,
            CArgT &&...constr_args) {
    ICMPHeader hdr(ver, cur);
    if (cur.size() < 4)
      return ResultError(ICMPHeaderError::OUT_OF_BOUNDS);
    cur.slice(0, 4).reset();
    hdr._code() = ICMPCode(code, ver).code;
    if (ver == IPVersion::V4) {
      auto msg_res = hdr.message_field<ICMPv4TypeAccessor>().set<TMsg>(
          std::forward<CArgT>(constr_args)...);
      if (msg_res.has_value())
        message = msg_res.value();
      else
        return ResultError(msg_res.error());
    } else {
      auto msg_res = hdr.message_field<ICMPv6TypeAccessor>().set<TMsg>(
          std::forward<CArgT>(constr_args)...);
      if (msg_res.has_value())
        message = msg_res.value();
      else
        return ResultError(msg_res.error());
    }
    return hdr;
  }

  size_t size() const {
    if (std::holds_alternative<ICMPv4HeaderTag>(*this)) {
      return 4 + message_field<ICMPv4TypeAccessor>().size();
    } else {
      return 4 + message_field<ICMPv6TypeAccessor>().size();
    }
  }

  bool is_v4() const { return std::holds_alternative<ICMPv4HeaderTag>(*this); }
  bool is_v6() const { return std::holds_alternative<ICMPv6HeaderTag>(*this); }
  IPVersion ver() const {
    return std::holds_alternative<ICMPv4HeaderTag>(*this) ? IPVersion::V4
                                                          : IPVersion::V6;
  }

  friend std::ostream &operator<<(std::ostream &os, ICMPHeader &addr) {
    os << "ICMP: version=" << (addr.is_v4() ? 4 : 6) << ", message=";
    std::visit(
        [&](auto msg) {
          if constexpr (std::is_same_v<decltype(msg), std::monostate>) {
            os << "unknown";
          } else {
            os << msg;
          }
        },
        addr.message());

    return os;
  }
};
} // namespace jay::ip
