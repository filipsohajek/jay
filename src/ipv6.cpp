#include "jay/ip/ip_hdr.h"
#include "jay/ip/opts.h"
#include "jay/ip/v6.h"

namespace jay::ip {
const uint8_t IPv6HBHOptions::NH_TYPE;
const uint8_t IPv6FragData::NH_TYPE;

Result<IPv6Header, IPv6Header::ErrorType> IPv6Header::read(StructWriter cur) {
  IPv6Header hdr{cur};
  if (cur.size() < MIN_SIZE)
    return ResultError(IPHeaderError::OUT_OF_BOUNDS);
  if (cur.size() < hdr.size())
    return ResultError(IPHeaderError::OUT_OF_BOUNDS);
  hdr.cur = cur.span().subspan(0, hdr.size());
  if (hdr.version() != IPVersion::V6)
    return ResultError(IPHeaderError::BAD_VERSION);
  return hdr;
}

Result<size_t, IPv6Header::ErrorType>
IPv6Header::size_hint(size_t exthdr_size) {
  return MIN_SIZE + exthdr_size;
}

Result<IPv6Header, IPv6Header::ErrorType>
IPv6Header::construct(StructWriter cur, size_t exthdr_size) {
  size_t total_size = size_hint(exthdr_size).value();
  cur = cur.span().subspan(0, total_size);
  IPv6Header hdr{cur};
  if (cur.size() != total_size)
    return ResultError(IPHeaderError::OUT_OF_BOUNDS);
  cur.slice(0, MIN_SIZE).reset();
  hdr.version() = IPVersion::V6;

  return hdr;
}

Result<size_t, IPv6Header::ErrorType>
IPv6Header::size_hint(IPHeader &, IPFragData *frag_data) {
  return MIN_SIZE + (frag_data ? IPv6FragData::size_hint() : 0);
}

Result<IPv6Header, IPv6Header::ErrorType>
IPv6Header::construct(StructWriter cur, IPHeader &base_hdr,
                      IPFragData *frag_data) {
  if (cur.size() < size_hint(base_hdr, frag_data).value())
    return ResultError(IPHeaderError::OUT_OF_BOUNDS);
  if (!base_hdr.is_v6())
    return ResultError(IPHeaderError::BAD_VERSION);

  IPv6Header base_v6_hdr = base_hdr.v6();
  uint8_t prev_nh = base_v6_hdr.exthdr_last().next_header;
  std::ranges::copy(base_v6_hdr.cursor().span().subspan(0, MIN_SIZE),
                    cur.span().begin());

  auto hdr_res = IPv6Header::read(cur);
  if (hdr_res.has_error())
    return ResultError(hdr_res.error());
  IPv6Header hdr = hdr_res.value();
  hdr.payload_len() = 0;
  hdr.next_header() = prev_nh;

  if (frag_data) {
    IPv6FragData v6_frag_data =
        IPv6FragData::construct(hdr.cursor().slice(MIN_SIZE)).value();
    v6_frag_data.next_header() = prev_nh;
    hdr.next_header() = IPv6FragData::NH_TYPE;
    *frag_data = v6_frag_data;
  }

  return hdr;
}

Result<size_t, IPv6Header::ErrorType>
IPv6Header::size_hint(IPProto, IPRAOption *ra_opt) {
  return MIN_SIZE + (ra_opt ? 8 : 0);
}

Result<IPv6Header, IPv6Header::ErrorType>
IPv6Header::construct(StructWriter cur, IPProto proto, IPRAOption *ra_opt) {
  auto hdr_res = IPv6Header::construct(cur, ra_opt ? 8 : 0); // TODO
  if (hdr_res.has_error())
    return ResultError(hdr_res.error());
  IPv6Header hdr = hdr_res.value();
  hdr.next_header() = static_cast<uint8_t>(proto);

  if (ra_opt) {
    hdr.next_header() = IPv6HBHOptions::NH_TYPE;
    IPv6HBHOptions hbh_opts =
        IPv6HBHOptions::construct(hdr.cursor().slice(MIN_SIZE)).value();
    hbh_opts.next_header() = static_cast<uint8_t>(proto);
    IPv6HBHOption hbh_opt = (*hbh_opts.options().begin()).construct().value();
    hbh_opt.data_len() = 2;
    *ra_opt = hbh_opt.data().set<IPv6RAOption>().value();
  }

  return hdr;
}

} // namespace jay::ip
