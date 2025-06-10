#include "jay/ip/ip_hdr.h"
#include "jay/ip/opts.h"
#include "jay/ip/v4.h"

namespace jay::ip {
const size_t IPv4Header::MIN_SIZE;
Result<IPv4Header, IPv4Header::ErrorType> IPv4Header::read(StructWriter cur) {
  IPv4Header hdr{cur};
  if (cur.size() < 4 * hdr.ihl())
    return ResultError(IPHeaderError::OUT_OF_BOUNDS);
  hdr.cur = cur.span().subspan(0, 4 * hdr.ihl());
  if (inet_csum(hdr.cur.span()) != 0)
    return ResultError(IPHeaderError::CHECKSUM_ERROR);
  if (hdr.version() != IPVersion::V4)
    return ResultError(IPHeaderError::BAD_VERSION);
  return hdr;
}

Result<size_t, IPv4Header::ErrorType> IPv4Header::size_hint(size_t opts_size) {
  return MIN_SIZE + opts_size;
}

Result<IPv4Header, IPv4Header::ErrorType>
IPv4Header::construct(StructWriter cur, size_t opts_size) {
  size_t total_size = size_hint(opts_size).value();
  cur = cur.span().subspan(0, total_size);
  IPv4Header hdr{cur};
  if (cur.size() != total_size)
    return ResultError(IPHeaderError::OUT_OF_BOUNDS);
  cur.slice(0, MIN_SIZE).reset();
  hdr.version() = IPVersion::V4;
  hdr.ihl() = cur.span().size() / 4;
  return hdr;
}

Result<size_t, IPv4Header::ErrorType> IPv4Header::size_hint(IPHeader &,
                                                            IPFragData *) {
  return MIN_SIZE;
}

Result<IPv4Header, IPv4Header::ErrorType>
IPv4Header::construct(StructWriter cur, IPHeader &base_hdr,
                      IPFragData *frag_data) {
  if (cur.size() < size_hint(base_hdr, frag_data).value())
    return ResultError(IPHeaderError::OUT_OF_BOUNDS);
  if (!base_hdr.is_v4())
    return ResultError(IPHeaderError::BAD_VERSION);

  IPv4Header base_v4_hdr = base_hdr.v4();
  std::ranges::copy(base_v4_hdr.cursor().span().subspan(0, MIN_SIZE),
                    cur.span().begin());
  auto hdr_res = IPv4Header::read(cur);
  if (hdr_res.has_error())
    return ResultError(hdr_res.error());
  IPv4Header hdr = hdr_res.value();

  if (frag_data)
    *frag_data = hdr.frag_data().read().value();
  return hdr;
}

Result<size_t, IPv4Header::ErrorType>
IPv4Header::size_hint(IPProto, IPRAOption *ra_opt) {
  return MIN_SIZE + (ra_opt ? 4 : 0);
}

Result<IPv4Header, IPv4Header::ErrorType>
IPv4Header::construct(StructWriter cur, IPProto proto, IPRAOption *ra_opt) {
  auto hdr_res = IPv4Header::construct(cur, ra_opt ? 4 : 0);
  if (hdr_res.has_error())
    return ResultError(hdr_res.error());
  IPv4Header hdr = hdr_res.value();

  hdr.proto() = proto;
  if (ra_opt) {
    auto opt_res = (*hdr.options().begin()).construct();
    if (opt_res.has_error())
      return ResultError(IPHeaderError::OPTION_ERROR);
    IPv4Option opt = opt_res.value();
    opt.length() = 4;
    opt.copied() = true;
    *ra_opt = opt.option().set<IPv4RAOption>().value();
  }

  return hdr;
}

} // namespace jay::ip
