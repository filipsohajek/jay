#include "jay/ip/ip_hdr.h"
#include "jay/ip/opts.h"
#include "jay/ip/v4.h"

namespace jay::ip {
const size_t IPv4Header::MIN_SIZE;
Result<IPv4Header, IPv4Header::ErrorType> IPv4Header::read(StructWriter cur) {
  IPv4Header hdr = UNWRAP_PROPAGATE(BufStruct::read(cur));
  if (inet_csum(hdr.cur.span()) != 0)
    return ResultError(IPHeaderError::CHECKSUM_ERROR);
  return hdr;
}

size_t IPv4Header::size_hint(size_t opts_size) {
  return MIN_SIZE + opts_size;
}

Result<IPv4Header, IPv4Header::ErrorType>
IPv4Header::construct(StructWriter cur, size_t opts_size) {
  size_t total_size = size_hint(opts_size);
  cur = cur.span().subspan(0, total_size);
  IPv4Header hdr{cur};
  if (cur.size() != total_size)
    return ResultError(IPHeaderError::OUT_OF_BOUNDS);
  cur.slice(0, MIN_SIZE).reset();
  hdr.version() = IPVersion::V4;
  hdr.ihl() = cur.span().size() / 4;
  return hdr;
}

size_t IPv4Header::size_hint(IPHeader &,
                                                            IPFragData *) {
  return MIN_SIZE;
}

Result<IPv4Header, IPv4Header::ErrorType>
IPv4Header::construct(StructWriter cur, IPHeader &base_hdr,
                      IPFragData *frag_data) {
  if (cur.size() < size_hint(base_hdr, frag_data))
    return ResultError(IPHeaderError::OUT_OF_BOUNDS);
  if (!base_hdr.is_v4())
    return ResultError(IPHeaderError::BAD_VERSION);

  IPv4Header base_v4_hdr = base_hdr.v4();
  std::ranges::copy(base_v4_hdr.cursor().span().subspan(0, MIN_SIZE),
                    cur.span().begin());
  IPv4Header hdr {cur};

  if (frag_data)
    *frag_data = UNWRAP_PROPAGATE(hdr.frag_data().read());
  else
    UNWRAP_PROPAGATE(hdr.frag_data().construct());
  return hdr;
}

size_t
IPv4Header::size_hint(IPProto, IPRAOption *ra_opt) {
  return MIN_SIZE + (ra_opt ? 4 : 0);
}

Result<IPv4Header, IPv4Header::ErrorType>
IPv4Header::construct(StructWriter cur, IPProto proto, IPRAOption *ra_opt) {
  IPv4Header hdr = UNWRAP_PROPAGATE(IPv4Header::construct(cur, ra_opt ? 4 : 0));

  hdr.proto() = proto;
  if (ra_opt) {
    IPv4Option opt = UNWRAP_PROPAGATE((*hdr.options().begin()).construct());
    opt.length() = 4;
    opt.copied() = true;
    *ra_opt = UNWRAP_PROPAGATE(opt.option().set<IPv4RAOption>());
  }

  return hdr;
}

} // namespace jay::ip
