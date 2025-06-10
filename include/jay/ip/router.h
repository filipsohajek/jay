#pragma once
#include "jay/if.h"
#include "jay/util/trie.h"
#include "jay/ip/common.h"

namespace jay::ip {
class IPRouter {
public:
  struct Route {
    Interface* iface = nullptr;
    std::optional<IPAddr> nh_iaddr;
    std::optional<IPAddr> src_iaddr;
  };

  struct Destination {
    Route route;
  };

  enum class Error {
    NO_ROUTE
  };

  Result<Destination*, Error> route(IPAddr dst_addr) {
    if (dst_cache.contains(dst_addr))
      return &dst_cache[dst_addr];

    Destination& dst = dst_cache[dst_addr];
    auto [match_prefix, match_route, _match_len] = rt_table.match_longest(dst_addr);
    if (match_route == nullptr)
      return ResultError(Error::NO_ROUTE);
    dst.route = *match_route;

    return &dst;
  }

  Route* default_route() {
    return rt_table.tree_root();
  }
  
  Result<Destination*, Error> route(PBuf& packet) {
    IPAddr dst_addr = packet->ip().dst_addr();
    if (dst_addr.is_local() || dst_addr.is_multicast()) {
      packet->nh_iaddr = packet->ip().dst_addr();
      return nullptr;
    }
    auto rt_result = route(dst_addr);
    if (rt_result.has_error())
      return rt_result;
    Destination* dst = rt_result.value();

    if (dst->route.nh_iaddr.has_value()) {
      packet->nh_iaddr = dst->route.nh_iaddr.value();
    } else {
      packet->nh_iaddr = packet->ip().dst_addr();
    }

    if (dst->route.src_iaddr.has_value() && !packet->forwarded) {
      packet->ip().src_addr() = dst->route.src_iaddr.value();
    }
    packet->iface = dst->route.iface;
  
    return rt_result;
  }

  void add_route(IPAddr prefix, size_t prefix_len, Interface* iface, std::optional<IPAddr> nh_iaddr, std::optional<IPAddr> src_iaddr) {
    rt_table.emplace(prefix, prefix_len, Route {
      .iface = iface,
      .nh_iaddr = nh_iaddr,
      .src_iaddr = src_iaddr
    });
  }

  void add_route(IPv4Addr prefix, size_t prefix_len, Interface* iface, std::optional<IPv4Addr> nh_iaddr, std::optional<IPv4Addr> src_iaddr) {
    rt_table.emplace(prefix, prefix_len + 96, Route {
      .iface = iface,
      .nh_iaddr = nh_iaddr,
      .src_iaddr = src_iaddr
    });
  }
private:
  hash_table<IPAddr, Destination> dst_cache;
  BitTrie<IPAddr, Route> rt_table;
};
}
