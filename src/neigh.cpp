
#include "jay/pbuf.h"
#include "jay/ip/common.h"
#include "jay/neigh.h"

#include <optional>
namespace jay {
std::optional<PBuf> NeighCache::resolve(PBuf packet) {
  ip::IPAddr tgt_iaddr = packet->nh_iaddr.value();
  Neighbour &neigh = cache[tgt_iaddr];
  Interface *iface = packet->iface;
  ip::IPAddr src_addr = packet->ip().src_addr();

  switch (neigh.state) {
  case NeighState::INCOMPLETE:
    start_solicit(iface, tgt_iaddr, src_addr, std::nullopt);
    neigh.queue.emplace_back(std::move(packet));
    return std::nullopt;
  case NeighState::STALE:
    neigh.state = NeighState::DELAY;
    neigh.timer =
        timers.create(delay_timeout,
                      std::bind(&NeighCache::start_solicit, this, iface,
                                tgt_iaddr, src_addr, neigh.haddr));
    // fallthrough
  case NeighState::DELAY:
  case NeighState::PROBE:
  case NeighState::REACHABLE:
    packet->nh_haddr = neigh.haddr;
    return std::move(packet);
  }
}

void NeighCache::start_solicit(Interface *iface, ip::IPAddr tgt_iaddr,
                               std::optional<ip::IPAddr> siaddr_hint,
                               std::optional<HWAddr> thaddr_hint) {
  Neighbour &neigh = cache[tgt_iaddr];
  neigh.state = (neigh.state == NeighState::INCOMPLETE) ? NeighState::INCOMPLETE : NeighState::PROBE;
  neigh.retry_ctr = 0;
  solicit_fn(iface, tgt_iaddr, thaddr_hint, siaddr_hint);
  neigh.timer =
      timers.create(retrans_timeout, [this, iface, tgt_iaddr, siaddr_hint,
                                      thaddr_hint, &neigh](Timer *timer) {
        neigh.retry_ctr += 1;
        if (neigh.retry_ctr == this->max_query_retries) {
          notify_unreachable(tgt_iaddr);
          return;
        }
        if (neigh.state != NeighState::REACHABLE) {
          solicit_fn(iface, tgt_iaddr, thaddr_hint, siaddr_hint);
          timer->reset();
        }
      });
}

void NeighCache::notify_unreachable(ip::IPAddr neigh_iaddr) {
  auto neigh_it = cache.find(neigh_iaddr);
  if (neigh_it == cache.end())
    return;
  unreachable_fn(neigh_iaddr, neigh_it->second);
  cache.erase(neigh_it);
}

void NeighCache::notify_reachable(Neighbour &neigh) {
  if ((neigh.state == NeighState::REACHABLE) && (neigh.timer != nullptr)) {
    neigh.timer->reset();
  } else {
    neigh.state = NeighState::REACHABLE;
    neigh.timer = timers.create(reachable_timeout, [&neigh](Timer *) {
      neigh.state = NeighState::STALE;
    });
  }
}

void NeighCache::notify_reachable(ip::IPAddr neigh_iaddr) {
  auto neigh_it = cache.find(neigh_iaddr);
  if (neigh_it != cache.end())
    notify_reachable(neigh_it->second);
}

std::optional<std::list<PBuf>> NeighCache::process_adv(ip::IPAddr tgt_iaddr, std::optional<HWAddr> tgt_haddr,
                                                       NeighAdvOptions opts) {
  auto neigh_it = cache.find(tgt_iaddr);
  if ((neigh_it == cache.end()) && opts.is_adv)
    return std::nullopt;
  if (!tgt_haddr.has_value() && !opts.is_adv)
    return std::nullopt;

  Neighbour &neigh = neigh_it->second;
  if (neigh.state == NeighState::INCOMPLETE) {
    neigh.router = opts.router;
    if (!tgt_haddr.has_value())
      return std::nullopt;

    neigh.haddr = tgt_haddr.value();
    if (opts.solicited)
      notify_reachable(neigh);
    else
      neigh.state = NeighState::STALE;

    return std::move(neigh.queue);
  } else {
    bool haddr_differs = tgt_haddr.has_value() && (neigh.haddr != tgt_haddr);
    if (!opts.override && haddr_differs) {
      if (neigh.state == NeighState::REACHABLE)
        neigh.state = NeighState::STALE;
    } else {
      if (haddr_differs) {
        neigh.haddr = tgt_haddr.value();
        neigh.state = NeighState::STALE;
      }

      if (opts.solicited)
        notify_reachable(neigh);

      neigh.router = opts.router;    
    }
  }

  return std::nullopt;
}
}; // namespace jay
