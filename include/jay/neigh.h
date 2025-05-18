#pragma once
#include "jay/util/hashtable.h"
#include "jay/eth.h"
#include "jay/ip/common.h"
#include "jay/util/time.h"
#include <list>
#include <memory>
#include <optional>

namespace jay {
class PBuf;
enum class NeighState { INCOMPLETE, REACHABLE, STALE, DELAY, PROBE };

struct Neighbour {
  HWAddr haddr;

  NeighState state = NeighState::INCOMPLETE;
  bool router;

  std::list<PBuf> queue;
  std::unique_ptr<Timer> timer = nullptr;
  uint8_t retry_ctr;
};

struct NeighAdvOptions {
  bool is_adv = true;
  bool router = false;
  bool solicited = false;
  bool override = false;
};

class Interface;
class NeighCache : public WithTimers {
public:
  clock::duration reachable_timeout = std::chrono::seconds{5};
  clock::duration delay_timeout = std::chrono::seconds{3};
  clock::duration retrans_timeout = std::chrono::seconds{1};
  uint8_t max_query_retries = 3;

  [[nodiscard]] std::optional<PBuf> resolve(PBuf);
  [[nodiscard]] std::optional<std::list<PBuf>>
  process_adv(ip::IPAddr tgt_iaddr, std::optional<HWAddr> tgt_haddr, NeighAdvOptions opts);

  void notify_reachable(Neighbour &);
  void notify_reachable(ip::IPAddr);
  void notify_unreachable(ip::IPAddr);

  const Neighbour *at(ip::IPAddr addr) const {
    auto neigh_it = cache.find(addr);
    return (neigh_it != cache.end()) ? &neigh_it->second : nullptr;
  }

  void set_callbacks(auto solicit_fn, auto unreachable_fn) {
    this->solicit_fn = solicit_fn;
    this->unreachable_fn = unreachable_fn;
  }

private:
  void start_solicit(Interface *iface, ip::IPAddr tgt_iaddr,
                     std::optional<ip::IPAddr> siaddr_hint,
                     std::optional<HWAddr> thaddr_hint);
  hash_table<ip::IPAddr, Neighbour> cache;
  std::function<void(Interface *, ip::IPAddr, std::optional<HWAddr>,
                     std::optional<ip::IPAddr>)>
      solicit_fn;
  std::function<void(ip::IPAddr, Neighbour &)> unreachable_fn;
};
} // namespace jay
