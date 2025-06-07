#pragma once
#include "jay/eth.h"
#include "jay/ip/common.h"
#include "jay/ip/opts.h"
#include "jay/ip/router.h"
#include "jay/ip/sock.h"
#include "jay/udp/udp_stack.h"
#include "jay/pbuf.h"
#include "jay/util/hashtable.h"
#include "jay/util/time.h"

namespace jay {
class Stack;
}
namespace jay::ip {

class IPStack : WithTimers {
public:
  clock::duration reassembly_timeout = std::chrono::seconds{10};
  explicit IPStack(Stack &stack) : stack(stack), _udp(*this) {}
  void ip_input(PBuf, IPVersion);
  void arp_input(PBuf);
  void output(PBuf);

  void setup_interface(Interface *);
  void assign_ip(Interface *, IPAddr, uint8_t prefix_len);

  void poll();
  IPRouter &router() { return _router; }
  udp::UDPStack &udp() { return _udp; }
private:
  void arp_output(PBuf);
  void ip_output_resolve(PBuf);
  void ip_output_fragment(PBuf, size_t if_mtu);
  void ip_output_final(PBuf);

  void ip_deliver(PBuf);
  void icmp_notify_unreachable(IPAddr, UnreachableReason, std::optional<PBuf> = std::nullopt);

  void icmp_input(PBuf, IPVersion);
  void solicit_haddr(Interface *iface, IPAddr tgt_iaddr,
                     std::optional<HWAddr> thaddr_hint,
                     std::optional<IPAddr> siaddr_hint);
  void reassemble_single(PBuf, IPFragData);

  struct AddrState {
    uint8_t prefix_len = 0;
    Interface *iface = nullptr;
  };
  BitTrie<IPv4Addr, AddrState> ips;

  using ReassKey = std::tuple<IPAddr, IPAddr, uint32_t>;
  struct Reassembly {
    PBuf packet;
    std::unique_ptr<Timer> timer;
  };
  hash_table<ReassKey, Reassembly> reass_queue;
  void reassemble_timeout(ReassKey, Reassembly&);

  IPRouter _router;
  Stack &stack;
  udp::UDPStack _udp;
};
} // namespace jay::ip
