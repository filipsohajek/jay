#pragma once
#include "jay/eth.h"
#include "jay/ip/common.h"
#include "jay/ip/opts.h"
#include "jay/ip/router.h"
#include "jay/ip/sock.h"
#include "jay/pbuf.h"
#include "jay/util/hashtable.h"
#include "jay/util/time.h"
#include "jay/udp/udp_sock.h"

namespace jay {
class Stack;
}
namespace jay::ip {

class IPStack : WithTimers {
public:
  clock::duration reassembly_timeout = std::chrono::seconds{10};
  explicit IPStack(Stack &stack)
      : stack(stack), _sock_table(std::bind(&IPStack::select_src_addr, this,
                                            std::placeholders::_1)) {}
  void ip_input(PBuf, IPVersion);
  void arp_input(PBuf);
  void output(PBuf);

  void setup_interface(Interface *);
  void assign_ip(Interface *, IPAddr, uint8_t prefix_len);

  void poll();
  SocketTable &sock_table() { return _sock_table; }
  IPRouter &router() { return _router; }
  udp::UDPSocket udp_sock() {
    return {*this};
  }
private:
  void arp_output(PBuf);
  void ip_output_resolve(PBuf);
  void ip_output_fragment(PBuf, size_t if_mtu);
  void ip_output_final(PBuf);

  void ip_deliver(PBuf);
  void udp_deliver(PBuf);
  void icmp_notify_unreachable(IPAddr, UnreachableReason,
                               std::optional<PBuf> = std::nullopt);

  IPAddr select_src_addr(std::optional<IPAddr> daddr_hint);
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
  void reassemble_timeout(ReassKey, Reassembly &);

  IPRouter _router;
  Stack &stack;

  SocketTable _sock_table;
};
} // namespace jay::ip
