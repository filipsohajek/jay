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
  clock::duration dad_timeout = std::chrono::seconds{3};
  explicit IPStack(Stack &stack)
      : stack(stack), _sock_table(std::bind(&IPStack::select_src_addr, this,
                                            std::placeholders::_1, nullptr)) {}
  void ip_input(PBuf, IPVersion);
  void arp_input(PBuf);
  void output(PBuf);

  void setup_interface(Interface *);
  void assign_ip(Interface *, IPAddr, uint8_t prefix_len);

  void mcast_join(Interface*, IPAddr);
  void mcast_leave(Interface*, IPAddr);

  void poll();
  SocketTable &sock_table() { return _sock_table; }
  IPRouter &router() { return _router; }
  udp::UDPSocket udp_sock() {
    return {*this};
  }
private:
  void ip_input_v4(PBuf);
  void ip_input_v6(PBuf);
  void ip_reassemble_single(PBuf, IPFragData);

  void arp_output(PBuf);
  void ip_forward(PBuf);
  void ip_output_resolve(PBuf);
  void ip_output_fragment(PBuf, size_t if_mtu);
  void ip_output_final(PBuf);

  void ip_deliver(PBuf, IPProto);
  void udp_deliver(PBuf);
  void icmp_deliver(PBuf, IPVersion);
  void igmp_deliver(PBuf);

  void ip_notify_duplicate(IPAddr);
  void icmp_notify_unreachable(PBuf, UnreachableReason);
  void icmp_deliver_msg(PBuf, ICMPEchoRequestMessage);

  void igmp_send_report(IGMPMessageType, Interface*, IPv4Addr);
  void igmp_deliver_query(Interface*, IPv4Addr group_addr, IPv4Addr dst_addr, uint16_t max_resp_ms);

  void mld_send_report(Interface*, IPAddr, bool leave);
  void icmp_deliver_msg(PBuf, MLDQuery);

  void icmp_deliver_msg(PBuf, NDPNeighborAdvertisement);
  void icmp_deliver_msg(PBuf, NDPNeighborSolicitation);
  void icmp_deliver_msg(PBuf, NDPRouterAdvertisement);

  IPAddr select_src_addr(std::optional<IPAddr> daddr_hint, Interface* iface = nullptr);

  void solicit_haddr(Interface *, IPAddr tgt_iaddr,
                     std::optional<HWAddr> thaddr_hint,
                     IPAddr siaddr);
  void solicit_haddr_v4(Interface*, IPv4Addr tgt_iaddr, IPv4Addr sdr_iaddr, std::optional<HWAddr> thaddr_hint);
  void solicit_haddr_v6(Interface*, IPAddr tgt_iaddr, IPAddr sdr_iaddr, std::optional<HWAddr> thaddr_hint);


  struct AddrState {
    uint8_t prefix_len = 0;
    std::unique_ptr<Timer> dad_timer = nullptr;
    bool tentative = false;
    Interface *iface = nullptr;
  };
  BitTrie<IPAddr, AddrState> ips;

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

  std::unordered_set<std::tuple<Interface*, IPAddr>> mcast_groups;
  std::unordered_set<std::unique_ptr<Timer>> mcast_resp_timers;
};
} // namespace jay::ip
