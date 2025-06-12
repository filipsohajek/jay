#include "jay/if.h"
#include "jay/util/rng.h"
#include "jay/ip/igmp.h"
#include "jay/ip/mld.h"
#include "jay/ip/ndp.h"
#include "jay/ip/sock.h"
#include "jay/ip/stack.h"
#include "jay/pbuf.h"
#include "jay/stack.h"

namespace jay::ip {
void IPStack::ip_input(PBuf packet, IPVersion version) {
  IPHeader ip_hdr =
      packet->is_ip() ? packet->ip()
                      : UNWRAP_RETURN(packet->read_net_hdr<IPHeader>(version));
  IPAddr dst_addr = ip_hdr.dst_addr();

  auto [local_ip, local_ip_state, match_len] = ips.match_longest(dst_addr);
  if (match_len != 128) {
    bool broadcast =
        dst_addr.is_v4() &&
        (dst_addr.is_broadcast() ||
         dst_addr.is_directed_broadcast(local_ip_state->prefix_len));
    if (!broadcast && !dst_addr.is_multicast() && !dst_addr.is_any()) {
      ip_forward(std::move(packet));
      return;
    }
  }

  if (ip_hdr.is_v4()) {
    ip_input_v4(std::move(packet));
  } else {
    ip_input_v6(std::move(packet));
  }
}

void IPStack::ip_forward(PBuf packet) {
  packet->forwarded = true;
  if (packet->ip().ttl() == 0) {
    output(PBuf::icmp_for<ICMPTimeExceededMessage>(
        packet->ip().src_addr(), nullptr, TimeExceededType::HOP_LIMIT,
        &packet->buf()));
    return;
  }
  output(std::move(packet));
}

void IPStack::ip_input_v4(PBuf packet) {
  IPv4Header v4_hdr = packet->ip().v4();
  IPFragData frag_data = v4_hdr.frag_data().read().value();
  if (frag_data.more_frags() || (frag_data.frag_offset() > 0)) {
    ip_reassemble_single(std::move(packet), frag_data);
    return;
  }
  for (auto opt_field : v4_hdr.options()) {
    auto opt_res = opt_field.read();
    if (opt_res.has_error())
      return;
    IPv4Option v4_opt = opt_res.value();
    auto opt_variant = v4_opt.option().variant();
    if (std::holds_alternative<IPv4RAOption>(opt_variant))
      packet->router_alert = true;
  }
  ip_deliver(std::move(packet), v4_hdr.proto());
}

void IPStack::ip_input_v6(PBuf packet) {
  IPv6Header v6_hdr = packet->ip().v6();

  auto ehdr_it = v6_hdr.exthdr_begin();

  for (; ehdr_it != v6_hdr.exthdr_end(); ehdr_it++) {
    auto ehdr_opt = *ehdr_it;
    if (std::holds_alternative<IPv6HBHOptions>(ehdr_opt)) {
      // TODO
      IPv6HBHOptions hbh_opts = std::get<IPv6HBHOptions>(ehdr_opt);
      for (auto opt_field : hbh_opts.options()) {
        IPv6HBHOption hbh_opt = UNWRAP_RETURN(opt_field.read());
        auto opt_variant = hbh_opt.data().variant();
        if (std::holds_alternative<IPv6RAOption>(opt_variant))
          packet->router_alert = true;
        else if (!(hbh_opt.type().value() & 0xc0))
          return;
      }
    } else if (std::holds_alternative<IPv6FragData>(ehdr_opt)) {
      ip_reassemble_single(std::move(packet), std::get<IPv6FragData>(ehdr_opt));
      return;
    }
  }
  ip_deliver(std::move(packet), IPProto(ehdr_it.next_header));
}

void IPStack::ip_deliver(PBuf packet, IPProto proto) {
  switch (proto) {
  case IPProto::ICMP:
    icmp_deliver(std::move(packet), IPVersion::V4);
    break;
  case IPProto::ICMPv6:
    icmp_deliver(std::move(packet), IPVersion::V6);
    break;
  case IPProto::UDP:
    udp_deliver(std::move(packet));
    break;
  case IPProto::IGMP:
    igmp_deliver(std::move(packet));
    break;
  default:
    return;
  }
}

void IPStack::igmp_deliver(PBuf packet) {
  if (!packet->ip().is_v4())
    return;
  if (!packet->router_alert)
    return;
  IPv4Addr dst_addr = IPAddr(packet->ip().dst_addr()).v4();
  IGMPHeader igmp_header = UNWRAP_RETURN(packet->read_tspt_hdr<IGMPHeader>());
  IPv4Addr group_addr = igmp_header.group_addr();
  if (igmp_header.type() == IGMPMessageType::MEMBER_QUERY) {
    igmp_deliver_query(packet->iface, group_addr, dst_addr,
                       igmp_header.max_resp_time() * 100);
  }
}

void IPStack::igmp_deliver_query(Interface *iface, IPv4Addr group_addr,
                                 IPv4Addr dst_addr, uint16_t max_resp_ms) {
  if ((group_addr == IPv4Addr::any()) && (dst_addr != IPv4Addr::all_systems()))
    return;
  if (group_addr != dst_addr)
    return;
  if (!mcast_groups.contains({iface, group_addr}))
    return;
  auto resp_timer = timers.create(
      std::chrono::milliseconds{random_int(0, max_resp_ms)},
      [this, iface, group_addr](Timer *timer) {
        std::unique_ptr<Timer> search_ptr(timer);
        mcast_resp_timers.erase(search_ptr);
        igmp_send_report(IGMPMessageType::V2_MEMBER_REPORT, iface, group_addr);
        search_ptr.release();
      });
  mcast_resp_timers.insert(std::move(resp_timer));
}

void IPStack::udp_deliver(PBuf packet) {
  UNWRAP_RETURN(packet->read_tspt_hdr<udp::UDPHeader>());
  _sock_table.deliver(std::move(packet));
}

void IPStack::icmp_deliver_msg(PBuf packet, ICMPEchoRequestMessage msg) {
  ICMPEchoReplyMessage reply_msg;
  PBuf reply_packet = PBuf::icmp_for<ICMPEchoReplyMessage>(
      packet->ip().src_addr(), &reply_msg, 0, &packet->buf());
  reply_packet->ip().src_addr() = IPAddr(packet->ip().dst_addr());
  reply_msg.ident() = uint16_t(msg.ident());
  reply_msg.seq_num() = uint16_t(msg.seq_num());
  reply_packet->iface = packet->iface;
  output(std::move(reply_packet));
}

void IPStack::icmp_deliver_msg(PBuf packet, MLDQuery msg) {
  IPAddr mcast_addr = msg.mcast_addr();
  if (!mcast_groups.contains({packet->iface, mcast_addr}))
    return;
  uint16_t max_resp_ms = msg.max_resp_time();
  Interface *iface = packet->iface;
  auto resp_timer = timers.create(std::chrono::milliseconds{random_int(0, max_resp_ms)},
                                  [this, iface, mcast_addr](Timer *timer) {
                                    std::unique_ptr<Timer> search_ptr(timer);
                                    mcast_resp_timers.erase(search_ptr);
                                    mld_send_report(iface, mcast_addr, false);
                                    search_ptr.release();
                                  });
  mcast_resp_timers.insert(std::move(resp_timer));
}

void IPStack::ip_notify_duplicate(IPAddr addr) {
  ips.erase(addr);
}

void IPStack::icmp_deliver_msg(PBuf packet, NDPNeighborAdvertisement msg) {
  IPAddr tgt_iaddr = msg.target_addr();
  auto [local_ip, local_ip_state, match_len] = ips.match_longest(tgt_iaddr);
  if (match_len == 128) {
    if (local_ip_state->tentative)
      ip_notify_duplicate(local_ip);
    return;
  }

  std::optional<HWAddr> tgt_haddr;
  for (auto adv_opt_field : msg.options()) {
    NDPOption adv_opt = adv_opt_field.read().value();
    auto opt_variant = adv_opt.data().variant();
    if (std::holds_alternative<NDPTargetAddrOption>(opt_variant))
      tgt_haddr = std::get<NDPTargetAddrOption>(opt_variant).addr();
  }
  auto queued =
      packet->iface->neighbours.process_adv(msg.target_addr(), tgt_haddr,
                                            {.is_adv = true,
                                             .router = msg.router(),
                                             .solicited = msg.solicited(),
                                             .override = msg.override()});
  if (queued.has_value()) {
    for (auto &&packet : queued.value()) {
      output(std::move(packet));
    }
  }
}

void IPStack::icmp_deliver_msg(PBuf packet, NDPNeighborSolicitation msg) {
  IPAddr tgt_iaddr = msg.target_addr();
  auto [local_ip, local_ip_state, match_len] = ips.match_longest(tgt_iaddr);
  if (match_len != 128)
    return;
  if (local_ip_state->tentative)
    return;

  std::optional<HWAddr> src_haddr;
  for (auto adv_opt_field : msg.options()) {
    NDPOption adv_opt = adv_opt_field.read().value();
    auto opt_variant = adv_opt.data().variant();
    if (std::holds_alternative<NDPSourceAddrOption>(opt_variant))
      src_haddr = std::get<NDPSourceAddrOption>(opt_variant).addr();
  }

  NDPNeighborAdvertisement adv_msg;
  bool src_is_unspecified = IPAddr(packet->ip().src_addr()).is_any();
  if (src_is_unspecified && src_haddr.has_value())
    return;
  PBuf reply_packet;
  reply_packet->reserve_headers();
  ICMPHeader icmp_hdr =
      reply_packet
          ->construct_tspt_hdr<ICMPHeader>(IPVersion::V6, adv_msg, 0,
                                           packet->iface->addr())
          .value();
  adv_msg.solicited() = !src_is_unspecified;
  adv_msg.target_addr() = tgt_iaddr;
  reply_packet->unmask(icmp_hdr.size());

  IPHeader ip_hdr =
      reply_packet->construct_net_hdr<IPHeader>(IPVersion::V6, IPProto::ICMPv6)
          .value();
  if (!src_is_unspecified)
    ip_hdr.dst_addr() = IPAddr(packet->ip().src_addr());
  else
    ip_hdr.dst_addr() = IPAddr::all_nodes();
  ip_hdr.src_addr() = tgt_iaddr;
  ip_hdr.ttl() = 255;
  if (src_haddr.has_value())
    reply_packet->nh_haddr = src_haddr.value();
  reply_packet->iface = packet->iface;

  output(std::move(reply_packet));
}

void IPStack::icmp_deliver_msg(PBuf packet, NDPRouterAdvertisement msg) {
  if (packet->ip().ttl() != 255)
    return;
  
  if (uint8_t new_hop_limit = msg.hop_limit())
    packet->iface->hop_limit = new_hop_limit;
  for (auto opt_field : msg.options()) {
    NDPOption opt = UNWRAP_RETURN(opt_field.read());
    auto opt_var = opt.data().variant();
    if (std::holds_alternative<NDPPrefixInfoOption>(opt_var)) {
      auto prefix_info = std::get<NDPPrefixInfoOption>(opt_var);
      if (!prefix_info.autonomous())
        continue;
      if (prefix_info.preferred_lifetime() > prefix_info.valid_lifetime())
        continue;
      IPAddr prefix = prefix_info.prefix();
      uint8_t prefix_len = prefix_info.prefix_len();
      if (prefix.is_link_local())
        continue;

      auto if_ident = packet->iface->ident();
      if (8*sizeof(if_ident) + prefix_len != 128)
        continue;
      IPAddr local_addr = prefix.as_prefix_for(packet->iface->ident(), prefix_len);

      if (!ips.contains(local_addr))
        assign_ip(packet->iface, local_addr, prefix_len);
    }
  }
}

void IPStack::icmp_deliver(PBuf packet, IPVersion version) {
  if (packet->ip().version() != version)
    return;

  ICMPHeader icmp_hdr =
      UNWRAP_RETURN(packet->read_tspt_hdr<ICMPHeader>(version));
  packet->unmask(icmp_hdr.size());
  IPProto proto = (version == IPVersion::V4) ? IPProto::ICMP : IPProto::ICMPv6;
  if (inet_csum(*packet, packet->ip().pseudohdr_sum(proto)) != 0x0000)
    return;
  packet->mask(icmp_hdr.size());

  std::visit(
      [&](auto msg) {
        if constexpr (requires { icmp_deliver_msg(PBuf(), msg); })
          icmp_deliver_msg(std::move(packet), msg);
      },
      icmp_hdr.message());
}

void IPStack::reassemble_timeout(ReassKey reass_key, Reassembly &reass) {
  reass.packet->unmask(reass.packet->ip().size());
  Buf &reass_buf = reass.packet->buf();
  reass_buf.truncate(reass.packet->ip().size());

  const auto &[src_ip, dst_ip, ident] = reass_key;
  PBuf reply_packet = PBuf::icmp_for<ICMPTimeExceededMessage>(
      src_ip, nullptr, TimeExceededType::REASSEMBLY, &reass_buf);
  reply_packet->ip().src_addr() = dst_ip;
  reass_queue.erase(reass_key);
  output(std::move(reply_packet));
}

void IPStack::ip_reassemble_single(PBuf packet, IPFragData frag_data) {
  ReassKey reass_key{packet->ip().src_addr(), packet->ip().dst_addr(),
                     frag_data.identification()};
  Reassembly &reass = reass_queue[reass_key];
  if (reass.packet->size() == 0) {
    reass.timer = timers.create(reassembly_timeout, [this, reass_key](Timer *) {
      reassemble_timeout(reass_key, reass_queue[reass_key]);
    });
    reass.packet->reserve_headers();
    reass.packet->construct_net_hdr<IPHeader>(packet->ip().version(),
                                              packet->ip());
  }

  if (!frag_data.more_frags()) {
    if (packet->has_last_fragment) {
      reass_queue.erase(reass_key);
      return;
    }
    packet->has_last_fragment = true;
  }

  if (reass.packet->insert(*packet, frag_data.frag_offset()).has_error()) {
    reass_queue.erase(reass_key);
    return;
  }

  if (reass.packet->is_complete() && packet->has_last_fragment) {
    ip_input(std::move(reass.packet), packet->ip().version());
    reass_queue.erase(reass_key);
  }
}

void IPStack::arp_input(PBuf packet) {
  ARPHeader arp_hdr = UNWRAP_RETURN(packet->read_net_hdr<ARPHeader>());

  if (arp_hdr.op() == ARPOp::REQUEST) {
    auto [tgt_ip, tgt_ip_state, match_len] =
        ips.match_longest(IPAddr::from_v4(arp_hdr.tgt_iaddr()));
    if (match_len != 128)
      return;
    if (packet->iface != tgt_ip_state->iface)
      return;

    PBuf reply_packet;
    reply_packet->reserve_headers();
    reply_packet->iface = packet->iface;
    ARPHeader reply_arp_hdr =
        reply_packet->construct_net_hdr<ARPHeader>().value();
    reply_arp_hdr.op() = ARPOp::REPLY;
    reply_arp_hdr.sdr_haddr() = packet->iface->addr();
    reply_arp_hdr.sdr_iaddr() = tgt_ip;
    reply_arp_hdr.tgt_haddr() = HWAddr(arp_hdr.sdr_haddr());
    reply_arp_hdr.tgt_iaddr() = IPv4Addr(arp_hdr.sdr_iaddr());
    reply_packet->unmask(reply_arp_hdr.size());
    output(std::move(reply_packet));
  } else if (arp_hdr.op() == ARPOp::REPLY) {
    auto queue_opt = packet->iface->neighbours.process_adv(
        arp_hdr.sdr_iaddr().value(), arp_hdr.sdr_haddr(),
        {.router = false, .solicited = true, .override = false});
    if (!queue_opt.has_value())
      return;

    std::list<PBuf> &queue = queue_opt.value();
    while (!queue.empty()) {
      output(std::move(queue.back()));
      queue.pop_back();
    }
  }
}

void IPStack::arp_output(PBuf packet) {
  ARPHeader arp_hdr = packet->arp();
  if (arp_hdr.sdr_iaddr().value() == IPv4Addr::any())
    arp_hdr.sdr_iaddr() = select_src_addr(arp_hdr.tgt_iaddr().value(), packet->iface);

  packet->construct_link_hdr<EthHeader>();
  packet->eth().src_haddr() = HWAddr(packet->arp().sdr_haddr());
  if (HWAddr(packet->arp().tgt_haddr()) == HWAddr::zero()) {
    packet->eth().dst_haddr() = HWAddr::broadcast();
  } else {
    packet->eth().dst_haddr() = HWAddr(packet->arp().tgt_haddr());
  }
  packet->eth().ether_type() = EtherType::ARP;

  stack.output(std::move(packet));
}

void IPStack::ip_output_resolve(PBuf packet) {
  IPAddr dst_ip = packet->ip().dst_addr();

  auto [local_ip, local_ip_state, local_ip_match] =
      ips.match_longest(dst_ip.v4());
  if (local_ip_match == 128) {
    packet->iface = local_ip_state->iface;
    packet->local = true;
  }

  IPRouter::Destination *dst = UNWRAP_RETURN(_router.route(packet));

  if (!packet->local && !packet->nh_haddr.has_value()) {
    if (dst_ip.is_multicast()) {
      packet->nh_haddr = dst_ip.multicast_haddr();
    } else {
      auto resolved_packet =
          packet->iface->neighbours.resolve(std::move(packet));
      if (!resolved_packet.has_value())
        return;
      packet = std::move(resolved_packet.value());
    }
  }

  if (IPAddr(packet->ip().src_addr()).is_any() && !packet->force_source_ip) {
    std::optional<IPAddr> src_addr;
    if (dst)
      src_addr = dst->src_iaddr;
    if (!src_addr.has_value())
      src_addr = select_src_addr(packet->ip().dst_addr(), packet->iface);
    packet->ip().src_addr() = src_addr.value();
    if (dst)
      dst->src_iaddr = src_addr;
  }

  uint16_t if_mtu = packet->iface->mtu();
  if (packet->size() <= if_mtu) {
    ip_output_final(std::move(packet));
    return;
  }

  if (packet->ip().is_v4()) {
    if (packet->ip().v4().frag_data().read().value().dont_frag()) {
      if (packet->is_icmp())
        return;
      icmp_notify_unreachable(std::move(packet),
                              UnreachableReason::PACKET_TOO_BIG);
      return;
    }
  } else if (packet->forwarded) {
    if (packet->is_icmp())
      return;
    output(PBuf::icmp_for<ICMPPacketTooBig>(packet->ip().src_addr(), nullptr, 0,
                                            &packet->buf()));
    return;
  }
  ip_output_fragment(std::move(packet), if_mtu);
}

void IPStack::ip_output_fragment(PBuf packet, size_t if_mtu) {
  size_t frag_offset = 0;
  while (packet->size() > 0) {
    PBuf fragment;
    fragment->reserve_headers();
    fragment->iface = packet->iface;
    fragment->nh_haddr = packet->nh_haddr;
    fragment->nh_iaddr = packet->nh_iaddr;

    IPFragData frag_data;
    fragment->construct_net_hdr<IPHeader>(packet->ip().version(), packet->ip(),
                                          &frag_data);

    size_t frag_payload_size = if_mtu - fragment->ip().size();
    if (packet->size() > frag_payload_size) {
      frag_data.more_frags() = true;
    } else {
      frag_payload_size = packet->size();
    }
    frag_data.frag_offset() = frag_data.frag_offset() + frag_offset;

    frag_offset += frag_payload_size;
    fragment->insert(*packet, 0, frag_payload_size);
    packet->mask(frag_payload_size);

    ip_output_final(std::move(fragment));
  }
}

void IPStack::ip_output_final(PBuf packet) {
  if (packet->ip().is_v4()) {
    auto v4_hdr = packet->ip().v4();
    v4_hdr.total_len() = packet->size() + v4_hdr.size();
  } else {
    auto v6_hdr = packet->ip().v6();
    v6_hdr.payload_len() = v6_hdr.exthdr_size() + packet->size();
  }

  std::visit(
      [&](auto tspt_hdr) {
        if constexpr (std::is_same_v<decltype(tspt_hdr), udp::UDPHeader>) {
          tspt_hdr.checksum() = 0;
          tspt_hdr.checksum() = inet_csum(
              packet->buf(), packet->ip().pseudohdr_sum(IPProto::UDP));
        } else if constexpr (std::is_same_v<decltype(tspt_hdr), ICMPHeader>) {
          tspt_hdr.checksum() = 0;
          if (tspt_hdr.is_v4())
            tspt_hdr.checksum() = inet_csum(packet->buf());
          else
            tspt_hdr.checksum() = inet_csum(
                packet->buf(), packet->ip().pseudohdr_sum(IPProto::ICMPv6));
        } else if constexpr (std::is_same_v<decltype(tspt_hdr), IGMPHeader>) {
          tspt_hdr.checksum() = 0;
          tspt_hdr.checksum() = inet_csum(packet->buf());
        }
      },
      packet->tspt_hdr);

  if (packet->ip().ttl() == 0)
    packet->ip().ttl() = packet->iface ? packet->iface->hop_limit : 64;
  else if (packet->forwarded)
    packet->ip().ttl() = packet->ip().ttl() - 1;

  packet->unmask(packet->ip().size());
  if (packet->ip().is_v4()) {
    auto v4_hdr = packet->ip().v4();
    v4_hdr.hdr_csum() = 0;
    v4_hdr.hdr_csum() = inet_csum(v4_hdr.cursor().span());
  }

  if (packet->local) {
    IPVersion version = packet->nh_iaddr.value().version();
    ip_input(std::move(packet), version);
  } else {
    packet->construct_link_hdr<EthHeader>();
    packet->eth().ether_type() =
        packet->ip().is_v4() ? EtherType::IPV4 : EtherType::IPV6;
    packet->eth().dst_haddr() = packet->nh_haddr.value();
    stack.output(std::move(packet));
  }
}

void IPStack::output(PBuf packet) {
  if (packet->is_arp()) {
    arp_output(std::move(packet));
  } else if (packet->is_ip()) {
    ip_output_resolve(std::move(packet));
  } else
    throw std::invalid_argument("not an IP or ARP packet");
}

void IPStack::solicit_haddr_v4(Interface *iface, IPv4Addr tgt_iaddr,
                               IPv4Addr sdr_iaddr,
                               std::optional<HWAddr> thaddr_hint) {
  PBuf solicit_packet;
  solicit_packet->reserve_headers();
  solicit_packet->iface = iface;
  ARPHeader arp_hdr = solicit_packet->construct_net_hdr<ARPHeader>().value();
  arp_hdr.op() = ARPOp::REQUEST;
  arp_hdr.sdr_haddr() = iface->addr();
  arp_hdr.sdr_iaddr() = sdr_iaddr;
  arp_hdr.tgt_haddr() = thaddr_hint.value_or(HWAddr::zero());
  arp_hdr.tgt_iaddr() = tgt_iaddr;
  solicit_packet->unmask(arp_hdr.size());
  output(std::move(solicit_packet));
}

void IPStack::solicit_haddr_v6(Interface *iface, IPAddr tgt_iaddr,
                               IPAddr siaddr,
                               std::optional<HWAddr> thaddr_hint) {
  IPAddr dst_addr;
  if (thaddr_hint.has_value())
    dst_addr = tgt_iaddr;
  else
    dst_addr = IPAddr::solicited_node(tgt_iaddr);

  NDPNeighborSolicitation solicit_msg;
  PBuf solicit_packet;
  solicit_packet->reserve_headers();

  std::optional<HWAddr> source_haddr;
  if (!siaddr.is_any())
    source_haddr = iface->addr();
  ICMPHeader icmp_hdr = solicit_packet
                            ->construct_tspt_hdr<ICMPHeader>(
                                IPVersion::V6, solicit_msg, 0, source_haddr)
                            .value();
  solicit_msg.target_addr() = tgt_iaddr;
  solicit_packet->unmask(icmp_hdr.size());

  IPHeader ip_hdr =
      solicit_packet
          ->construct_net_hdr<IPHeader>(IPVersion::V6, IPProto::ICMPv6)
          .value();
  ip_hdr.src_addr() = siaddr;
  solicit_packet->force_source_ip = true;
  ip_hdr.dst_addr() = dst_addr;
  ip_hdr.ttl() = 255;

  solicit_packet->iface = iface;
  solicit_packet->nh_haddr = thaddr_hint.value_or(tgt_iaddr.multicast_haddr());
  output(std::move(solicit_packet));
}

void IPStack::solicit_haddr(Interface *iface, IPAddr tgt_iaddr,
                            std::optional<HWAddr> thaddr_hint,
                            IPAddr siaddr) {
  if (tgt_iaddr.is_v4()) {
    solicit_haddr_v4(iface, tgt_iaddr.v4(), siaddr.v4(), thaddr_hint);
  } else {
    solicit_haddr_v6(iface, tgt_iaddr, siaddr, thaddr_hint);
  }
}

void IPStack::icmp_notify_unreachable(PBuf packet, UnreachableReason reason) {
  if (packet->is_icmp())
    return;
  output(PBuf::icmp_for<ICMPDestinationUnreachableMessage>(
      packet->ip().src_addr(), nullptr, reason, &packet->buf()));
}

void IPStack::setup_interface(Interface *iface) {
  using namespace std::placeholders;
  iface->neighbours.set_callbacks(
      std::bind(&IPStack::solicit_haddr, this, _1, _2, _3, _4),
      [this](IPAddr, Neighbour &neigh) {
        while (!neigh.queue.empty()) {
          PBuf queued_packet = std::move(neigh.queue.back());
          icmp_notify_unreachable(std::move(queued_packet),
                                  UnreachableReason::HOST_UNREACHABLE);
          neigh.queue.pop_back();
        }
      });

  assign_ip(iface, IPAddr::unicast_ll(iface->ident()), 10);
}

IPAddr IPStack::select_src_addr(std::optional<IPAddr> daddr_hint,
                                Interface *iface) {
  if (!iface) {
    const IPRouter::Route *rt = _router.default_route();
    if (daddr_hint.has_value()) {
      auto route_res = _router.route(daddr_hint.value());
      if (route_res.has_value())
        rt = &route_res.value()->route;
    }

    if (rt && rt->iface)
      iface = rt->iface;
  }

  auto [src_ip, src_state] = std::ranges::max(ips, [&](const auto &left,
                                                       const auto &right) {
    auto [left_ip, left_state] = left;
    auto [right_ip, right_state] = right;

    // TODO
    if (left_state->tentative)
      return true;
    if (right_state->tentative)
      return false;

    if (daddr_hint.has_value()) {
      if (left_ip == daddr_hint.value())
        return false;
      if (right_ip == daddr_hint.value())
        return true;
    }

    if (iface) {
      if (left_state->iface == iface)
        return false;
      if (right_state->iface == iface)
        return true;
    }

    if (daddr_hint.has_value()) {
      auto left_bits = AsBits{left_ip};
      auto right_bits = AsBits{right_ip};
      auto daddr_bits = AsBits{daddr_hint.value()};

      return std::distance(left_bits.begin(),
                           std::ranges::mismatch(left_bits, daddr_bits).in1) <
             std::distance(right_bits.begin(),
                           std::ranges::mismatch(right_bits, daddr_bits).in1);
    }

    return false;
  });

  return src_ip;
}

void IPStack::mcast_join(Interface *iface, IPAddr group_addr) {
  mcast_groups.emplace(iface, group_addr);
  if (group_addr.is_v4()) {
    igmp_send_report(IGMPMessageType::V2_MEMBER_REPORT, iface, group_addr.v4());
  } else {
    mld_send_report(iface, group_addr, false);
  }
}

void IPStack::mcast_leave(Interface *iface, IPAddr group_addr) {
  mcast_groups.erase({iface, group_addr});
  if (group_addr.is_v4()) {
    igmp_send_report(IGMPMessageType::LEAVE_GROUP, iface, group_addr.v4());
  } else {
    mld_send_report(iface, group_addr, true);
  }
}

void IPStack::igmp_send_report(IGMPMessageType msg_type, Interface *iface,
                               IPv4Addr group_addr) {
  PBuf report_packet;
  report_packet->iface = iface;
  report_packet->reserve_headers();
  auto igmp_hdr = report_packet->construct_tspt_hdr<IGMPHeader>().value();
  igmp_hdr.type() = msg_type;
  igmp_hdr.group_addr() = group_addr;
  report_packet->unmask(igmp_hdr.size());
  IPRAOption ra_opt;
  auto ip_hdr =
      report_packet
          ->construct_net_hdr<IPHeader>(IPVersion::V4, IPProto::IGMP, &ra_opt)
          .value();

  switch (msg_type) {
  case IGMPMessageType::LEAVE_GROUP:
    ip_hdr.dst_addr() = IPv4Addr::all_routers();
    break;
  default:
    ip_hdr.dst_addr() = group_addr;
    break;
  }
  ip_hdr.src_addr() = select_src_addr(group_addr, iface);
  ip_hdr.ttl() = 1;
  output(std::move(report_packet));
}

void IPStack::mld_send_report(Interface *iface, IPAddr mcast_addr, bool leave) {
  PBuf report_packet;
  if (leave) {
    MLDDone leave_msg;
    report_packet = PBuf::icmp_for(IPAddr::all_routers(), &leave_msg);
    leave_msg.mcast_addr() = mcast_addr;
  } else {
    MLDReport report_msg;
    report_packet = PBuf::icmp_for(mcast_addr, &report_msg);
    report_msg.mcast_addr() = mcast_addr;
  }
  report_packet->iface = iface;

  IPAddr ll_addr = IPAddr::unicast_ll(iface->ident());
  if (ips.contains(ll_addr) && !ips.at(ll_addr).tentative)
    report_packet->ip().src_addr() = ll_addr;
  else
    report_packet->ip().src_addr() = IPAddr{};

  output(std::move(report_packet));
}

void IPStack::assign_ip(Interface *iface, IPAddr address, uint8_t prefix_len) {
  AddrState &addr_state = ips.at(address);
  addr_state.iface = iface;
  addr_state.prefix_len = address.prefix_len(prefix_len);

  if (!address.is_v4()) {
    addr_state.tentative = true;
    solicit_haddr(iface, address, std::nullopt, IPAddr{});
    addr_state.dad_timer =
        timers.create(dad_timeout, [this, iface, address](Timer *) {
          if (ips.contains(address))
            ips.at(address).tentative = false;
          mcast_join(iface, IPAddr::all_nodes());
          mcast_join(iface, IPAddr::solicited_node(address));
        });
  }
}

void IPStack::poll() {
  poll_timers();
  for (const auto &interface : stack.interfaces()) {
    interface->neighbours.poll_timers();
  }
}
} // namespace jay::ip
