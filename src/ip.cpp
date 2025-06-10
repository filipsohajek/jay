#include "jay/if.h"
#include "jay/ip/igmp.h"
#include "jay/ip/sock.h"
#include "jay/ip/stack.h"
#include "jay/pbuf.h"
#include "jay/stack.h"
#include <iostream>
#include <random>

namespace jay::ip {
void IPStack::ip_input(PBuf packet, IPVersion version) {
  if (!packet->is_ip() && packet->read_net_hdr<IPHeader>(version).has_error())
    return;
  auto ip_hdr = packet->ip();
  IPAddr dst_addr = ip_hdr.dst_addr();

  auto [local_ip, local_ip_state, match_len] = ips.match_longest(dst_addr);
  if (match_len != 128) {
    bool broadcast = false;
    if (dst_addr.is_v4()) {
      if (local_ip_state && (match_len >= local_ip_state->prefix_len)) {
        auto dst_bits = AsBits{dst_addr};
        broadcast =
            std::ranges::all_of(dst_bits.begin() + local_ip_state->prefix_len,
                                dst_bits.end(), [](bool b) { return b; });
      }
    }
    if (!broadcast && !dst_addr.is_multicast()) {
      packet->forwarded = true;
      if (packet->ip().ttl() == 0) {
        output(PBuf::icmp_for<ICMPTimeExceededMessage>(
            packet->ip().src_addr(), nullptr, TimeExceededType::HOP_LIMIT,
            &packet->buf()));
        return;
      }
      output(std::move(packet));
      return;
    }
  }

  if (ip_hdr.is_v4()) {
    ip_input_v4(std::move(packet));
  } else {
    ip_input_v6(std::move(packet));
  }
}

void IPStack::ip_input_v4(PBuf packet) {
  IPv4Header v4_hdr = packet->ip().v4();
  IPFragData frag_data = v4_hdr.frag_data().read().value();
  if (frag_data.more_frags() || (frag_data.frag_offset() > 0)) {
    reassemble_single(std::move(packet), frag_data);
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
        auto opt_res = opt_field.read();
        if (opt_res.has_error())
          return;
        auto opt_variant = opt_res.value().data().variant();
        if (std::holds_alternative<IPv6RAOption>(opt_variant))
          packet->router_alert = true;
      }
    } else if (std::holds_alternative<IPv6FragData>(ehdr_opt)) {
      reassemble_single(std::move(packet), std::get<IPv6FragData>(ehdr_opt));
      return;
    }
  }
  ip_deliver(std::move(packet), IPProto(ehdr_it.next_header));
}

void IPStack::ip_deliver(PBuf packet, IPProto proto) {
  switch (proto) {
  case IPProto::ICMP:
    if (!packet->ip().is_v4())
      break;
    icmp_input(std::move(packet), IPVersion::V4);
    break;
  case IPProto::UDP:
    udp_deliver(std::move(packet));
    break;
  case IPProto::IGMP:
    if (!packet->ip().is_v4())
      break;
    igmp_deliver(std::move(packet));
    break;
  default:
    return;
  }
}

void IPStack::igmp_deliver(PBuf packet) {
  if (!packet->ip().is_v4())
    return;
  IPv4Addr group_addr = IPAddr(packet->ip().dst_addr()).v4();
  if (!group_addr.is_multicast())
    return;

  if (packet->construct_net_hdr<IGMPHeader>().has_error())
    return;
  auto igmp_header = packet->igmp();
  if (igmp_header.type() == IGMPMessageType::MEMBER_QUERY) {
    if (mcast_groups.contains({packet->iface, group_addr})) {
      uint16_t max_resp_ms = igmp_header.max_resp_time() * 100;
      std::mt19937 mt;
      std::uniform_int_distribution<uint16_t> dur_unif(0, max_resp_ms);
      Interface *iface = packet->iface;
      auto resp_timer =
          timers.create(std::chrono::milliseconds{dur_unif(mt)},
                        [this, iface, group_addr](Timer *timer) {
                          std::unique_ptr<Timer> search_ptr(timer);
                          mcast_resp_timers.erase(search_ptr);
                          igmp_send_report(IGMPMessageType::V2_MEMBER_REPORT,
                                           iface, group_addr);
                          search_ptr.release();
                        });
      mcast_resp_timers.insert(std::move(resp_timer));
    }
  }
}

void IPStack::udp_deliver(PBuf packet) {
  if (packet->read_tspt_hdr<udp::UDPHeader>().has_error())
    return;
  _sock_table.deliver(std::move(packet));
}

void IPStack::icmp_input(PBuf packet, IPVersion version) {
  auto icmp_res = packet->read_tspt_hdr<ICMPHeader>(version);
  if (icmp_res.has_error())
    return;

  auto icmp_hdr = packet->icmp();
  packet->unmask(icmp_hdr.size());
  if (inet_csum(*packet) != 0x0000)
    return;
  packet->mask(icmp_hdr.size());

  std::visit(
      [&](auto msg) {
        using MsgT = std::remove_cv_t<decltype(msg)>;
        if constexpr (std::is_same_v<MsgT, ICMPEchoRequestMessage>) {

          ICMPEchoReplyMessage reply_msg;
          PBuf reply_packet = PBuf::icmp_for<ICMPEchoReplyMessage>(
              packet->ip().src_addr(), &reply_msg, 0, &packet->buf(),
              packet->ip().dst_addr());
          reply_msg.ident() = uint16_t(msg.ident());
          reply_msg.seq_num() = uint16_t(msg.seq_num());
          output(std::move(reply_packet));
        }
        return 0;
      },
      icmp_hdr.message());
}

void IPStack::reassemble_timeout(ReassKey reass_key, Reassembly &reass) {
  reass.packet->unmask(reass.packet->ip().size());
  Buf &reass_buf = reass.packet->buf();
  reass_buf.truncate(reass.packet->ip().size());

  const auto &[src_ip, dst_ip, ident] = reass_key;
  PBuf reply_packet = PBuf::icmp_for<ICMPTimeExceededMessage>(
      src_ip, nullptr, TimeExceededType::REASSEMBLY, &reass_buf, dst_ip);
  reass_queue.erase(reass_key);
  output(std::move(reply_packet));
}

void IPStack::reassemble_single(PBuf packet, IPFragData frag_data) {
  std::tuple<IPAddr, IPAddr, uint32_t> frag_key = {packet->ip().src_addr(),
                                                   packet->ip().dst_addr(),
                                                   frag_data.identification()};
  Reassembly &reass = reass_queue[frag_key];
  if (reass.packet->size() == 0) {
    reass.timer = timers.create(reassembly_timeout, [this, frag_key](Timer *) {
      reassemble_timeout(frag_key, reass_queue[frag_key]);
    });
    reass.packet->reserve_headers();
    reass.packet->construct_net_hdr<IPHeader>(packet->ip().version(),
                                              packet->ip());
  }

  if (!frag_data.more_frags()) {
    if (packet->has_last_fragment) {
      reass_queue.erase(frag_key);
      return;
    }
    packet->has_last_fragment = true;
  }

  if (reass.packet->insert(*packet, frag_data.frag_offset()).has_error()) {
    reass_queue.erase(frag_key);
    return;
  }

  if (reass.packet->is_complete() && packet->has_last_fragment) {
    ip_input(std::move(reass.packet), packet->ip().version());
    reass_queue.erase(frag_key);
  }
}

void IPStack::arp_input(PBuf packet) {
  if (packet->read_net_hdr<ARPHeader>().has_error())
    return;
  auto arp_hdr = packet->arp();

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
  if (_router.route(packet).has_error())
    throw std::runtime_error("cannot route packet");
  if (!packet->nh_haddr.has_value()) {
    IPAddr dst_ip = packet->ip().dst_addr();
    auto [local_ip, local_ip_state, local_ip_match] =
        ips.match_longest(dst_ip.v4());
    if (local_ip_match == 32) {
      Interface *local_if = local_ip_state->iface;
      packet->iface = local_if;
      packet->local = true;
    } else if (dst_ip.is_multicast()) {
      packet->nh_haddr = dst_ip.multicast_haddr();
    } else {
      auto resolved_packet =
          packet->iface->neighbours.resolve(std::move(packet));
      if (!resolved_packet.has_value())
        return;
      packet = std::move(resolved_packet.value());
    }
  }
  uint16_t if_mtu = packet->iface->mtu();

  if (packet->size() > if_mtu) {
    if (packet->ip().is_v4()) {
      if (packet->ip().v4().frag_data().read().value().dont_frag()) {
        icmp_notify_unreachable(std::move(packet),
                                UnreachableReason::PACKET_TOO_BIG);
        return;
      }
    }
    ip_output_fragment(std::move(packet), if_mtu);
  } else {
    ip_output_final(std::move(packet));
  }
}

void IPStack::ip_output_fragment(PBuf packet, size_t if_mtu) {
  size_t frag_offset = 0;
  while (packet->size() > 0) {
    PBuf fragment;
    fragment->iface = packet->iface;
    fragment->nh_haddr = packet->nh_haddr;
    fragment->nh_iaddr = packet->nh_iaddr;

    fragment->reserve_headers();
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
  }

  std::visit(
      [&](auto tspt_hdr) {
        if constexpr (std::is_same_v<decltype(tspt_hdr), udp::UDPHeader>) {
          tspt_hdr.checksum() = 0;
          tspt_hdr.checksum() = inet_csum(
              packet->buf(), packet->ip().pseudohdr_sum(IPProto::UDP));
        } else if constexpr (std::is_same_v<decltype(tspt_hdr), ICMPHeader>) {
          tspt_hdr.checksum() = 0;
          tspt_hdr.checksum() = inet_csum(packet->buf());
        }
      },
      packet->tspt_hdr);

  if (packet->ip().ttl() == 0)
    packet->ip().ttl() = 128;
  else if (packet->forwarded)
    packet->ip().ttl() = packet->ip().ttl() - 1;

  packet->unmask(packet->ip().size());
  if (packet->ip().is_v4()) {
    auto v4_hdr = packet->ip().v4();
    v4_hdr.hdr_csum() = 0;
    v4_hdr.hdr_csum() = inet_csum(v4_hdr.cursor().span());
  }

  if (packet->local) {
    ip_input(std::move(packet), packet->nh_iaddr.value().version());
  } else {
    packet->construct_link_hdr<EthHeader>();
    packet->eth().ether_type() =
        packet->ip().is_v4() ? EtherType::IPV4 : EtherType(0);
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

void IPStack::solicit_haddr(Interface *iface, IPAddr tgt_iaddr,
                            std::optional<HWAddr> thaddr_hint,
                            std::optional<IPAddr> siaddr_hint) {
  IPAddr sdr_iaddr;
  if (siaddr_hint.has_value() &&
      ips.contains(siaddr_hint.value())) // TODO: verify iface?
    sdr_iaddr = siaddr_hint.value();
  else
    sdr_iaddr = select_src_addr(tgt_iaddr, iface);

  if (tgt_iaddr.is_v4()) {
    PBuf solicit_packet;
    solicit_packet->reserve_headers();
    solicit_packet->iface = iface;
    ARPHeader arp_hdr = solicit_packet->construct_net_hdr<ARPHeader>().value();
    arp_hdr.op() = ARPOp::REQUEST;
    arp_hdr.sdr_haddr() = iface->addr();
    arp_hdr.sdr_iaddr() = sdr_iaddr.v4();
    arp_hdr.tgt_haddr() = thaddr_hint.value_or(HWAddr::zero());
    arp_hdr.tgt_iaddr() = tgt_iaddr.v4();
    solicit_packet->unmask(arp_hdr.size());
    output(std::move(solicit_packet));
  } else {
    throw std::invalid_argument("IPv6 address resolution not implemented");
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
      [this](IPAddr addr, Neighbour &neigh) {
        while (!neigh.queue.empty()) {
          PBuf queued_packet = std::move(neigh.queue.back());
          icmp_notify_unreachable(std::move(queued_packet),
                                  UnreachableReason::HOST_UNREACHABLE);
          neigh.queue.pop_back();
        }
      });
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
  }
}

void IPStack::mcast_leave(Interface *iface, IPAddr group_addr) {
  mcast_groups.erase({iface, group_addr});
  if (group_addr.is_v4()) {
    igmp_send_report(IGMPMessageType::LEAVE_GROUP, iface, group_addr.v4());
  }
}

void IPStack::igmp_send_report(IGMPMessageType msg_type, Interface *iface,
                               IPv4Addr group_addr) {
  PBuf report_packet;
  report_packet->iface = iface;
  report_packet->reserve_headers();
  auto igmp_hdr = report_packet->construct_net_hdr<IGMPHeader>().value();
  igmp_hdr.type() = msg_type;
  igmp_hdr.group_addr() = group_addr;
  report_packet->unmask(igmp_hdr.size());
  igmp_hdr.checksum() = inet_csum(report_packet->buf());
  IPRAOption ra_opt;
  auto ip_hdr =
      report_packet
          ->construct_net_hdr<IPHeader>(IPVersion::V4, IPProto::IGMP, &ra_opt)
          .value();

  switch (msg_type) {
  case IGMPMessageType::LEAVE_GROUP:
    ip_hdr.dst_addr() = IPv4Addr{224, 0, 0, 2};
    break;
  default:
    ip_hdr.dst_addr() = group_addr;
    break;
  }
  ip_hdr.src_addr() = select_src_addr(group_addr, iface);
  ip_hdr.ttl() = 1;
  output(std::move(report_packet));
}

void IPStack::assign_ip(Interface *iface, IPAddr address, uint8_t prefix_len) {
  AddrState &addr_state = ips.at(address);
  addr_state.iface = iface;
  addr_state.prefix_len = prefix_len + (address.is_v4() ? 96 : 0);
}

void IPStack::poll() {
  poll_timers();
  for (const auto &interface : stack.interfaces()) {
    interface->neighbours.poll_timers();
  }
}
} // namespace jay::ip
