#include "jay/if.h"
#include "jay/ip/stack.h"
#include "jay/pbuf.h"
#include "jay/stack.h"
#include "jay/ip/sock.h"
#include <random>
#include <ranges>

namespace jay::ip {
void IPStack::ip_input(PBuf packet, IPVersion version) {
  if (!packet->is_ip() && packet->read_net_hdr<IPHeader>(version).has_error())
    return;
  auto ip_hdr = packet->ip();
  if (!ips.contains(ip_hdr.dst_addr()))
    return; // TODO: routing unsupported
  if (ip_hdr.is_v4()) {
    IPFragData frag_data = ip_hdr.v4().frag_data().read().value();
    if (frag_data.more_frags() || (frag_data.frag_offset() > 0)) {
      reassemble_single(std::move(packet), frag_data);
      return;
    }
  }
  
  ip_deliver(std::move(packet));
}

void IPStack::ip_deliver(PBuf packet) {
  IPHeader ip_hdr = packet->ip();
  switch (ip_hdr.proto()) {
  case IPProto::ICMP:
    if (ip_hdr.version() != IPVersion::V4)
      break;
    icmp_input(std::move(packet), IPVersion::V4);
    break;
  case IPProto::UDP:
    _udp.deliver(std::move(packet));
    break;
  default:
    return;
  }
}

void IPStack::icmp_input(PBuf packet, IPVersion version) {
  auto icmp_res = packet->read_tspt_hdr<ICMPHeader>(version);
  if (icmp_res.has_error())
    return;
  // TODO: verify ICMP checksum

  auto icmp_hdr = packet->icmp();
  std::visit(
      [&](auto msg) {
        using MsgT = std::remove_cv_t<decltype(msg)>;
        if constexpr (std::is_same_v<MsgT, ICMPEchoRequestMessage>) {
          PBuf reply_packet;
          reply_packet->reserve_headers();
          reply_packet->insert(*packet, 0);
          ICMPEchoReplyMessage reply_msg;
          auto icmp_hdr =
              reply_packet->construct_tspt_hdr<ICMPHeader>(version, reply_msg)
                  .value();
          reply_msg.ident() = uint16_t(msg.ident());
          reply_msg.seq_num() = uint16_t(msg.seq_num());
          reply_packet->unmask(icmp_hdr.size());
          auto ip_hdr =
              reply_packet->construct_net_hdr<IPHeader>(version).value();
          ip_hdr.proto() = IPProto::ICMP;
          ip_hdr.dst_addr() = IPAddr(packet->ip().src_addr());
          ip_hdr.src_addr() = IPAddr(packet->ip().dst_addr());
          output(std::move(reply_packet));
        }
        return 0;
      },
      icmp_hdr.message());
}

void IPStack::reassemble_single(PBuf packet, IPFragData frag_data) {
  std::tuple<IPAddr, IPAddr, uint32_t> frag_key = {packet->ip().src_addr(),
                                                   packet->ip().dst_addr(),
                                                   frag_data.identification()};
  Reassembly &reass = reass_queue[frag_key];
  if (reass.packet->size() == 0) {
    reass.timer = timers.create(reassembly_timeout, [this, frag_key](Timer *) {
      auto reass_it = reass_queue.find(frag_key);
      if (reass_it == reass_queue.end())
        return;
      reass_queue.erase(frag_key);
      // TODO: ICMP
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
    auto tgt_ip_iter = ips.find(arp_hdr.tgt_iaddr());
    if (tgt_ip_iter == ips.end())
      return;
    auto &[tgt_ip, tgt_ip_state] = *tgt_ip_iter;
    if (packet->iface != tgt_ip_state.iface)
      return;

    PBuf reply_packet;
    reply_packet->reserve_headers();
    reply_packet->iface = packet->iface;
    ARPHeader reply_arp_hdr =
        reply_packet->construct_net_hdr<ARPHeader>().value();
    reply_arp_hdr.op() = ARPOp::REPLY;
    reply_arp_hdr.sdr_haddr() = packet->iface->addr();
    reply_arp_hdr.sdr_iaddr() = tgt_ip.v4();
    reply_arp_hdr.tgt_haddr() = HWAddr(arp_hdr.sdr_haddr());
    reply_arp_hdr.tgt_iaddr() = IPv4Addr(arp_hdr.sdr_iaddr());
    reply_packet->unmask(reply_arp_hdr.size());
    output(std::move(reply_packet));

  } else if (arp_hdr.op() == ARPOp::REPLY) {
    auto queue_opt = packet->iface->neighbours.process_adv(
        arp_hdr.sdr_iaddr(), arp_hdr.sdr_haddr(),
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
    auto resolved_packet = packet->iface->neighbours.resolve(std::move(packet));
    if (!resolved_packet.has_value())
      return;
    packet = std::move(resolved_packet.value());
  }
  uint16_t if_mtu = packet->iface->mtu();

  if (packet->size() > if_mtu) {
    ip_output_fragment(std::move(packet), if_mtu);
  } else {
    ip_output_final(std::move(packet));
  }
}

void IPStack::ip_output_fragment(PBuf packet, size_t if_mtu) {
  std::mt19937 mt{};
  uint32_t ident = std::uniform_int_distribution<uint32_t>{}(mt);
  size_t frag_offset = 0;
  while (packet->size() > 0) {
    PBuf fragment;
    fragment->iface = packet->iface;
    fragment->nh_haddr = packet->nh_haddr;
    fragment->nh_iaddr = packet->nh_iaddr;

    fragment->reserve_headers();
    IPFragData frag_data;
    fragment->construct_net_hdr<IPHeader>(packet->ip().version(), packet->ip(),
                                          frag_data);

    size_t frag_payload_size = if_mtu - fragment->ip().size();
    frag_data.identification() = ident;
    if (packet->size() > frag_payload_size) {
      frag_data.more_frags() = true;
    } else {
      frag_payload_size = packet->size();
      frag_data.more_frags() = false;
    }
    frag_data.frag_offset() = frag_offset;

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

  std::visit([&](auto tspt_hdr) {
    if constexpr (std::is_same_v<decltype(tspt_hdr), udp::UDPHeader>) {
      tspt_hdr.checksum() = 0;
      tspt_hdr.checksum() = inet_csum(packet->buf(), packet->ip().pseudohdr_sum());
    } else if constexpr (std::is_same_v<decltype(tspt_hdr), ICMPHeader>) {
      tspt_hdr.checksum() = 0;
      tspt_hdr.checksum() = inet_csum(packet->buf());
    }
  }, packet->tspt_hdr); 

  packet->ip().ttl() = 128;
  packet->unmask(packet->ip().size());
  if (packet->ip().is_v4()) {
    auto v4_hdr = packet->ip().v4();
    v4_hdr.hdr_csum() = 0;
    v4_hdr.hdr_csum() = inet_csum(v4_hdr.cursor().span());
  }

  packet->construct_link_hdr<EthHeader>();
  packet->eth().ether_type() =
      packet->ip().is_v4() ? EtherType::IPV4 : EtherType(0);
  packet->eth().dst_haddr() = packet->nh_haddr.value();
  stack.output(std::move(packet));
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
    throw std::invalid_argument("source address selection not implemented");

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

void IPStack::setup_interface(Interface *iface) {
  using namespace std::placeholders;
  iface->neighbours.set_callbacks(
      std::bind(&IPStack::solicit_haddr, this, _1, _2, _3, _4),
      [](IPAddr, Neighbour &) {});
}

void IPStack::assign_ip(Interface *iface, IPAddr address) {
  auto &addr_state = ips[address];
  addr_state.iface = iface;
}

void IPStack::poll() {
  poll_timers();
  for (const auto &interface : stack.interfaces()) {
    interface->neighbours.poll_timers();
  }
}
} // namespace jay::ip
