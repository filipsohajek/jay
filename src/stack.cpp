#include <iostream>
#include <stdexcept>

#include "jay/eth.h"
#include "jay/stack.h"

namespace jay {
void Stack::input(Interface *iface, PBuf packet) {
  packet->iface = iface;
  auto eth_header = packet->read_link_hdr<EthHeader>();
  if (eth_header.has_error())
    return;
    
  std::cout << "input:" << *packet;
  switch (eth_header.value().ether_type()) {
  case EtherType::ARP:
    ip.arp_input(std::move(packet));
    break;
  case EtherType::IPV4:
    ip.ip_input(std::move(packet), ip::IPVersion::V4);
    break;
  case EtherType::IPV6:
    ip.ip_input(std::move(packet), ip::IPVersion::V6);
    break;
  }
}

void Stack::output(PBuf packet) {
  if (packet->iface == nullptr)
    throw std::invalid_argument(
        "output of packet with no assigned output interface");
  packet->eth().src_haddr() = packet->iface->addr();
  packet->unmask(packet->eth().size());
  packet->iface->enqueue(std::move(packet));
}

void Stack::poll() {
  ip.poll();
  for (auto &iface : ifaces) {
    iface->poll_rx(*this);
    iface->poll_tx(*this);
  }
}

void Stack::add_interface(std::shared_ptr<Interface> iface) {
  ifaces.push_back(iface);
  ip.setup_interface(iface.get());
}
}; // namespace jay
