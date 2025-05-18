#pragma once
#include "jay/util/hashtable.h"
#include <tuple>
#include <cstdint>
#include <random>
#include <unordered_set>
#include "jay/ip/common.h"
#include "jay/udp/udp_sock.h"

namespace jay::udp {
class UDPStack {
public:
  uint16_t local_port_sel_min = 49152;
  uint16_t local_port_sel_max = 65535;

  explicit UDPStack(ip::IPStack& ip_stack) : ip_stack(ip_stack) {}

  std::unique_ptr<UDPSocket> listen(std::optional<ip::IPAddr> local_addr, uint16_t local_port) {
    return udp_socket(std::nullopt, 0, local_addr, local_port);
  }
  
  std::unique_ptr<UDPSocket> connect(std::optional<ip::IPAddr> remote_addr, uint16_t remote_port) {
    return udp_socket(remote_addr, remote_port, std::nullopt, 0);
  }

  std::unique_ptr<UDPSocket> udp_socket(std::optional<ip::IPAddr> remote_addr, uint16_t remote_port, std::optional<ip::IPAddr> local_addr, uint16_t local_port) {
    std::unique_ptr<UDPSocket> sock(new UDPSocket(ip_stack));
    sock->protocol = ip::IPProto::UDP;
    sock->_remote_addr = remote_addr;
    sock->_local_addr = local_addr;

    sock->_remote_port = remote_port;

    if (local_port == 0) {
      std::mt19937 mt;
      std::uniform_int_distribution<uint16_t> port_unif(local_port_sel_min, local_port_sel_max);
      
      uint16_t tried_ports = 0;
      uint16_t num_ports = local_port_sel_max - local_port_sel_min;
      while (tried_ports < num_ports) {
        local_port = port_unif(mt);
        if (!used_local_ports.contains(local_port)) {
          break;
        }
        tried_ports++;
      }

      if (used_local_ports.contains(local_port)) {
        throw std::runtime_error("no available UDP ports"); 
      }
    }

    sock->_local_port = local_port;
    sockets.insert(sock.get());
    
    if (local_addr.has_value() || local_port)
      bound_sockets.emplace(std::make_tuple(local_addr, local_port), sock.get());
    return sock;
  }

  void remove_socket(UDPSocket* sock) {
    sockets.erase(sock);
    if (sock->_local_addr.has_value() || sock->local_port())
      bound_sockets.erase(std::make_tuple(sock->_local_addr.value(), sock->local_port()));
    used_local_ports.erase(sock->local_port());
  }

  void deliver(PBuf packet) {
    if (packet->read_tspt_hdr<UDPHeader>().has_error())
      return;

    ip::IPHeader ip_hdr = packet->ip();
    UDPHeader udp_hdr = packet->udp();
    
    auto sock_it = bound_sockets.find(std::make_tuple(ip_hdr.dst_addr(), udp_hdr.dst_port()));
    if (sock_it != bound_sockets.end()) {
      sock_it->second->deliver(packet);
      return;
    }
    sock_it = bound_sockets.find(std::make_tuple(std::nullopt, udp_hdr.dst_port()));
    if (sock_it != bound_sockets.end()) {
      sock_it->second->deliver(packet);
      return;
    }
    sock_it = bound_sockets.find(std::make_tuple(std::nullopt, 0));
    if (sock_it != bound_sockets.end()) {
      sock_it->second->deliver(packet);
      return;
    }
  }

private:
  ip::IPStack& ip_stack;
  std::unordered_set<UDPSocket*> sockets;
  hash_table<std::tuple<std::optional<ip::IPAddr>, uint16_t>, UDPSocket*> bound_sockets;
  std::unordered_set<uint16_t> used_local_ports;
};
}
