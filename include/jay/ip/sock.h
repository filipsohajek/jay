#pragma once

#include "jay/pbuf.h"
#include "jay/util/hashtable.h"
#include <functional>
#include <random>
#include <unordered_set>

namespace jay::ip {
class IPStack;
class SocketTable;
class Socket {
  friend class SocketTable;

public:
  Socket(const Socket &) = delete;
  Socket(Socket &&) = delete;
  Socket &operator=(const Socket &) = delete;
  Socket &operator=(Socket &&) = delete;
  Socket(IPStack& ip_stack, IPProto protocol) : ip_stack(ip_stack), _protocol(protocol) {}
  ~Socket();

  std::optional<IPAddr> local_addr() const { return _local_addr; }
  std::optional<IPAddr> remote_addr() const { return _remote_addr; }
  IPProto protocol() const { return _protocol; }

  virtual void deliver(const PBuf&) = 0;
  virtual void listen(std::optional<IPAddr> local_addr = std::nullopt, uint16_t local_port = 0);
  virtual void connect(IPAddr remote_addr, uint16_t remote_port, std::optional<IPAddr> local_addr = std::nullopt, uint16_t local_port = 0);
protected:
  Socket(IPStack &ip_stack) : ip_stack(ip_stack) {}
  void send_pbuf(PBuf, std::optional<IPAddr> = std::nullopt);

  IPStack &ip_stack;
  IPProto _protocol;
  std::optional<IPAddr> _local_addr, _remote_addr;
  uint16_t _local_port = 0, _remote_port = 0;
  bool listening = false, connected = false;
};

class SocketTable {
  using ConnectedKey = std::tuple<IPProto, IPAddr, uint16_t, IPAddr, uint16_t>;
  using ListeningKey = std::tuple<IPProto, IPAddr, uint16_t>;
  using SelAddrFn = std::function<IPAddr(std::optional<IPAddr>)>;

public:
  uint16_t port_sel_min = 49152;
  uint16_t port_sel_max = 65535;

  SocketTable(SelAddrFn sel_addr_fn) : sel_addr_fn(std::move(sel_addr_fn)) {}

  void listen(Socket *sock, std::optional<IPAddr> local_addr = std::nullopt,
              uint16_t local_port = 0) {
    auto bind_key = bind(sock, local_addr, local_port);
    if (listening.contains(bind_key))
      throw std::runtime_error("address already in use");
    listening.emplace(bind_key, sock);
    sock->listening = true;
  }

  void connect(Socket *sock, IPAddr remote_addr, uint16_t remote_port,
               std::optional<IPAddr> local_addr = std::nullopt,
               uint16_t local_port = 0) {
      std::tie(std::ignore, local_addr, local_port) =
          bind(sock, local_addr, local_port, remote_addr, remote_port);

    ListeningKey listen_key{sock->_protocol, local_addr.value(), local_port};
    listening.erase(listen_key);

    ConnectedKey conn_key{sock->_protocol, local_addr.value(), local_port,
                          remote_addr, remote_port};
    if (connected.contains(conn_key))
      throw std::runtime_error("address already in use");
    connected.emplace(conn_key, sock);

    sock->_remote_addr = remote_addr;
    sock->_remote_port = remote_port;
    sock->connected = true;
  }

  void deliver(PBuf packet) {
    IPAddr src_addr = packet->ip().src_addr();
    IPAddr dst_addr = packet->ip().dst_addr();
    IPProto proto;
    uint16_t src_port, dst_port;
    if (packet->is_udp()) {
      proto = IPProto::UDP;
      src_port = packet->udp().src_port();
      dst_port = packet->udp().dst_port();
    }

    auto conn_it =
        connected.find({proto, dst_addr, dst_port, src_addr, src_port});
    if (conn_it != connected.end()) {
      conn_it->second->deliver(std::move(packet));
      return;
    }

    auto listen_it = listening.find({proto, dst_addr, dst_port});
    if (listen_it != listening.end()) {
      listen_it->second->deliver(std::move(packet));
      return;
    }
  }

  void remove(Socket *sock) {
    if (sock->listening) {
      listening.erase(
          {sock->_protocol, sock->_local_addr.value(), sock->_local_port});
    } else if (sock->connected) {
      connected.erase({sock->_protocol, sock->_local_addr.value(),
                       sock->_local_port, sock->_remote_addr.value(),
                       sock->_remote_port});
    }
  }

private:
  ListeningKey bind(Socket *sock,
                    std::optional<IPAddr> local_addr = std::nullopt,
                    uint16_t local_port = 0,
                    std::optional<IPAddr> remote_addr = std::nullopt,
                    uint16_t remote_port = 0) {
    if (!local_addr.has_value())
      local_addr = sel_addr_fn(remote_addr);

    if (!local_port)
      local_port = find_free_port(sock->_protocol, port_sel_min, port_sel_max,
                                  local_addr.value(), remote_addr, remote_port);
    if (!local_port)
      throw std::runtime_error("no free ports");

    sock->_local_addr = local_addr;
    sock->_local_port = local_port;

    return {sock->_protocol, local_addr.value(), local_port};
  }

  uint16_t find_free_port(IPProto proto, uint16_t min, uint16_t max,
                          IPAddr local_addr,
                          std::optional<IPAddr> remote_addr = std::nullopt,
                          uint16_t remote_port = 0) {
    std::mt19937 mt;
    std::uniform_int_distribution<uint16_t> port_unif(min, max);

    uint16_t tried_ports = 0;
    uint16_t num_ports = max - min;
    uint16_t local_port = 0;
    while (tried_ports < num_ports) {
      local_port = port_unif(mt);
      if (remote_addr.has_value()) {
        if (!connected.contains({proto, local_addr, local_port,
                                 remote_addr.value(), remote_port}))
          break;
      } else {
        if (!listening.contains({proto, local_addr, local_port}))
          break;
      }
      tried_ports++;
    }

    if (tried_ports == num_ports) {
      return 0;
    }

    return local_port;
  }

  hash_table<ConnectedKey, Socket *> connected;
  hash_table<ListeningKey, Socket *> listening;

  SelAddrFn sel_addr_fn;
};
}; // namespace jay::ip
