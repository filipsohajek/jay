#pragma once

#include "jay/if.h"
#include "jay/ip/stack.h"
#include <memory>
#include <vector>
namespace jay {
class Stack {
public:
  Stack() : ip(*this) {};
  Stack(const Stack &) = delete;
  Stack &operator=(const PBuf &) = delete;
  Stack(Stack &&) = delete;

  void input(Interface *iface, PBuf packet);
  void output(PBuf packet);
  void poll();

  void add_interface(std::shared_ptr<Interface> iface);
  const std::vector<std::shared_ptr<Interface>> &interfaces() const {
    return ifaces;
  }
  ip::IPStack ip;

private:
  std::vector<std::shared_ptr<Interface>> ifaces;
};
} // namespace jay
