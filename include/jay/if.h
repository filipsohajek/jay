#pragma once

#include "jay/eth.h"
#include "jay/neigh.h"
#include "jay/pbuf.h"
namespace jay {

class Stack;
class NeighCache;

class Interface {
public:
  uint8_t hop_limit = 64;

  virtual ~Interface() {}
  /// Queue a packet for transmission on the interface. If the interface has no
  /// queue, the invocation may transmit the packet immediately, but may not
  /// block in doing so.
  virtual void enqueue(PBuf) = 0;

  /// Poll the interface for incoming packets. The [Stack] instance is supplied
  /// as the first argument, on which [Stack::input] shall be called for each
  /// processed incoming packet. The invocation may not block.
  virtual void poll_rx(Stack &) = 0;

  /// Poll the interface for transmission of queued packets. When invoked, the
  /// queue should be checked for packets that have been transmitted, freeing
  /// the [PBuf] if the transmission was sucessful and notifying the supplied
  /// [Stack] instance if an error has occured during the transmission.
  virtual void poll_tx(Stack &) = 0;

  /// Returns the MAC address of the interface. This value is assumed to be
  /// stable throughout the lifetime of the interface.
  virtual HWAddr addr() const noexcept = 0;
  
  /// Returns the maximum size of packet (excluding the Ethernet) header the the interface can transmit.
  virtual uint16_t mtu() const noexcept = 0;
  NeighCache neighbours;
  
  std::array<uint8_t, 8> ident() const {
    HWAddr haddr = addr();
    return {haddr[0], haddr[1], haddr[2], 0xff, 0xfe, haddr[3], haddr[4], haddr[5]}; 
  }
};
} // namespace jay
