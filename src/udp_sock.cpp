#include "jay/udp/udp_sock.h"
#include "jay/ip/stack.h"

namespace jay::udp {
UDPSocket::~UDPSocket() {
  ip_stack.udp().remove_socket(this);
}
};
