#include <cerrno>
#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <thread>
#include <unistd.h>
#include <stdio.h>
#include <netdb.h>
#include <memory>

#include <net/if.h> 
#include <linux/if_tun.h> 
#include <linux/if_arp.h>

#include <sys/ioctl.h>


#include "jay/if.h"
#include "jay/pbuf.h"
#include "jay/stack.h"

class TAPInterface : public jay::Interface {
public:
  TAPInterface(std::string if_name, jay::HWAddr hwaddr, size_t mtu = 1500) : recv_packet(mtu + jay::EthHeader::SIZE), if_name(if_name), _hwaddr(hwaddr) {
    fd = open("/dev/net/tun", O_RDWR);
    if (fd == -1) {
      perror("tun open");
      return;
    }
    assert(if_name.size() + 1 <= IFNAMSIZ);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
    strncpy(ifr.ifr_name, if_name.data(), if_name.size() + 1);
    if (ioctl(fd, TUNSETIFF, &ifr) == -1) {
      perror("TUNSETIFF ioctl");
      return;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
      perror("fcntl O_NONBLOCK");
      return;
    }

    set_mtu(mtu);
  }
  
  void enqueue(jay::PBuf packet) override {
    //std::cout << "enqueue:" << *packet;
    jay::Buf contig_buf = packet->as_contiguous();
    if (write(fd, contig_buf.begin().contiguous().data(), contig_buf.size()) == -1) {
      perror("write");
      return;
    }
  }

  void poll_rx(jay::Stack& stack) override {
    while (true) {
    int read_len;
    if ((read_len = read(fd, recv_packet->begin().contiguous().data(), recv_packet->size())) == -1) {
      if (errno == EAGAIN) {
        return;
      }
      perror("read");
      return;
    }
    std::cout << std::format("read {} bytes from interface\n", read_len);
    recv_packet->truncate(read_len);
//    std::cout << "poll_rx:" << *recv_packet;
    stack.input(this, std::move(recv_packet)); 
    recv_packet = jay::PBuf(_mtu + jay::EthHeader::SIZE);
    }
  }

  void poll_tx(jay::Stack&) override {
  }

  jay::HWAddr addr() const noexcept override {
    return _hwaddr;
  }

  uint16_t mtu() const noexcept override {
    return _mtu;
  }

  void set_mtu(uint16_t mtu) {
    int sock = socket(PF_INET, SOCK_STREAM, 0);
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_mtu = mtu;
    strncpy(ifr.ifr_name, if_name.data(), if_name.size() + 1);
    if (ioctl(sock, SIOCSIFMTU, &ifr) == -1) {
      perror("SIOCSIFMTU ioctl");
      return;
    }
    close(sock);
    _mtu = mtu;
  }

private:
  jay::PBuf recv_packet;
  std::string if_name;
  int fd;
  jay::HWAddr _hwaddr;
  uint16_t _mtu;
};

int main() {
  jay::Stack stack;
  auto tap = std::make_shared<TAPInterface>("tap0", jay::HWAddr {0x02, 0xa0, 0x04, 0xd3, 0x00, 0x11}, 1500);
  stack.add_interface(tap);
  stack.ip.router().add_route(jay::ip::IPv4Addr {10, 0, 0, 0}, 24, tap.get(), std::nullopt, jay::ip::IPv4Addr {10, 0, 0, 2});
  stack.ip.assign_ip(tap.get(), jay::ip::IPv4Addr {10, 0, 0, 2}, 24);


  stack.ip.mcast_join(tap.get(), jay::ip::IPv4Addr {224, 0, 0, 3});

  jay::Buf payload(10000);
  auto payload_span = payload.begin().contiguous();
  uint8_t ctr = 0;
  for (auto it = payload_span.subspan(6).begin(); it < payload_span.end(); it++, ctr++) {
    *it = ctr;
  }
  stack.ip.mcast_leave(tap.get(), jay::ip::IPv4Addr {224, 0, 0, 3});

  auto udp_sock = stack.ip.udp_sock();
  udp_sock.listen(std::nullopt, 12345);
  udp_sock.on_data_fn = [](jay::udp::UDPSocket& sock, const jay::Buf& buf, jay::ip::IPAddr addr, uint16_t remote_port) {
    std::cout << "socked received " << buf.size() << " bytes from " << addr << ":" << remote_port << "\n";
    sock.send(buf, addr, remote_port);
  };
  
  while (true) {
    stack.poll();
    std::this_thread::sleep_for(std::chrono::milliseconds {200});
  }
}
