# jay -- a TCP/IP stack
The goal of this project is to build an implementation of IPv4/v6 and higher transport protocols (TCP, UDP, maybe QUIC) supporting a minimal subset of features needed for a host to work reasonably well in modern networks. Ultimately, **this is not an attempt at a production-grade implementation**, but rather an excercise in learning the innards of TCP/IP (and also familiarizing myself with C++20 features in doing so).

The current state is a bit of a mess -- below is a tracking list of features/issues/bugs in no particular order:
- tests, tests, tests
- concurrency support (RCU)
- IPv4 broadcast handling
- weak host model (check destination IPs on input, optionally RPF)
- get rid of exceptions in `IPStack` (use `Result` with an error type shared with sockets?)
- emit ICMP messages on errors
- buffers are not allocated with any aligment by default (needs a custom shared_ptr)
- loopback interface/local delivery
- source address selection (may combine with the IPv6 implementation)
- basic forwarding support
- IPv4 option processing (just RTRALT for IGMP, really)
- path MTU discovery
- IPv6 (needs generic multicast support first)
- TCP
- IPv4 identification is only filled in fragmented packets + does not get copied (see forwarding)
- move the TAP interface implementation into the library tree (possibly w/ vector io/io_uring?)
- handle ICMP Destination unreachable messages (deliver them to sockets)
- `SmallVec` double-calls destructors
- structures in `util` need polishing (const iterators, more tests)
- BufChunk gets passed by value a lot
- performance (benchmarks; optimize happy paths; check inlining and LTO for all the indirection)
- better hashtable (open addressing, randomized hashing)
- move stuff out of headers
- move ostream debug printers to a sepratate file
