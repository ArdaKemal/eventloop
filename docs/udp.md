# UDP API contract

Shared results, ownership, affinity, and cancellation: [coroutines](coroutines.md).

- Include `eventloop/udp_socket.h` for IPv4 or IPv6 datagrams using
  `eventloop::ip_endpoint`. Datagrams stay atomic:
  empty datagrams succeed with size zero, and a truncated receive consumes the
  datagram and reports `EMSGSIZE`. At most one receive and one send may be
  pending per socket; a duplicate same-direction operation reports `EBUSY`.
