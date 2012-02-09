#!/usr/bin/python
import optparse
import socket
import sys
import select

def create_sockets(ttl):
  recv_socket = socket.socket(socket.AF_INET,
                              socket.SOCK_RAW,
                              socket.getprotobyname('icmp'))
  send_socket = socket.socket(socket.AF_INET,
                              socket.SOCK_DGRAM,
                              socket.getprotobyname('udp'))
  send_socket.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
  recv_socket.setblocking(0)
  return recv_socket, send_socket

def main(dest_name, max_hops):
    dest_addr = socket.gethostbyname(dest_name)
    timeout_in_seconds = 1
    ttl = 1
    while True:
        recv_socket, send_socket = create_sockets(ttl)
        send_socket.sendto("", (dest_name, 33434))
        curr_addr = None
        curr_name = None
        try:
            ready = select.select([recv_socket], [], [], timeout_in_seconds)
            if not ready[0]:
                print 'timed out'
                return
            _, curr_addr = recv_socket.recvfrom(2048)
            curr_addr = curr_addr[0]
        except socket.error:
            pass
        finally:
            send_socket.close()
            recv_socket.close()

        if curr_addr is not None:
            curr_host = "%s" % (curr_addr)
        else:
            curr_host = "*"
        print "%s" % (curr_host)

        ttl += 1
        if curr_addr == dest_addr or ttl > max_hops:
            break
        
    return 0

if __name__ == "__main__":
  parser = optparse.OptionParser(usage="%prog [options] hostname")
  parser.add_option("-m", "--max-hops", dest="max_hops",
                    help="Max hops before giving up [default: %default]",
                    default=30, metavar="MAXHOPS")
  options, args = parser.parse_args()
  if len(args) != 1:
    print 'usage: simple-trace.py [options] hostname'
    exit(0)
  else:
    dest_name = args[0]
    sys.exit(main(dest_name=dest_name,
             max_hops=int(options.max_hops)))
