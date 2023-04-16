import socket
from socket import *
import os
import sys
import struct
import time
import select
import binascii
import pandas as pd

ICMP_ECHO_REQUEST = 8
MAX_HOPS = 60
TIMEOUT = 2.0
TRIES = 1


# The packet that we shall send to each router along the path is the ICMP echo
# request packet, which is exactly what we had used in the ICMP ping exercise.
# We shall use the same packet that we built in the Ping exercise

def checksum(string):
    # In this function we make the checksum of our packet
    csum = 0
    countTo = (len(string) // 2) * 2
    count = 0

    while count < countTo:
        thisVal = (string[count + 1]) * 256 + (string[count])
        csum += thisVal
        csum &= 0xffffffff
        count += 2

    if countTo < len(string):
        csum += (string[len(string) - 1])
        csum &= 0xffffffff

    csum = (csum >> 16) + (csum & 0xffff)
    csum = csum + (csum >> 16)
    answer = ~csum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer


def build_packet():
    # Fill in start
    # In the sendOnePing() method of the ICMP Ping exercise ,firstly the header of our
    # packet to be sent was made, secondly the checksum was appended to the header and
    # then finally the complete packet was sent to the destination.

    # Make the header in a similar way to the ping exercise.
    # Append checksum to the header.

    # Don’t send the packet yet , just return the final packet in this function.

    ID = os.getpid() & 0xffff

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, 0, ID, 1)
    data = struct.pack("d", time.time())

    checksum_val = checksum(header + data)
    if sys.platform == 'darwin':
        checksum_val = socket.htons(checksum_val) & 0xffff
    else:
        checksum_val = htons(checksum_val)

    header = struct.pack("bbHHh", ICMP_ECHO_REQUEST, 0, checksum_val, ID, 1)
    # Fill in end

    # So the function ending should look like this
    packet = header + data
    return packet


def get_route(hostname):
    timeLeft = TIMEOUT
    df = pd.DataFrame(columns=['Hop Count', 'Try', 'IP', 'Hostname', 'Response Code'])
    destAddr = gethostbyname(hostname)

    for ttl in range(1, MAX_HOPS):
        for tries in range(TRIES):
            # Fill in start
            # Make a raw socket named mySocket
            mySocket = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)
            mySocket.bind(("", 0))
            # Fill in end
            mySocket.setsockopt(IPPROTO_IP, IP_TTL, struct.pack('I', ttl))
            mySocket.settimeout(TIMEOUT)
            recvPacket = b''
            addr = 0
            try:
                d = build_packet()
                mySocket.sendto(d, (hostname, 0))
                t = time.time()
                startedSelect = time.time()
                whatReady = select.select([mySocket], [], [], timeLeft)
                howLongInSelect = (time.time() - startedSelect)
                if whatReady[0] == []:  # Timeout
                    # Fill in start
                    # append response to your dataframe including hop #, try #, and "timeout" responses as required by the acceptance criteria
                    df = pd.concat([df, pd.DataFrame({'Hop Count': str(ttl), 'Try': str(tries), 'IP': '*', 'Hostname': '*', 'Response Code': 'timeout'}, index=[0])], ignore_index=True)
                    # print(df)
                    # Fill in end
                    recvPacket = mySocket.recvfrom(1024)
                    addr = recvPacket[1]
                    print(recvPacket, "  ", addr)
                    timeReceived = time.time()
                    timeLeft = timeLeft - howLongInSelect
                if timeLeft <= 0:
                    # Fill in start
                    # append response to your dataframe including hop #, try #, and "timeout" responses as required by the acceptance criteria
                    # df = df.append({'Hop Count': str(ttl), 'Try': str(tries+1), 'IP': '*', 'Hostname': '*', 'Response Code': 'timeout'}, ignore_index=True)
                    df = pd.concat([df, pd.DataFrame({'Hop Count': str(ttl), 'Try': str(tries), 'IP': '*', 'Hostname': '*', 'Response Code': 'timeout'}, index=[0])], ignore_index=True)
                    print(df)
                    # Fill in end
            except Exception as e:
                # print (e) # uncomment to view exceptions
                # df = df.append({'Hop Count': str(ttl), 'Try': str(tries + 1), 'IP': '*', 'Hostname': '*', 'Response Code': str(e)}, ignore_index=True)
                df = pd.concat([df, pd.DataFrame({'Hop Count': str(ttl), 'Try': str(tries), 'IP': '*', 'Hostname': '*', 'Response Code': str(e)}, index=[0])], ignore_index=True)
                continue

            else:
                # Fill in start
                # Fetch the icmp type from the IP packet
                icmpHeader = recvPacket[20:28]
                if len(icmpHeader) >= 8:
                    types, code, checksum_val, ID, sequence = struct.unpack("bbHHh", icmpHeader)
                else:
                    continue
                # Fill in end
                try:  # try to fetch the hostname of the router that returned the packet - don't confuse with the hostname that you are tracing
                    # Fill in start
                    routerHostname = gethostbyaddr(addr[0])
                    # Fill in end
                except herror:  # if the router host does not provide a hostname use "hostname not returnable"
                    # Fill in start
                    routerHostname = "hostname not returnable"
                    # Fill in end

                if types == 11:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    # Fill in start
                    # You should update your dataframe with the required column field responses here
                    # df = df.append({'Hop Count': str(ttl), 'Try': str(tries + 1), 'IP': addr[0], 'Hostname': routerHostname, 'Response Code': 'TTL exceeded'}, ignore_index=True)
                    df = pd.concat([df, pd.DataFrame({'Hop Count': str(ttl), 'Try': str(tries), 'IP': str(addr), 'Hostname': str(routerHostname), 'Response Code': 'TTL exceeded'}, index=[0])], ignore_index=True)
                    print(df)
                    # Fill in end
                elif types == 3:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    # Fill in start
                    # You should update your dataframe with the required column field responses here
                    # df = df.append({'Hop Count': str(ttl), 'Try': str(tries + 1), 'IP': addr[0], 'Hostname': routerHostname, 'Response Code': 'Destination Unreachable'}, ignore_index=True)
                    df = pd.concat([df, pd.DataFrame({'Hop Count': str(ttl), 'Try': str(tries), 'IP': str(addr), 'Hostname': str(routerHostname), 'Response Code': 'Destination Unreachable'}, index=[0])], ignore_index=True)
                    print(df)
                    # Fill in end
                elif types == 0:
                    bytes = struct.calcsize("d")
                    timeSent = struct.unpack("d", recvPacket[28:28 + bytes])[0]
                    # Fill in start
                    # You should update your dataframe with the required column field responses here
                    # df = df.append({'Hop Count': str(ttl), 'Try': str(tries + 1), 'IP': addr[0], 'Hostname': routerHostname, 'Response Code': 'Success'}, ignore_index=True)
                    df = pd.concat([df, pd.DataFrame({'Hop Count': str(ttl), 'Try': str(tries), 'IP': str(addr), 'Hostname': str(routerHostname), 'Response Code': 'Success'}, index=[0])], ignore_index=True)
                    print(df)
                    # Fill in end
                    return df
                else:
                    # Fill in start
                    # If there is an exception/error to your if statements, you should append that to your df here
                    # df = df.append({'Hop Count': str(ttl), 'Try': str(tries + 1), 'IP': '*', 'Hostname': '*', 'Response Code': 'Unknown'}, ignore_index=True)
                    df = pd.concat([df, pd.DataFrame({'Hop Count': str(ttl), 'Try': str(tries), 'IP': str(addr), 'Hostname': str(routerHostname), 'Response Code': 'Unknown'}, index=[0])], ignore_index=True)
                    print(df)
                    # Fill in end
                break
            finally:
                mySocket.close()
    return df


if __name__ == '__main__':
    get_route("google.co.il")
