import datetime
from math import floor, log10
import dpkt
import socket
from dpkt.tcp import TCP, TH_SYN, TH_ACK, parse_opts, TCP_OPT_WSCALE, TH_FIN, TH_PUSH
SENDER_IP = '130.245.145.12'
RECEIVER_IP = '128.208.2.198'

def readFileA(filename):
    pcap = dpkt.pcap.Reader(open(filename, 'rb'))
    tcp_flow = 0
    a = {}
    b = {}
    c = {}
    flows_scaling_factor = {}
    print2times = {}
    print2times_sender = {}
    start_time = {}
    triple_duplicate = {}
    timeout = {}
    RTT = {}
    last_seq = {}
    all_ack = {}
    all_ack_first_timestamp = {}
    start_cwnd_timestamp = {}
    three_cwnd_size = {}
    counter_cwnd_size = {}
    for index,(ts, buf) in enumerate(pcap):
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            if type(ip.data) == TCP:
                tcp = ip.data
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)
                tcp_header = {
                    "source_ip": socket.inet_ntoa(ip.src),
                    "destination_ip": socket.inet_ntoa(ip.dst),
                    "source_port": tcp.sport,
                    "destination_port": tcp.dport,
                    "sequence_number" : tcp.seq,
                    "acknowledgement_number": tcp.ack,
                    "flags": tcp.flags,
                    "options": {i[0]: int.from_bytes(i[1], byteorder='little') for i in parse_opts(tcp.opts)}
                }
                #PART A
                #------------------------------------------------------------------------
                #1st Handshake
                if ((tcp.flags & TH_SYN) and (src == SENDER_IP)):
                    tcp_flow += 1
                    print2times[tcp.seq] = 0
                    # flows_scaling_factor[tcp.seq] = parse_opts(buf) & TCP_OPT_WSCALE
                    for i in parse_opts(tcp.opts):
                        if i[0] == TCP_OPT_WSCALE:
                            flows_scaling_factor[tcp.seq] = 2**int.from_bytes(i[1], byteorder='little')
                    c[tcp.seq] = len(tcp)
                    start_time[tcp.seq]=datetime.datetime.utcfromtimestamp(ts)

                #2nd Handshake
                elif src == RECEIVER_IP and tcp.ack-1 in start_time:
                    RTT[tcp.seq+1] = (datetime.datetime.utcfromtimestamp(ts) - start_time[tcp.ack-1]).total_seconds()
                # #3rd Handshake
                # #update tcp.seq to tcp.ack
                elif src == SENDER_IP and print2times.get(tcp.seq-1,-1) != -1 :
                    del print2times[tcp.seq-1]
                    flows_scaling_factor[tcp.ack] = flows_scaling_factor[tcp.seq-1]
                    del flows_scaling_factor[tcp.seq-1]
                    start_time[tcp.ack] = start_time[tcp.seq-1]
                    del start_time[tcp.seq-1]
                    c[tcp.ack] = c[tcp.seq-1] + len(tcp)
                    del c[tcp.seq-1]
                    print2times_sender[tcp.ack] = 0
                    print2times[tcp.ack] = 0
                    #tuple = (src_ip, src_port, dst_ip, dst_port)
                    a[tcp.ack] = (src, tcp.sport, dst, tcp.dport)

                #print two packet from sender side
                elif (src == SENDER_IP) and print2times_sender.get(tcp.ack,3) < 3:
                    b[tcp.ack] = b.get(tcp.ack, []) + [(tcp.seq, tcp.ack,  flows_scaling_factor[tcp.ack] * tcp.win)]
                    # print(f'Packet #: {index}, Seq #: {tcp.seq}, Ack #: {tcp.ack}, Receive Window: {tcp.win}')
                    print2times_sender[tcp.ack] = print2times_sender[tcp.ack] + 1
                #print two packet from receiver side
                elif (src == RECEIVER_IP) and print2times.get(tcp.seq,2) < 2:
                    # print(tcp.seq, print2times.get(tcp.seq,-1), print2times.get(tcp.seq,-1) > 0)

                    print2times[tcp.seq] = print2times[tcp.seq] + 1
                    b[tcp.seq] = b.get(tcp.seq, []) + [(tcp.seq, tcp.ack, flows_scaling_factor[tcp.seq] * tcp.win)]

                #count the total time
                if src == SENDER_IP and tcp.ack == 0:
                    continue
                elif src == SENDER_IP and last_seq.get(tcp.ack-1, False):

                    start_time[tcp.ack-1] = (datetime.datetime.utcfromtimestamp(ts) - start_time[tcp.ack-1]).total_seconds()
                    c[tcp.ack-1] = c[tcp.ack-1] + len(tcp)
                elif src == SENDER_IP and not last_seq.get(tcp.ack-1, False):
                    c[tcp.ack] = c.get(tcp.ack,0) + len(tcp)

                elif src == RECEIVER_IP and tcp.flags & TH_FIN:
                    last_seq[tcp.seq] = True

                # ------------------------------------------------------------------------
                #PART B:
                #Congestion Window
                if tcp.ack == 0:
                    continue
                elif src == SENDER_IP and tcp.flags & TH_ACK and tcp.flags & TH_PUSH and tcp.ack not in start_cwnd_timestamp:
                    start_cwnd_timestamp[tcp.ack] = datetime.datetime.utcfromtimestamp(ts)
                elif src == SENDER_IP and start_cwnd_timestamp.get(tcp.ack, -1) != -1 and (datetime.datetime.utcfromtimestamp(ts)-start_cwnd_timestamp[tcp.ack]).total_seconds() < round(RTT[tcp.ack], -int(floor(log10(abs(RTT[tcp.ack]))))):
                    counter_cwnd_size[tcp.ack] = counter_cwnd_size.get(tcp.ack, 0) + 1
                elif src == SENDER_IP and start_cwnd_timestamp.get(tcp.ack, -1) != -1 and (datetime.datetime.utcfromtimestamp(ts)-start_cwnd_timestamp[tcp.ack]).total_seconds() > round(RTT[tcp.ack], -int(floor(log10(abs(RTT[tcp.ack]))))):
                    if three_cwnd_size.get(tcp.ack, -1) == -1 or counter_cwnd_size[tcp.ack] not in three_cwnd_size[tcp.ack] and len(three_cwnd_size[tcp.ack]) < 3:
                        three_cwnd_size[tcp.ack] = three_cwnd_size.get(tcp.ack, []) + [counter_cwnd_size[tcp.ack]]
                    counter_cwnd_size[tcp.ack] = 1
                    start_cwnd_timestamp[tcp.ack] = datetime.datetime.utcfromtimestamp(ts)



                #duplicate Ack
                if src == SENDER_IP and all_ack_first_timestamp.get(tcp.seq, -1) == -1:
                    all_ack_first_timestamp[tcp.seq] = datetime.datetime.utcfromtimestamp(ts)
                elif src == RECEIVER_IP and tcp.flags & TH_ACK:
                    all_ack[tcp.ack] = all_ack.get(tcp.ack, 0) + 1
                #Fast Transmission
                elif src == SENDER_IP and all_ack.get(tcp.seq, 0) > 2:
                    #Fast Transmission
                    triple_duplicate[tcp.ack] = triple_duplicate.get(tcp.ack, 0) + 1
                #Slow Transmission
                elif src == SENDER_IP and RTT.get(tcp.ack, -1) != -1 and (datetime.datetime.utcfromtimestamp(ts) - all_ack_first_timestamp.get(tcp.seq, 10)).total_seconds() > RTT[tcp.ack]:
                    # print(tcp.seq)

                    timeout[tcp.ack] = timeout.get(tcp.ack, 0) + 1
                    all_ack_first_timestamp[tcp.seq] = datetime.datetime.utcfromtimestamp(ts)




    print("Number of flow initiated by sender is:", tcp_flow)
    for i in a:
        print("------------------------")
        #print a
        print(f'Src Ip Address: {a[i][0]}, Src Port: {a[i][1]}, Dst Ip Address: {a[i][2]}. Dst Port: {a[i][3]}')
        #print b
        for el in b[i][1:]:
            print(f'Seq #: {el[0]}, Ack #: {el[1]}, Window: {el[2]}')
        #print c
        print(c)

        print(f'Sender Throughput: {round(c[i]/start_time[i], 2)} bytes per second')
        #print d

        print(f'Congestion Window Size: {three_cwnd_size[i]}')
        #print e
        print(f'Triple duplicate: {triple_duplicate.get(i, None)}')
        print(f'Timeout : {timeout.get(i, None)}')


readFileA('assignment2.pcap')
