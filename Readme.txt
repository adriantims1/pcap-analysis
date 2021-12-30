(i)
This is how the program works:
1. Modules that I use in the program are datetime, math, dpkt, and socket
2. This program properly works if the sender ip is '130.245.145.12' and receiver ip is '128.208.2.198'
3. Loop over the data and only process a TCP connection 
4. While processing the data, I retrieve the necessary information and store it in a dictionary
5. After data suffices, create another loop that prints out the information for each flow.


PART A
-------
a. I retrieve the source and destination ip from the IP header, and port from the TCP header
b. Store the scale factor in the three way handshake. Get seq#, ack#, and window size from the TCP header.
   Multiply the scale factor and window size.
c. Sum the len(tcp) and timestamp. Divdes the amount by the time

PARtB
-------
a. Approximate the RTT by subtracting the 2nd step timestamp and 1st step timestamp of the three way handshake.
   Calculate the amount of packet sent on every RTT interval
b. Triple Duplicate: I store a counter for all the acks from the receiver side in a dictionary. When a sender sends the same packet,
   see whether a counter reaches 3 
   Timeout: I store all the acks from the sender side in a dictionary along with their latest timestamp. If there is a resend after 
   more than 2RTT interval, it means that it is a timeout. 

(iii)
1. Install all modules listed above.
2. Put PCAP file on the same file as the program
3. Change the filename in the program