# comp9331 assignment written by Maowen Zhou
# Using python 3.7
from socket import *
import time
import sys
import random
import pickle
import struct
import threading


class Header:
    def __init__(self):
        self.file_name = sys.argv[3]
        self.source_IP, self.source_port = get_host_IP_port()
        self.destination_IP = sys.argv[1]
        self.destination_port = int(sys.argv[2])
        self.Sequence_num = 0
        self.receiver_seq = 0
        self.ACK_num = 0
        self.SYN = 0
        self.FIN = 0
        self.FINACK = 0
        self.MWS = int(sys.argv[4])
        self.MSS = int(sys.argv[5])
        self.gamma = float(sys.argv[6])
        self.state = 'closed'
        self.pDrop = float(sys.argv[7])
        self.pDuplicate = float(sys.argv[8])
        self.pCorrupt = float(sys.argv[9])
        self.pOrder = float(sys.argv[10])
        # maxOrder between [1, 6]
        self.maxOrder = int(sys.argv[11])
        self.pDelay = float(sys.argv[12])
        # maxDelay (ms)
        self.maxDelay = float(sys.argv[13]) / 1000
        self.seed = int(sys.argv[-1])
        #
        self.send_data = b''
        self.checksum = 0
        self.recv_data = b''
        self.len_send_data = 0
        self.len_recv_data = 0
        self.send_time = 0
        # timeout  (s)
        self.timeout = (500 + self.gamma * 250) / 1000
        # for the log file
        self.start_time = 0
        self.file_len = 0

    # this part of code is borrowed from the web
    def generate_checksum(self):
        checksum = 0
        data_len = len(self.send_data)
        data = self.send_data
        if (data_len % 2) == 1:
            data_len += 1
            data += struct.pack('!B', 0)

        for i in range(0, len(data), 2):
            w = (data[i] << 8) + (data[i + 1])
            checksum += w

        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = ~checksum & 0xFFFF
        self.checksum = checksum

    def pack_data(self):
        """
        Payload is bytes object.
        ----------------------------------------------------------------------------------------------------------------
        Header format: 12 fields.
        << (src IP, src Port)|(dest IP, dest Port)| seq num | ack num | SYN | FIN | MWS | MSS | payload | payload len |
        checksum| FINACK>>
        ----------------------------------------------------------------------------------------------------------------
        """
        src_ip_port = (self.source_IP, self.source_port)
        dest_ip_port = (self.destination_IP, self.destination_port)
        self.len_send_data = len(self.send_data)
        head_info = [src_ip_port, dest_ip_port, self.Sequence_num, self.ACK_num, self.SYN, self.FIN, self.MWS, self.MSS,
                     self.send_data, self.len_send_data, self.checksum, self.FINACK]
        return pickle.dumps(head_info)

    def unpack_data(self):
        # need to unpack Acknowledgement segments with no data in it sent by receiver, maybe set self.len_data to 0
        self.recv_data = pickle.loads(self.recv_data)
        (self.source_IP, self.source_port) = self.recv_data[1]
        (self.destination_IP, self.destination_port) = self.recv_data[0]
        self.receiver_seq, self.ACK_num, self.SYN, self.FIN, self.MWS, self.MSS = self.recv_data[2:8]
        self.checksum = self.recv_data[10]
        self.FINACK = self.recv_data[11]
        self.len_recv_data, self.recv_data = self.recv_data[9], self.recv_data[8]


class Timer:
    def __init__(self, duration):
        self.start_time = 0
        self.started = False
        self.tracking = 1
        self.duration = duration

    def stop(self):
        self.started = False
        self.start_time = 0

    def start(self):
        assert(not self.started)
        self.start_time = time.time()
        self.started = True

    def restart(self):
        if self.started:
            self.stop()
        self.start()

    def time(self):
        if self.started:
            return time.time() - self.start_time

    def timeout(self):
        if self.started:
            if time.time() - self.start_time >= self.duration:
                return True
            return False


def get_host_IP_port():
    """
    Elegantly get the IP address and port number of the sender machine
    """
    s = socket(AF_INET, SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        host_ip, host_port = s.getsockname()
    finally:
        s.close()
    return host_ip, host_port


def read_PDF_file(file_name):
    """
    Get the content of the PDF file in byte form
    """
    try:
        with open(file_name, 'rb') as file_to_send:
            content_of_file = file_to_send.read()
            return content_of_file
    except FileNotFoundError:
        print(f"No file called {file_name}in the current directory.")


def chop_up_file(file_content, MSS):
    """
    Generate a dictionary, where key is like sequence number, value is byte_data with the size of MSS
    """
    content_len = len(file_content)
    content_list = [file_content[i:i + MSS] for i in range(0, content_len, MSS)]
    content_list_len = len(content_list)
    content_dict = dict()
    for i in range(content_list_len):
        content_dict[i * MSS] = content_list[i]
    return content_dict


def valid_IP_Port(ip_address, port):
    """
    Make sure the IP address is in the correct format
    """
    num_list = ip_address.split('.')
    if len(num_list) != 4:
        return False
    for i in num_list:
        if int(i) > 255:
            return False
    if not (10000 <= port <= 65536):
        return False
    return True


def sender_log_file(event, time_T, type_of_pckt, seq_num, num_of_data, ack_num):
    with open("Sender_log.txt", 'a+') as sender_log:
        sender_log.write(f"{event:<10}{time_T:<30.3f}{type_of_pckt:^10}{seq_num:<20}"
                         f"{num_of_data:<20}{ack_num:<20}\n")


def write_statistics(statistics):
    """
    Write the statistics of the send process at the end of the file
    """
    with open('Sender_log.txt', 'a+') as sender_log:
        sender_log.write("====================================================\n")
        sender_log.write("Size of the file (in Bytes)".ljust(28) + f"{statistics[0]}\n".rjust(72))
        sender_log.write("Segments transmitted (including drop & RXT)".ljust(28) + f"{statistics[1]}\n".rjust(39))
        sender_log.write("Number of Segments handled by PLD".ljust(28) + f"{statistics[2]}\n".rjust(51))
        sender_log.write("Number of Segments dropped".ljust(28) + f"{statistics[3]}\n".rjust(60))
        sender_log.write("Number of Segments Corrupted".ljust(28) + f"{statistics[4]}\n".rjust(60))
        sender_log.write("Number of Segments Re-ordered".ljust(28) + f"{statistics[5]}\n".rjust(60))
        sender_log.write("Number of Segments Duplicated".ljust(28) + f"{statistics[6]}\n".rjust(60))
        sender_log.write("Number of Segments Delayed".ljust(28) + f"{statistics[7]}\n".rjust(60))
        sender_log.write("Number of Retransmissions due to TIMEOUT".ljust(28) + f"{statistics[8]}\n".rjust(41))
        sender_log.write("Number of FAST RETRANSMISSION".ljust(28) + f"{statistics[9]}\n".rjust(60))
        sender_log.write("Number of DUP ACKs received".ljust(28) + f"{statistics[10]}\n".rjust(60))
        sender_log.write("====================================================\n")


def three_way_handshaking(sender_socket, head, dest_ip_port):
    """
    """
    global segment_sent
    # Initiate the connection
    head.SYN = 1
    head.FIN = 0
    head.generate_checksum()
    sender_socket.sendto(head.pack_data(), dest_ip_port)
    start_connection_time = round(time.time() - head.start_time, 3)
    sender_log_file('snd', start_connection_time, 'S', head.Sequence_num, head.len_send_data, head.ACK_num)
    head.recv_data, addr = sender_socket.recvfrom(1024)
    recv_SA_time = round(time.time() - head.start_time, 3)
    head.unpack_data()
    # when receiving segments source_ip_port and dest_ip_port are swapped.
    sender_log_file('rcv', recv_SA_time, 'SA', head.receiver_seq, head.len_recv_data, head.ACK_num)
    if head.ACK_num == head.Sequence_num + 1:
        print("Connection is established, ready to transmit data.")
        head.SYN = 0
        head.Sequence_num = head.ACK_num
        head.ACK_num = head.receiver_seq + 1
        head.receiver_seq += 1
        head.pack_data()
        head.generate_checksum()
        sender_socket.sendto(head.pack_data(), addr)
        time_stamp = round(time.time() - head.start_time, 3)
        sender_log_file('snd', time_stamp, 'A', head.Sequence_num, head.len_send_data, head.ACK_num)
        head.state = 'connected'
        segment_sent += 2


def PLD_module(state_head, sender_socket, dest_ip_port):
    odds = random.random()
    reorder_holder = set()
    reorder_counter = 0
    reorder_head = Header()
    reorder_head.start_time = state_head.start_time
    global segment_dropped, segment_corrupted, sent_Seq
    global segment_reorderd, segment_duplicated, segment_delayed

    if odds < state_head.pDrop:
        time_stamp = round(time.time() - state_head.start_time, 3)
        sender_log_file('drop', time_stamp, 'D', state_head.Sequence_num, state_head.len_send_data,
                        state_head.ACK_num)
        segment_dropped += 1
        reorder_counter += 1
    elif odds < state_head.pDuplicate:
        time_stamp = round(time.time() - state_head.start_time, 3)
        sender_socket.sendto(state_head.pack_data(), dest_ip_port)
        sender_log_file('snd', time_stamp, 'D', state_head.Sequence_num, state_head.len_send_data,
                        state_head.ACK_num)
        time_stamp = round(time.time() - state_head.start_time, 3)
        sender_socket.sendto(state_head.pack_data(), dest_ip_port)
        sender_log_file('snd/dup', time_stamp, 'D', state_head.Sequence_num, state_head.len_send_data,
                        state_head.ACK_num)
        reorder_counter += 2
        segment_duplicated += 1
    elif odds < state_head.pCorrupt:
        time_stamp = round(time.time() - state_head.start_time, 3)
        # introduce 1 bit error
        state_head.send_data = state_head.send_data[:-1] + b'*'
        sender_socket.sendto(state_head.pack_data(), dest_ip_port)
        sender_log_file('snd/corr', time_stamp, 'D', state_head.Sequence_num, state_head.len_send_data,
                        state_head.ACK_num)
        reorder_counter += 1
        segment_corrupted += 1
    elif odds < state_head.pOrder:
        if not reorder_holder:
            reorder_holder.add(state_head.Sequence_num)
            segment_reorderd += 1
            reorder_head.Sequence_num = state_head.Sequence_num
            reorder_head.send_data = state_head.send_data
            reorder_head.len_send_data = len(reorder_head.send_data)
            reorder_head.receiver_seq = state_head.receiver_seq
            reorder_head.ACK_num = state_head.receiver_seq + reorder_head.len_recv_data
        elif reorder_holder:
            sender_socket.sendto(state_head.pack_data(), dest_ip_port)
            time_stamp = round(time.time() - state_head.start_time, 3)
            sender_log_file('snd', time_stamp, 'D', state_head.Sequence_num,
                            state_head.len_send_data, state_head.ACK_num)
            reorder_counter += 1
        if reorder_counter > state_head.maxOrder:
            reorder_counter = 0
            reorder_holder.pop()
            sender_socket.sendto(reorder_head.pack_data(), dest_ip_port)
            time_stamp = round(time.time() - reorder_head.start_time, 3)
            sender_log_file('snd/rord', time_stamp, 'D', reorder_head.Sequence_num,
                            reorder_head.len_send_data, reorder_head.ACK_num)
    elif odds < state_head.pDelay:
        time.sleep(state_head.maxDelay)
        time_stamp = round(time.time() - state_head.start_time, 3)
        sender_socket.sendto(state_head.pack_data(), dest_ip_port)
        sender_log_file('snd/dely', time_stamp, 'D', state_head.Sequence_num, state_head.len_send_data,
                        state_head.ACK_num)
        reorder_counter += 1
        segment_delayed += 1
    else:
        time_stamp = round(time.time() - state_head.start_time, 3)
        sender_socket.sendto(state_head.pack_data(), dest_ip_port)
        if state_head.Sequence_num in sent_Seq:
            sender_log_file('snd/RXT', time_stamp, 'D', state_head.Sequence_num,
                            state_head.len_send_data, state_head.ACK_num)
        else:
            sender_log_file('snd', time_stamp, 'D', state_head.Sequence_num,
                            state_head.len_send_data, state_head.ACK_num)
        reorder_counter += 1
    sent_Seq.add(state_head.Sequence_num)


def Sending(sender_socket, file_dict, dest_ip_port):
    # data transmitting
    global SendBase, NextSeqNum, timer, state_head
    global received_ACK, sent_Seq
    global timer, segment_PLD
    global segment_sent, recv_flag
    global RXT_timeout, sampleRTT

    sent_Seq = set()
    received_ACK = 0
    timer = Timer(state_head.timeout)
    sampleRTT = Timer(0)
    RXT_head = Header()
    RXT_head.receiver_seq = 1
    RXT_head.start_time = state_head.start_time
    while True:
        if received_ACK - 1 == state_head.file_len:
            break
        while NextSeqNum < SendBase + state_head.MWS and NextSeqNum < state_head.file_len:
            state_head.Sequence_num = NextSeqNum
            state_head.send_data = file_dict[NextSeqNum - 1]
            # generate checksum just for the data
            state_head.generate_checksum()
            state_head.len_send_data = len(state_head.send_data)
            state_head.ACK_num = state_head.receiver_seq + state_head.len_recv_data
            PLD_module(state_head, sender_socket, dest_ip_port)
            if not timer.started:
                timer.start()
                timer.tracking = SendBase
            # keep track of Seq handled by PLD
            NextSeqNum += state_head.len_send_data
            # if (not sampleRTT.started) and (NextSeqNum not in sent_Seq):
            #     sampleRTT.start()
            #     sampleRTT.tracking = NextSeqNum
            segment_sent += 1
            segment_PLD += 1
        # timeout and retrasmit
        if timer.timeout() and recv_flag == 0:
            RXT_head.Sequence_num = timer.tracking
            RXT_head.send_data = file_dict[timer.tracking - 1]
            # generate checksum just for the data
            RXT_head.generate_checksum()
            RXT_head.len_send_data = len(RXT_head.send_data)
            RXT_head.ACK_num = RXT_head.receiver_seq + RXT_head.len_recv_data
            PLD_module(RXT_head, sender_socket, dest_ip_port)
            timer.restart()
            RXT_timeout += 1
            segment_sent += 1
            segment_PLD += 1


def Receiving(recv_head, sender_socket, file_dict, dest_ip_port):
    global EstimatedRTT, DevRTT, SendBase, NextSeqNum
    global timer, state_head, ACK_count
    global received_ACK, recv_flag
    global segment_sent, segment_PLD
    global fast_RXT, dup_ACK, sampleRTT

    ACK_count = 0
    while True:
        recv_flag = 0
        recv_head.recv_data = sender_socket.recvfrom(1024)[0]
        time_stamp = round(time.time() - state_head.start_time, 3)
        recv_head.unpack_data()
        received_ACK = recv_head.ACK_num
        # file transmission complete
        if received_ACK - 1 == state_head.file_len:
            sender_log_file('rcv', time_stamp, 'A', recv_head.receiver_seq,
                            recv_head.len_recv_data, recv_head.ACK_num)
            print("PDF file has been successfully transmitted, about to terminate the connection.")
            state_head.state = 'FIN'
            if state_head.state == 'FIN':
                # send FIN
                state_head.FIN = 1
                state_head.Sequence_num = recv_head.ACK_num
                state_head.send_data = b''
                state_head.len_send_data = len(state_head.send_data)
                state_head.ACK_num = state_head.receiver_seq + state_head.len_send_data
                time_stamp = round(time.time() - state_head.start_time, 3)
                state_head.generate_checksum()
                sender_socket.sendto(state_head.pack_data(), dest_ip_port)
                sender_log_file('snd', time_stamp, 'F', state_head.Sequence_num, state_head.len_send_data,
                                state_head.ACK_num)
                state_head.state = 'FINACK'
            if state_head.state == 'FINACK':
                recv_head.recv_data = sender_socket.recvfrom(1024)[0]
                time_stamp = round(time.time() - state_head.start_time, 3)
                recv_head.unpack_data()
                if recv_head.FINACK == 1:
                    sender_log_file('rcv', time_stamp, 'A', recv_head.receiver_seq, recv_head.len_recv_data,
                                    recv_head.ACK_num)
                    state_head.state = 'receiverFIN'
            if state_head.state == 'receiverFIN':
                recv_head.recv_data = sender_socket.recvfrom(1024)[0]
                time_stamp = round(time.time() - state_head.start_time, 3)
                recv_head.unpack_data()
                if recv_head.FIN == 1:
                    sender_log_file('rcv', time_stamp, 'F', recv_head.receiver_seq, recv_head.len_recv_data,
                                    recv_head.ACK_num)
                    state_head.state = 'senderACK'
            if state_head.state == 'senderACK':
                state_head.FIN = 0
                state_head.Sequence_num = recv_head.ACK_num
                state_head.ACK_num = state_head.receiver_seq + 1
                state_head.generate_checksum()
                sender_socket.sendto(state_head.pack_data(), dest_ip_port)
                time_stamp = round(time.time() - state_head.start_time, 3)
                sender_log_file('snd', time_stamp, 'A', state_head.Sequence_num, state_head.len_send_data,
                                state_head.ACK_num)
            segment_sent += 2
            statistics = [state_head.file_len, segment_sent, segment_PLD, segment_dropped, segment_corrupted,
                              segment_reorderd, segment_duplicated, segment_delayed, RXT_timeout, fast_RXT, dup_ACK]
            print("Writing statistics into Sender log file....")
            write_statistics(statistics)
            print("All done.")
            if timer.started:
                timer.stop()
            sender_socket.close()
            break
        else:
            # receive ACKs
            if received_ACK > SendBase:
                # refresh the timeout value
                # len_tracking_data = len(file_dict[sampleRTT.tracking - 1])
                # # print("sampleRTT.tracking->", sampleRTT.tracking)
                # print("timer.duration->", timer.duration)
                # if sampleRTT.started and sampleRTT.tracking + len_tracking_data == received_ACK:
                #     # print("received_ACK->", received_ACK)
                #     time_value = sampleRTT.time() * 1000
                #     # print(time_value/1000)
                #     EstimatedRTT = 0.875 * EstimatedRTT + 0.125 * time_value
                #     DevRTT = 0.75 * DevRTT + 0.25 * abs(time_value - EstimatedRTT)
                #     calculated_interval = (EstimatedRTT + state_head.gamma * DevRTT) / 1000
                #     if 0 < calculated_interval <= 60:
                #         timer.duration = calculated_interval
                #     sampleRTT.stop()
                sender_log_file('rcv', time_stamp, 'A', recv_head.receiver_seq,
                                recv_head.len_recv_data, recv_head.ACK_num)
                SendBase = received_ACK
                if timer.started:
                    timer.tracking = SendBase
                    timer.restart()
                ACK_count = 0
                recv_flag = 1
            # receive duplicate ACK
            else:
                ACK_count += 1
                sender_log_file('rcv/DA', time_stamp, 'A', recv_head.receiver_seq,
                                recv_head.len_recv_data, recv_head.ACK_num)
                dup_ACK += 1
            # fast retransmit
            if ACK_count == 3:
                RXT_head = Header()
                RXT_head.receiver_seq = 1
                RXT_head.start_time = state_head.start_time
                RXT_head.Sequence_num = timer.tracking
                RXT_head.send_data = file_dict[timer.tracking - 1]
                # generate checksum just for the data
                RXT_head.generate_checksum()
                RXT_head.len_send_data = len(RXT_head.send_data)
                RXT_head.ACK_num = RXT_head.receiver_seq + RXT_head.len_recv_data
                PLD_module(RXT_head, sender_socket, dest_ip_port)
                timer.restart()
                fast_RXT += 1
                segment_sent += 1
                segment_PLD += 1


def main_function():
    global state_head
    global segment_sent, segment_PLD, segment_dropped, segment_corrupted
    global segment_reorderd, segment_duplicated, segment_delayed
    global RXT_timeout, fast_RXT, dup_ACK
    segment_sent = 0
    segment_PLD = 0
    segment_dropped = 0
    segment_corrupted = 0
    segment_reorderd = 0
    segment_duplicated = 0
    segment_delayed = 0
    RXT_timeout = 0
    fast_RXT = 0
    dup_ACK = 0
    state_head = Header()
    try:
        if not valid_IP_Port(state_head.destination_IP, state_head.destination_port):
            raise ValueError
    except ValueError:
        print("Sorry, incorrect IP address or Port number, safe Port number [10000 <-> 65536].")
        sys.exit()
    # read PDF file
    file_content = read_PDF_file(state_head.file_name)
    state_head.file_len = len(file_content)
    file_dict = chop_up_file(file_content, state_head.MSS)
    sender_socket = socket(AF_INET, SOCK_DGRAM)
    random.seed(state_head.seed)
    state_head.start_time = time.time()
    dest_ip_port = (state_head.destination_IP, state_head.destination_port)
    # send the len of the file to the receiver
    sender_socket.sendto(str(state_head.file_len).encode(), dest_ip_port)
    recv_head = Header()
    recv_head.start_time = state_head.start_time
    global EstimatedRTT, DevRTT, SendBase, NextSeqNum
    SendBase = 1
    NextSeqNum = 1
    EstimatedRTT = 500
    DevRTT = 250
    # three way handshake
    if state_head.state == 'closed':
        three_way_handshaking(sender_socket, state_head, dest_ip_port)
        print("Transmitting the file, please wait patiently.")

    sending = threading.Thread(target=Sending, args=(sender_socket, file_dict, dest_ip_port))
    receiving = threading.Thread(target=Receiving, args=(recv_head, sender_socket, file_dict, dest_ip_port))
    for proc in (sending, receiving):
        proc.start()
    for proc in (sending, receiving):
        proc.join()


if __name__ == '__main__':
    main_function()