# comp9331 assignment written by Maowen Zhou
# Using python 3.7

from socket import *
import struct
import time
import sys
import pickle


# elegantly get the IP address of the host machine
def get_host_IP():
    s = socket(AF_INET, SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        host_ip = s.getsockname()[0]
    finally:
        s.close()
    return host_ip


class Header:
    def __init__(self):
        self.source_IP = get_host_IP()
        self.source_port = 0
        self.destination_IP = ''
        self.destination_port = 0
        self.Sequence_num = 0
        self.sender_seq = 0
        self.ACK_num = 0
        self.recv_ACK = 0
        self.SYN = 0
        self.FIN = 0
        self.FINACK = 0
        self.MWS = 0
        self.MSS = 0
        self.gamma = 0
        self.state = 'closed'
        self.file_name = ''
        self.send_data = b''
        self.checksum = 0
        self.recv_data = b''
        self.len_send_data = 0
        self.len_recv_data = 0
        # for the log file
        self.start_time = 0
        self.file_len = 0
        self.total_segments = 0
        self.data_segments = 0
        self.segment_bit_error = 0
        self.data_segment_duplicate = 0
        self.dup_ACK_sent = 0

    def generate_checksum(self):
        checksum = 0
        data_len = len(self.recv_data)
        data = self.recv_data
        if (data_len % 2) == 1:
            data_len += 1
            data += struct.pack('!B', 0)

        for i in range(0, len(data), 2):
            w = (data[i] << 8) + (data[i + 1])
            checksum += w

        checksum = (checksum >> 16) + (checksum & 0xFFFF)
        checksum = ~checksum & 0xFFFF
        return checksum

    # def verify_checksum(self, checksum):
    #     data_len = len(self.recv_data)
    #     data = self.recv_data
    #     if (data_len % 2) == 1:
    #         data_len += 1
    #         data += struct.pack('!B', 0)
    #
    #     for i in range(0, len(data), 2):
    #         w = (data[i] << 8) + (data[i + 1])
    #         checksum += w
    #         checksum = (checksum >> 16) + (checksum & 0xFFFF)
    #     if checksum == 0xFFFF:
    #         return True
    #     else:
    #         return False

    def pack_data(self):
        """
        Payload is bytes object.
        :return:
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
        self.sender_seq, self.recv_ACK, self.SYN, self.FIN, self.MWS, self.MSS = self.recv_data[2:8]
        self.checksum = self.recv_data[10]
        self.FINACK = self.recv_data[11]
        self.len_recv_data, self.recv_data = self.recv_data[9], self.recv_data[8]


def receiver_log_file(event, time_T, type_of_pckt, seq_num, num_of_data, ack_num):
    with open('Receiver_log.txt', 'a+') as receiver_log:
        receiver_log.write(f"{event:<10}{time_T:>30.3f}{type_of_pckt:^10}{seq_num:<20}{num_of_data:<20}{ack_num:<20}\n")


def write_statistics(info):
    with open('Receiver_log.txt', 'a+') as receiver_log:
        receiver_log.write("====================================================\n")
        receiver_log.write("Amount of data received (bytes)".ljust(28) + f"{info[0]}\n".rjust(72))
        receiver_log.write("Total Segments Received".ljust(28) + f"{info[1]}\n".rjust(72))
        receiver_log.write("Data Segments Received".ljust(28) + f"{info[2]}\n".rjust(72))
        receiver_log.write("Data Segments with Bit Errors".ljust(28) + f"{info[3]}\n".rjust(72))
        receiver_log.write("Duplicate Data Segments Received".ljust(28) + f"{info[4]}\n".rjust(72))
        receiver_log.write("Duplicate ACKs Sent".ljust(28) + f"{info[5]}\n".rjust(72))
        receiver_log.write("====================================================\n")


def generate_PDF_copy(file_name, content):
    with open(file_name, 'wb+') as pdf_copy:
        pdf_copy.write(content)


def three_way_handshaking(receiver_socket, head, dest_ip_port):
    head.recv_data = receiver_socket.recvfrom(4096)[0]
    recv_S_time = round((time.time() - head.start_time), 3)
    head.unpack_data()
    if head.SYN == 1:
        receiver_log_file('rcv', recv_S_time, 'S', head.sender_seq, head.len_recv_data, head.ACK_num)
        head.SYN = 1
        head.ACK_num = head.sender_seq + 1
        receiver_socket.sendto(head.pack_data(), dest_ip_port)
        time_stamp = round((time.time() - head.start_time), 3)
        receiver_log_file('snd', time_stamp, 'SA', head.Sequence_num, head.len_send_data, head.ACK_num)
        head.recv_data = receiver_socket.recvfrom(4096)[0]
        time_stamp = round((time.time() - head.start_time), 3)
        head.unpack_data()
        if head.ACK_num == head.Sequence_num + 1:
            receiver_log_file('rcv', time_stamp, 'A', head.sender_seq, head.len_recv_data, head.ACK_num)
            head.Sequence_num = head.ACK_num
            head.state = 'connected'
            head.total_segments += 2


def find_gap(ACK_num, MSS):
    gap = 1
    while gap in ACK_num:
        gap += MSS
    return gap


def main_function():
    state_header = Header()
    state_header.source_IP = get_host_IP()
    state_header.source_port = int(sys.argv[1])
    state_header.file_name = sys.argv[2]
    recv_socket = socket(AF_INET, SOCK_DGRAM)
    state_header.start_time = time.time()
    recv_socket.bind(('', state_header.source_port))
    print(f"receiver is running on {state_header.source_IP}, using {state_header.source_port} as its port")
    # this just receiver the whole length of the file and the address info about the sender.
    file_len, addr = recv_socket.recvfrom(1024)
    state_header.file_len = int(file_len.decode())
    state_header.destination_IP, state_header.destination_port = addr[0], addr[1]
    # file_dict stores the whole file bytes
    file_dict = dict()
    ACK_num = []

    while True:
        # handshaking with the sender.
        if state_header.state == 'closed':
            three_way_handshaking(recv_socket, state_header, addr)
            file_len = state_header.file_len // state_header.MSS
            file_len += 1
            print("Receiving data, please wait patiently...")
        # data transmission
        if state_header.state == 'connected':
            state_header.recv_data, addr = recv_socket.recvfrom(4096)
            time_stamp = round(time.time() - state_header.start_time, 3)
            state_header.unpack_data()
            checksum = state_header.generate_checksum()
            if checksum == state_header.checksum:
                # print a progress bar to make it easier for us to see the process
                progres = len(list(set(ACK_num)))
                print('\r[' + '>>' * (int(progres / file_len * 20)) + ' ' * (20 - int(progres / file_len * 20)) * 2 +
                      ']  ' + str(int(progres / file_len * 100)) + '%', end='')
                data_num = state_header.sender_seq - 1
                # FIN segment received
                if state_header.FIN == 1:
                    state_header.state = 'FINACK'
                    receiver_log_file('rcv', time_stamp, 'F', state_header.sender_seq, state_header.len_recv_data,
                                      state_header.recv_ACK)
                    continue
                # data segment received
                receiver_log_file('rcv', time_stamp, 'D', state_header.sender_seq, state_header.len_recv_data,
                                  state_header.recv_ACK)
                # duplicate data segment recieved
                if data_num in file_dict:
                    state_header.data_segment_duplicate += 1
                state_header.data_segments += 1
                state_header.total_segments += 1
                file_dict[state_header.sender_seq - 1] = state_header.recv_data
                ACK_num.append(state_header.sender_seq)
                gap_point = find_gap(ACK_num, state_header.MSS)
                max_ACK = max(ACK_num)
                # no gap between received ACK
                if gap_point > max_ACK:
                    data_len = len(file_dict[max_ACK - 1])
                    state_header.ACK_num = max_ACK + data_len
                    # print("ACK_number", state_header.ACK_num)
                    state_header.checksum = 0
                    recv_socket.sendto(state_header.pack_data(), addr)
                    time_stamp = round(time.time() - state_header.start_time, 3)
                    receiver_log_file('snd', time_stamp, 'A', state_header.Sequence_num, state_header.len_send_data,
                                      state_header.ACK_num)
                # there is gap between received ACK
                else:
                    state_header.ACK_num = gap_point
                    state_header.checksum = 0
                    recv_socket.sendto(state_header.pack_data(), addr)
                    time_stamp = round(time.time() - state_header.start_time, 3)
                    receiver_log_file('snd/DA', time_stamp, 'A', state_header.Sequence_num, state_header.len_send_data,
                                      state_header.ACK_num)
                    state_header.dup_ACK_sent += 1
            # corrupted data segment received
            else:
                receiver_log_file('rcv/corr', time_stamp, 'D', state_header.sender_seq, state_header.len_recv_data,
                                  state_header.recv_ACK)
                state_header.segment_bit_error += 1
                state_header.total_segments += 1

        if state_header.state == 'FINACK':
            # ACK
            state_header.ACK_num = state_header.sender_seq + 1
            state_header.FINACK = 1
            state_header.checksum = 0
            recv_socket.sendto(state_header.pack_data(), addr)
            time_stamp = round(time.time() - state_header.start_time, 3)
            receiver_log_file('snd', time_stamp, 'A', state_header.Sequence_num, state_header.len_send_data,
                              state_header.ACK_num)
            # FIN
            state_header.FIN = 1
            state_header.checksum = 0
            recv_socket.sendto(state_header.pack_data(), addr)
            time_stamp = round(time.time() - state_header.start_time, 3)
            receiver_log_file('snd', time_stamp, 'F', state_header.Sequence_num, state_header.len_send_data,
                              state_header.ACK_num)
            state_header.state = 'senderACK'
        if state_header.state == 'senderACK':
            state_header.recv_data = recv_socket.recvfrom(1024)[0]
            time_stamp = round(time.time() - state_header.start_time, 3)
            state_header.unpack_data()
            receiver_log_file('rcv', time_stamp, 'A', state_header.sender_seq, state_header.len_recv_data,
                              state_header.recv_ACK)
            state_header.state = 'finished'
            state_header.total_segments += 2
            recv_socket.close()
            break
    if state_header.state == 'finished':
        # assemble the content
        content_copy = b''
        for key in sorted(file_dict.keys()):
            content_copy += file_dict[key]
        generate_PDF_copy(state_header.file_name, content_copy)
        # write statistics into receiver log file
        print("\nFile received successfully, writing statistics into receiver log file.")
        statistics = [state_header.file_len, state_header.total_segments, state_header.data_segments,
                      state_header.segment_bit_error, state_header.data_segment_duplicate, state_header.dup_ACK_sent]
        write_statistics(statistics)
        print("All done.")


if __name__ == '__main__':
    main_function()