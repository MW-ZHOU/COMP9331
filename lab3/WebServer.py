from socket import *
import sys
# hostname = gethostbyname(gethostname())
hostname = 'localhost'
serverPort = int(sys.argv[1])

print(f"\nIP address:{hostname}")
serverSocket = socket(AF_INET, SOCK_STREAM)
# create a socket for listening request
serverSocket.bind((hostname, serverPort))
serverSocket.listen(1)

while True:
    # print("\n\nThe server is Ready...")
    # create a socket for TCP connection
    connectionSocket, address = serverSocket.accept()
    try:
        # receive HTTP request from the client and decode the bytes strings.
        request = connectionSocket.recv(1024).decode()
        # print(f"\nHTTP request message:")
        # print(request)
        # get the name of the file that the client wants
        requested_file = request.split()[1]
        # open the file and read its content
        file = open(requested_file[1:], 'rb')
        content = file.read()
        # print(content)
        # send a HTTP header line within the socket and encode
        connectionSocket.send(b"HTTP/1.1 200 OK\r\n\r\n")
        # send the contend of the file requested by the browser
        connectionSocket.send(content)
        connectionSocket.close()

    except IOError:
        connectionSocket.send(b"HTTP/1.1 404 Not Found\r\n\r\n")
        connectionSocket.send(b"404 Not Found")
        connectionSocket.close()
