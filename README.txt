Submitted Files:

1. tcpclient.py: This is the client side program which should run after the tcpserver is running
2. tcpserver.py: This should run before the tcpclient gets run
3. input.txt: This is the file to be transferred by tcpclient and received by tcpserver
4. output.txt: This is the file written by the tcpserver and it should be exact the same as input.txt
5. helpers.py: This is the python file contains several functions that are used by both tcpclient and tcpserver



Command to run the programs:

./newudpl -i127.0.0.1 -o127.0.0.1 -L 50

python3 tcpserver.py output.txt 41194 127.0.0.1 41191

NOTICE: 41194 is the port that newudpl outputting to
	  41191 is the port that newudpl accepting from

python3 tcpclient.py input.txt 127.0.0.1 41192 1024 41191

NOTICE: 41192 is the port that newudpl's input port
	  41191 is the port that newudpl accepting from
        !!! The TCP WINDOWSIZE has to be 1024 !!!




List of features:

1. The timeout value gets updated everytime an RTT get sampled. This accelerate the sending rate dramatically.
2. The server program utilized sequence number and ack number to tolerate duplicated packets. Duplicated packets get droped.
3. SYN handshake and FIN handshake are implemented properly.
4. Checksum is implemented properly. Incorrect checksum packet gets dropped.





