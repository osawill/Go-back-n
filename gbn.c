#include "gbn.h"
/*--- Timeout ---*/
volatile sig_atomic_t to_flag = false;

void timeout_handler( int sig ) { //Sets timeout flag to alert program
    to_flag = true;
		printf("~~ Timeout ~~\n", );
}

void reset_timeout() { //Reset timeout
	to_flag = false;
}

state_t machine = {SLOW, CLOSED};

/*--- Global ---*/
struct sockaddr * hostAddr;
socklen_t hostLen;

/*--- Header ---*/
gbnhdr make_head(int type, uint8_t sequence_num)
{
	gbnhdr header;
	header.type = type;
	header.seqnum = sequence_num;
	header.checksum = 0; // initial checksum

	return header;
}

gbnhdr make_head_wdata(int type, uint8_t sequence_num, char *buffer, int data_length)
{
	gbnhdr header;
	header.type = type;
	header.seqnum = sequence_num;
	header.checksum = 0;
	memcpy(header.data, buffer, data_length);
	header.lenData = data_length;

	return header;
}

///////////////////////
uint16_t checksum(uint16_t *buf, int nwords)
{
	uint32_t sum;

	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}

ssize_t gbn_send(int sockfd, const void *buf, size_t len, int flags){

	/* TODO: Your code here. */

	/* Hint: Check the data length field 'len'.
	 *       If it is > DATALEN, you will have to split the data
	 *       up into multiple packets - you don't have to worry
	 *       about getting more than N * DATALEN.
	 */

	return(-1);
}

ssize_t gbn_recv(int sockfd, void *buf, size_t len, int flags){

	/* TODO: Your code here. */

	return(-1);
}

int gbn_close(int sockfd){

	/* TODO: Your code here. */

	return(-1);
}

int gbn_connect(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* TODO: Your code here. */
	hostAddr = server;
	hostLen = socklen;

	// If connection is broken
	if (sockfd < 0)
		return -1;

	int attempt = 0;
	gbnhdr syn_header = make_header(SYN, 0);
	machine.state = SYN_SENT;
	machine.isFin = 0;

	// Attempt to send the SYN packet up to 5 times
	while (machine.state == SYN_SENT && attempt < 5) {

		int rtn = sendto(sockfd, &syn_header, sizeof syn_header, 0, server, socklen); //hardcoded 4 since that's always the length of the packet header

		alarm(TIMEOUT); // Signal at timeout

		if (rtn == -1) { // Send error, try again
			attempts++;
			continue;
		}

		//Receive syn ack
		char buf[1030];
		int rec_size = recvfrom(sockfd, buf, sizeof buf, 0, sender_global, sender_socklen_global);

		// Timeout or nothing received
		if (to_flag || rec_size == -19) {
			attempts++;
			reset_timeout();
		}
		else { // Received a packet
			if (buffer[0] == SYNACK) { // Check to see if we got the right response
				machine.state = ESTABLISHED;
				return 0;
			}

			attempts++;
		}
	}

	if (attempts >= 5) {
		machine.state = CLOSED;
		return -1;
	}

	// Machine entered a wrong state
	return -2;
}

int gbn_listen(int sockfd, int backlog){

	/* TODO: Your code here. */

	return(-1);
}

int gbn_bind(int sockfd, const struct sockaddr *server, socklen_t socklen){

	/* TODO: Your code here. */

	return(-1);
}

int gbn_socket(int domain, int type, int protocol){

	/*----- Randomizing the seed. This is used by the rand() function -----*/
	srand((unsigned)time(0));

	//Set timeout handler
	signal(SIGALRM, timeout_handler);

	int sock = socket(domain, type, protocol);
	return sock;
}

int gbn_accept(int sockfd, struct sockaddr *client, socklen_t *socklen){

	/* TODO: Your code here. */

	return(-1);
}

ssize_t maybe_sendto(int  s, const void *buf, size_t len, int flags, \
                     const struct sockaddr *to, socklen_t tolen){

	char *buffer = malloc(len);
	memcpy(buffer, buf, len);


	/*----- Packet not lost -----*/
	if (rand() > LOSS_PROB*RAND_MAX){
		/*----- Packet corrupted -----*/
		if (rand() < CORR_PROB*RAND_MAX){

			/*----- Selecting a random byte inside the packet -----*/
			int index = (int)((len-1)*rand()/(RAND_MAX + 1.0));

			/*----- Inverting a bit -----*/
			char c = buffer[index];
			if (c & 0x01)
				c &= 0xFE;
			else
				c |= 0x01;
			buffer[index] = c;
		}

		/*----- Sending the packet -----*/
		int retval = sendto(s, buffer, len, flags, to, tolen);
		free(buffer);
		return retval;
	}
	/*----- Packet lost -----*/
	else
		return(len);  /* Simulate a success */
}
