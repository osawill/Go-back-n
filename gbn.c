#include "gbn.h"
/*--- Timeout ---*/
volatile sig_atomic_t to_flag = false;

/*Sets timeout flag to alert program*/
void timeout_handler( int sig ) {
    to_flag = true;
		printf("~~ Timeout ~~\n");
}
/*Reset timeout*/
void reset_timeout() {
	to_flag = false;
}

state_t machine = {SLOW, CLOSED, 2};

/*--- Global ---*/
struct sockaddr * hostAddr;
socklen_t hostLen;

/*--- Packet Tools ---*/
gbnhdr make_header(int type, uint8_t sequence_num)
{
	gbnhdr header;
	header.type = type;
	header.seqnum = sequence_num;
	header.checksum = 0; /* initial checksum*/

	return header;
}

gbnhdr* make_packet(int type, uint8_t sequence_num, char *buffer, int data_length)
{
	gbnhdr * packet = malloc(sizeof(gbnhdr));
	packet->type = type;
	packet->seqnum = sequence_num;
	memcpy(packet->data, buffer, data_length);

	packet->checksum = checksum((uint16_t *) buffer, data_length);

	return packet;
}

int check_packet(gbnhdr * packet, int type, int len){
	/* Check timeout*/
	if (to_flag == true || len ==-1) {
		reset_timeout();
		return -1;
	}
	/* Check type */
	else if (packet->type != type) {
		printf("Wrong packet type received, %d\n", packet->type);
		return -1;
	}
	/* Check seqnum*/
	else if (packet->seqnum <= machine.seqnum){
		printf("Wrong seqnum, rec: %d, sent: %d\n",packet->seqnum, machine.seqnum );
		return -1;
	}

	return 0;
}

/*///////*/
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

	int cur_mode = machine.mode;
	int cur_seq = rand();

	machine.seqnum = cur_seq;

	int remaining = len;
	int cur_size = 0;
	int track = 0;
	int attempts;


	char * tempBuf = (char *) malloc(DATALEN * sizeof(char));
	/*Keep sending till end of file*/
	while (track < len) {

		/* Clear the packet buffer*/
		memset(tempBuf, '\0', DATALEN);

		if (remaining >= DATALEN) {
			cur_size = DATALEN;
		}
		else {
			cur_size = remaining;
		}

		/* SLOW*/
    attempts = 0;
		if (cur_mode == SLOW) {
      gbnhdr * nextPack;
      gbnhdr * rec_buf;

			memcpy(tempBuf, buf + track, cur_size);

			while(machine.state != ACK_RCVD && attempts < 5) {
				nextPack = make_packet(DATA, cur_seq, tempBuf, cur_size);


				int rtn = sendto(sockfd, nextPack, sizeof(*nextPack), 0, hostAddr, hostLen);

				if (rtn == -1) {
					printf("Failed to send packet, attempt: %d\n", ++attempts);
					continue;
				}

				machine.state = DATA_SENT;
				alarm(TIMEOUT);

				rec_buf = malloc(sizeof(gbnhdr));
				int rec_size = recvfrom(sockfd, rec_buf, sizeof(gbnhdr), 0, hostAddr, &hostLen);


        if(check_packet(rec_buf, DATAACK, rec_size) == 0){
          machine.state = ACK_RCVD;
					cur_mode = FAST;
          track += cur_size;
          remaining = remaining - cur_size;
          cur_seq++;
          machine.seqnum = cur_seq;
        } else {
          attempts++;
        }

			}

			/* Close out after 5 attempts*/
			if (machine.state == DATA_SENT) {
				return -1;
			}

      free(nextPack);
      free(rec_buf);
			machine.state = ESTABLISHED;
		} else { /* FAST*/

			memcpy(tempBuf, buf + track, cur_size);
			machine.state = ESTABLISHED;

			int firstTrack = track;
			int firstLen  = cur_size;
			int firstSeqnum = cur_seq;

			/* send first packet*/
      gbnhdr * firstPack = make_packet(DATA, cur_seq, tempBuf, cur_size);

			int firstRtn = sendto(sockfd, firstPack,
                sizeof(*firstPack), 0, hostAddr, hostLen);

			machine.state = DATA_SENT;


			/* Clear the buffer*/
			memset(tempBuf, '\0', DATALEN);

			/* Send second only if theres still remaining buffer*/
      int secondTrack;
      int secondLen;
      int secondSeqnum;
			if (track + cur_size < len) {
				cur_seq++;
        machine.seqnum = cur_seq;
        track += cur_size;

        secondTrack = track;
        secondSeqnum = cur_seq;

        /* Check size*/
        if (remaining >= DATALEN*2) {
  				secondLen = DATALEN;
  			}
  			else {
  				secondLen = remaining - DATALEN;
  			}

        memcpy(tempBuf, buf + track, cur_size);
        gbnhdr * secondPack = make_packet(DATA, cur_seq, tempBuf, cur_size);

        int secondRtn = sendto(sockfd, secondPack,
                                sizeof(*secondPack), 0, hostAddr, hostLen);

			}
      else {
        secondSeqnum = cur_seq;
        secondLen = firstLen;
      }

      cur_seq = firstSeqnum;

      while(attempts < 5 && machine.state != ACK_RCVD){
        alarm(TIMEOUT);
        gbnhdr * rec_buf = malloc(sizeof(gbnhdr));
        int rec_size = recvfrom(sockfd, rec_buf, sizeof * rec_buf, 0, hostAddr, &hostLen);

        if(check_packet(rec_buf, DATAACK, rec_size) ==0){
          if(rec_buf->seqnum == secondSeqnum) {
            printf("Ack second packet, seqnum: %d\n", rec_buf->seqnum);
            machine.state = ACK_RCVD;
            track += secondLen;
            remaining -= (secondLen);
            cur_seq++;
            machine.seqnum = cur_seq;
          }
          else if(rec_buf->seqnum == firstSeqnum) {
            printf("Ack first packet, seqnum: %d\n", rec_buf->seqnum);
            remaining -= firstLen;
            cur_seq = secondSeqnum;
          }
          else {
            attempts++;
            continue;
          }
        } else {
          if (rec_buf->seqnum == firstSeqnum) {
            cur_mode = SLOW;
            track = firstTrack;
            cur_seq = firstSeqnum;
            break;
          }
          else if (rec_buf->seqnum == secondSeqnum && cur_seq == secondSeqnum){
            cur_mode = SLOW;
            track = secondTrack;
            break;
          }
          else {
            attempts++;
          }
        }
      }
      /* Start over again with first packer */
      if (attempts == 5) {
        cur_mode = SLOW;
        track = firstTrack;
        cur_seq = firstSeqnum;
      }
		}
	}
	machine.isFin = 1;

	return remaining;
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

	/* If connection is broken*/
	if (sockfd < 0)
		return -1;

	int attempt = 0;
	gbnhdr syn_header = make_header(SYN, 0);
	machine.state = SYN_SENT;
	machine.isFin = 0;
	printf("SYN sent\n");

	/* Attempt to send the SYN packet up to 5 times*/
	while (attempt < 5) {

		int rtn = sendto(sockfd, &syn_header, sizeof syn_header, 0, server, socklen);

		if (rtn == -1) { /* Send error, try again*/
			attempt++;
			continue;
		}

		alarm(TIMEOUT); /* Signal at timeout*/

		/*Receive ack*/
		/*char buf[1030];*/
		gbnhdr * rec_buf = malloc(sizeof(gbnhdr));
		int rec_size = recvfrom(sockfd, rec_buf, sizeof(gbnhdr), 0, hostAddr, &hostLen);

		/* Timeout or nothing received*/
		if (to_flag==true || rec_size == -19) {
			attempt++;
			reset_timeout();
		}
		else { /* Received a packet*/
			if (rec_buf->type == SYNACK) { /* Check to see if we got the right response*/
				machine.state = ESTABLISHED;
				printf("Connection established\n");
				return 0;
			}

			attempt++;
		}
	}

	machine.state = CLOSED;
	return -1;

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

	/*Set timeout handler*/
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
