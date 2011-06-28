/*
 * Sealing Wafter OpenBSD LKM: 0.1.4
 *
 * Copyright (c) 2005-2010 Jaime Fournier <ober@LinBSD.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met: 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer. 2.
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution. 3. Neither the name
 * of the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE FOR
 * ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Changes since last version:
 * 1. Added os_detect() with several fingerprints.
 * 2. Cleaned up the RST code to handle tcpkill properly.
 *    Was causing hangs on ftp, and other items as real RST
 *    were being dropped, thus causing hangs.
 *    (There are probably cases where we are ignoring valid RST)
 * 3. Cleaned up the code to reduce the code paths.
 * 4. Added more tests for NMAP packets. Used p0f rulesets
 *    as well as testing.   
 *
 * Goals of Sealing Wafter:
 * 1. To reduce OS detection based on well known fingerprints
 *    network stack behavior.
 * 2. To have the ability to load custom rules into the stack.
 * 3. To unload, modify, reload the kernel module with on the fly rules.
 *    (great feature at packet parties)
 * 4. To learn how the magic of tcpip stacks work.
 *
 * What Sealing Wafter currently provides:
 * 1. Hide from Nmap Syn/Xmas/Null scans, as well as the specific
 *    fingerprinting packets. 
 * 2. Ability to see what your stack is receiving without the need
 *    to drop your network device into promisc mode.
 * 3. Complete control over rules that you can load on the fly to
 *    deal with specific incoming packets.
 * 4. Initial support for several OS passive detection has been
 *    added for SYNs.
 *
 * Weaknesses in current Sealing Wafter:
 * 1. Full connection scans. e.g. nmap -sT will still find open ports.
 *    this is because I have yet to find anything that seperates a real
 *    tcp connection vs an nmap full conncetion. (most likely isn't one.)
 * 2. Can be very verbose when under heavy load.
 *    I have run this on my heaviest web servers, and have not noticed
 *    any major overhead.
 *
 * Goals:
 * 1. Clean up code some more.
 * 2. Add p0f ruleset for basic detection of remote operating systems.
 * 3. Hijack outbound functions as well as the inbound. This will allow
 *    for control over specifics items that remote boxes running p0f could
 *    use to fingerprint us.
 * 4. Personality support for inbound and outbound fingerprinting.
 *    (e.g. pretend we are windows. open all the windows ports to only
 *    things like nmap. :P)
 *
 * Why not use pf?
 * 1. Because I wanted to learn, and because I want dynamic behavior
 *    that I can not do with pf.
 *
 * To Compile: gcc  -Wall -D_KERNEL -I/sys -c wafter.c
 * To Load: modload -o waftermod.o -ewafter wafter.o
 *
 * Originally based on the tutorial from peter_a_werner@yahoo.com located at:
 * http://undeadly.org/cgi?action=article&sid=20010812210650
*/

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/exec.h>
#include <sys/conf.h>
#include <sys/lkm.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <net/route.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in_pcb.h>
#include <machine/stdarg.h>
#include <netinet/ip6.h>

/*
 * We will modify the entry for TCP in this structure.
 */

#define TH_BOG      0xc0
extern struct protosw inetsw[];

/*
 * Our prototypes
 */

extern int lkmexists __P((struct lkm_table *));
extern char    *inet_ntoa __P((struct in_addr));
static int wafter_handler __P((struct lkm_table *, int));
int     wafter_lkmentry __P((struct lkm_table *lkmtp, int, int));
//static int load __P((struct lkm_table *, int));
void print_ip_header(struct ip * ip);
void tcpdrop(struct tcphdr * th);
void os_detect(struct ip * ip, struct tcphdr * th);
void print_tcp_header(struct tcphdr * th);


void new_tcp_input __P((struct mbuf *,...));
void new_icmp_input __P((struct mbuf *,...));
void new_udp_input __P((struct mbuf *,...));

void     (*old_tcp_input) __P((struct mbuf *,...));
void     (*old_udp_input) __P((struct mbuf *,...));
void     (*old_icmp_input) __P((struct mbuf *,...));

/*
 * Declare and initialise our module structure
 */

MOD_MISC("waftermod")
/*
 * Our handler function, used for load and unload.
 */

	int wafter_handler(lkmtp, cmd)
	struct lkm_table *lkmtp;
	int             cmd;
{
	int             s;

	switch (cmd) {

	case LKM_E_LOAD:

		/*
		 * Provide some sanity checking, making sure the module
		 * will not be loaded more than once.
		 */

		if (lkmexists(lkmtp))
			return (EEXIST);

		/*
	 	 * Block network protocol processing while we modify
		 * the structure. We are changing the pointer to the
		 * function tcp_input to our own wrapper function.
		 */

		s = splnet();
		old_icmp_input = inetsw[4].pr_input;
		old_tcp_input = inetsw[2].pr_input;
		old_udp_input = inetsw[1].pr_input;
		inetsw[4].pr_input = new_icmp_input;
		//inetsw[2].pr_input = new_tcp_input;
		//inetsw[1].pr_input = new_udp_input;
		splx(s);

		break;

	case LKM_E_UNLOAD:

		/*
		 * Restore the structure back to normal when we
		 * are unloaded.
		 */

		s = splnet();
		//inetsw[1].pr_input = old_udp_input;
		//inetsw[2].pr_input = old_tcp_input;
		inetsw[4].pr_input = old_icmp_input;
		splx(s);

		break;
	}

	return (0);
}

/*
 * Our external entry point, nothing to do but use DISPATCH.
 */

int
wafter_lkmentry(lkmtp, cmd, ver)
	struct lkm_table *lkmtp;
	int             cmd;
	int             ver;
{
	DISPATCH(lkmtp, cmd, ver, wafter_handler, wafter_handler, lkm_nofunc);
}

void
print_ip_header(struct ip * ip)
{

#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */

	printf(" ip-<src:%s dst:%s hl:%u v:%u tos:%u len:%u id:%u off:%u ttl:%u p:%u sum:%u> ", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst), ip->ip_hl, ip->ip_v, ip->ip_tos, ntohs(ip->ip_len), ip->ip_id, ip->ip_off, ip->ip_ttl, ip->ip_p, ip->ip_sum);

	if (ntohs(ip->ip_off) & IP_RF)
		printf("IP_RF:");

	if (ntohs(ip->ip_off) & IP_DF)
		printf("IP_DF:");

	if (ntohs(ip->ip_off) & IP_MF)
		printf("IP_MF:");

}

void
tcpdrop(struct tcphdr * th)
{
	printf(" DROPPED ");
	th->th_flags = 0;
}

void
os_detect(struct ip * ip, struct tcphdr * th)
{
	/*Linux*/
	if ((ntohs(th->th_win) == 5840) && (ntohs(ip->ip_off) & IP_DF) && (ip->ip_ttl <= 64) && (ntohs(ip->ip_len) == 60))  {
		printf(" Linux 2.4 (Maybe 2.5) ");
		printf("\n");
		return;
	}

	/*
	* OpenBSD 
	* Sometimes OpenBSD has DF set, othertimes it does not 
	*/
	if ((ntohs(th->th_win) == 16384) && (ip->ip_ttl <= 64) && (ntohs(ip->ip_len) == 64)){
		printf(" OpenBSD 3.0-3.8 ");
		printf("\n");
		return;
	}

	/*
	 * MacOSX 
	 * ip_len has been noted at 60, and 64 
	 */
	if ((ntohs(th->th_win) == 65535) && (ntohs(ip->ip_off) & IP_DF) && (ip->ip_ttl <= 64) && (ntohs(ip->ip_len) == 60)){
		printf(" FreeBSD:4.7-5.2 (or MacOS X 10.2-10.3) (1) ");
		printf("\n");
		return;
	}

	/*
	 * Windows XP SP2 
	 */
	if ((ntohs(th->th_win) == 16384) && (ntohs(ip->ip_off) & IP_DF) && (ip->ip_ttl <= 128) && (ntohs(ip->ip_len) == 48)){
		printf(" Windows:2000 SP2+, XP SP1 (seldom 98 4.10.2222) ");
		printf("\n");
		return;
	}

	/*
         * NetBSD 3.0 i386 32768:64:1:64:
	 */
	
	if ((ntohs(th->th_win) == 32768) && (ntohs(ip->ip_off) & IP_DF) && (ip->ip_ttl <= 64) && (ntohs(ip->ip_len) == 64)){
		printf(" NetBSD 3.0\n");
		return;
	}
	
	/* 
	 * Windows XP Pro SP1, 2000 SP3 [Tiscali Denmark] 
	 */
	if ((ntohs(th->th_win) == 64240) && (ntohs(ip->ip_off) & IP_DF) && (ip->ip_ttl <= 128) && (ntohs(ip->ip_len) == 48)){
		printf(" Windows XP Pro SP1, 2000 SP3 [Tiscali Denmark] \n");
		return;
	}

	/* 
         * Windows 2000 SP4, XP SP1 
	 */
   	
	if ((ntohs(th->th_win) == 65535) && (ntohs(ip->ip_off) & IP_DF) && (ip->ip_ttl <= 128) && (ntohs(ip->ip_len) == 48)){
		printf(" Windows XP Pro SP1, 2000 SP3 [Tiscali Denmark] \n");
		return;
	}

	/* 
	 * Red Hat Enterprise Linux WS release 3 (Taroon Update 6) 
	 */
	if ((ntohs(th->th_win) == 53760) && (ntohs(ip->ip_off) & IP_DF) && (ip->ip_ttl <= 32) && (ntohs(ip->ip_len) == 48)){
		printf(" Red Hat Enterprise Linux WS release 3 (Taroon Update 6) \n");
		return;
	}

	/*
	 * Plan 9 
	 * 65535:228:0:48:M1460,W1,N:.:?:? 
	 */
	if ((ntohs(th->th_win) == 65535) && (!(ntohs(ip->ip_off) & IP_DF)) && (ip->ip_ttl <= 228) && (ntohs(ip->ip_len) == 48)){
		printf(" Plan 9 (4th Edition)\n");
		return;
	}

	/* 
	 *  FreeBSD 6 
	 *  65535:228:0:48:M1460,W1,N:.:?:? 
	 */

	if ((ntohs(th->th_win) == 65535) && (ntohs(ip->ip_off) & IP_DF) && (ip->ip_ttl <= 44) && (ntohs(ip->ip_len) == 64)){
		printf(" FreeBSD 6.0\n");
		return;
	}

	printf(" Unknown OS\n");
}

void
print_tcp_header(struct tcphdr * th)
{
	printf(" tcp-< sport:%u dport:%u seq:%u ack:%u x2:%u off:%u flags:%u win:%u sum:%u urp:%u> ", ntohs(th->th_sport), ntohs(th->th_dport), th->th_seq, ntohl(th->th_ack), th->th_x2, th->th_off, th->th_flags, ntohs(th->th_win), th->th_sum, th->th_urp);

	if (th->th_flags & TH_FIN) {
		printf(":FIN");
	}
	if (th->th_flags & TH_SYN) {
		printf(":SYN");
	}
	if (th->th_flags & TH_RST) {
		printf(":RST");
	}
	if (th->th_flags & TH_PUSH) {
		printf(":PUSH");
	}
	if (th->th_flags & TH_ACK) {
		printf(":ACK");
	}
	if (th->th_flags & TH_URG) {
		printf(":URG");
	}
	if (th->th_flags & TH_ECE) {
		printf(":ECE");
	}
	if (th->th_flags & TH_CWR) {
		printf(":CWR");
	}
}

/*
 * Our tcp_input wrapper. If the mbuf represents a packet header, print
 * out the total length of the packet, the interface it was received on
 * and its source address. Then continue on with the original tcp_input.
 */

void
new_tcp_input(struct mbuf * m,...)
{
	va_list         ap;
	int             iphlen;
	struct ifnet   *ifnp;
	struct ip      *ip;
	struct tcphdr  *th;

	va_start(ap, m);
	iphlen = va_arg(ap, int);
	va_end(ap);

	if (m->m_flags & M_PKTHDR) {
		ifnp = m->m_pkthdr.rcvif;
		ip = mtod(m, struct ip *);
		th = (struct tcphdr *) (ip + 1);

		if (!th->th_flags) {
			printf("NMAP OS t2/Null Scan t2 on:%s Flags:NULL", ifnp->if_xname);
			print_ip_header(ip);
			print_tcp_header(th);
			printf("\n");
		}

		if ((ntohs(ip->ip_len) == 40) && (!(ntohs(ip->ip_off) & IP_DF)) && (ip->ip_ttl <= 64) && ((ntohs(th->th_win) == 1024) || (ntohs(th->th_win) == 2048) || (ntohs(th->th_win) == 3072) || (ntohs(th->th_win) == 4096)))  {

			if (th->th_flags & TH_FIN) {
				printf("NMAP FIN Scan on:%s", ifnp->if_xname);
				/*
				 * print_ip_header(ip);
				 * print_tcp_header(th);
				 * tcpdrop(th);
				 */
				printf("\n");
			}

			if (th->th_flags == TH_FIN)  {
				printf("NMAP FIN Scan on:%s", ifnp->if_xname);
				print_ip_header(ip);
				print_tcp_header(th);
				printf("\n");
			}

			if ((th->th_flags & TH_SYN) && (th->th_flags & TH_ECE)) {
				printf("NMAP OS Detection Scan t1 on:%s Flags:SYN|ECE", ifnp->if_xname);
				print_ip_header(ip);
				print_tcp_header(th);
				tcpdrop(th);
				printf("\n");
			}

			if ((th->th_flags & TH_FIN) && (th->th_flags & TH_SYN) && (th->th_flags & TH_PUSH) && (th->th_flags & TH_URG)) {
				printf("NMAP OS Detection Scan t3 on:%s Flags:FIN|SYN|PUSH|URG", ifnp->if_xname);
				/*
				 * print_ip_header(ip);
				 * print_tcp_header(th);
				 */
				tcpdrop(th);
				printf("\n");
			}

			if ((th->th_flags & TH_FIN) && (th->th_flags & TH_PUSH) && (th->th_flags & TH_URG)) {
				printf("NMAP OS t4/XMAS Scan on:%s Flags:FIN|PUSH|URG", ifnp->if_xname);
				/*
				 * print_ip_header(ip);
				 * print_tcp_header(th);
				 */
				tcpdrop(th);
				printf("\n");
			}

			if (th->th_flags == TH_SYN)  {
				printf("NMAP SYN Scan on:%s", ifnp->if_xname);
				print_ip_header(ip);
				print_tcp_header(th);
				tcpdrop(th);
				printf("\n");
			}

			if (th->th_flags == TH_ACK)  {
				printf("NMAP ACK/Window Scan on:%s", ifnp->if_xname);
				/*
				 * print_ip_header(ip);
				 * print_tcp_header(th);
				 */
				tcpdrop(th);
				printf("\n");
			}

		}else{ 
			/* 
			 * NOT NMAP/TCPKILL/SSH SCAN 
			 */

			 if (th->th_flags == TH_SYN) {
				printf("SYN connect on:%s", ifnp->if_xname);
				print_ip_header(ip);
				print_tcp_header(th);
				os_detect(ip, th);
			}

			/* 
			 * tcpkill sets just RST, not RST,ACK 
			 */
			if (th->th_flags == TH_RST) {
				printf("TCPKILL RST on:%s", ifnp->if_xname);
				/*
				 * print_ip_header(ip);
				 * print_tcp_header(th);
				 * tcpdrop(th);
				 */
				printf("\n");
			}

			/* 
		         * Real RST's as seen so far set ACK as well 
			 */
			if ((th->th_flags & TH_RST) && (th->th_flags & TH_ACK)) {
				printf("RST on:%s", ifnp->if_xname);
				print_ip_header(ip);
				print_tcp_header(th);
				/*	
				 * tcpdrop(th);
				 */
				printf("\n");
			}

		}
	}			/*	
				 * mbuf head
				 */
	
	(*old_tcp_input) (m, iphlen);

	return;
}

void
new_icmp_input(struct mbuf * m,...)
{
	//struct icmp    *icp;
	struct ip      *ip = mtod(m, struct ip *);
	//int             icmplen;
	//void           *(*ctlfunc) (int, struct sockaddr *, void *);
	//int             code;
	int 		iphlen;
	va_list         ap;
	va_start(ap, m);
	iphlen = va_arg(ap, int);
	va_end(ap);

	printf("icmp from %s to %s, len %d\n", inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst), ntohs(ip->ip_len));

	(*old_icmp_input) (m, iphlen);
	return;
}

void
new_udp_input(struct mbuf * m,...)
{
	struct ip      *ip;
	struct udphdr  *uh;
	//struct mbuf    *opts = 0;
	//struct ip       save_ip;
	int             iphlen;
	//int 		version;
	//int 		len;
	va_list         ap;
	//u_int16_t       savesum;
	unsigned        srcport, destport;
	union {
		struct sockaddr sa;
		struct sockaddr_in sin;
	}               srcsa;  //  dstsa;

	va_start(ap, m);
	iphlen = va_arg(ap, int);
	va_end(ap);

	if (mtod(m, struct ip *)->ip_v == 4) {

		ip = mtod(m, struct ip *);

		srcsa.sa.sa_family = AF_INET;

		IP6_EXTHDR_GET(uh, struct udphdr *, m, iphlen, sizeof(struct udphdr));

		if (uh) {
			srcport = ntohs(uh->uh_sport);
			destport = ntohs(uh->uh_dport);
				printf("UDP from:%s ", inet_ntoa(ip->ip_src));
				printf(" Details: srcport:%u dstport:%u ulen:%d usum:%d size:%d\n", srcport, destport, uh->uh_ulen, uh->uh_sum, ip->ip_len);
		}
	}
	(*old_udp_input) (m, iphlen);
	return;
}
