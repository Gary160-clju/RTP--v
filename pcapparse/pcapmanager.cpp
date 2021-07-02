#include "pcapmanager.h"
#include <WinSock2.h>
#include <iostream>
#include "util.h"

#define ETH_HEADER_LEN 14
typedef struct {
    unsigned char src[6], dst[6]; /* ethernet MACs */
    int type;
} eth_header;

#define LOOP_HEADER_LEN 4
typedef struct {
    int family;
} loop_header;

#define IP_HEADER_MIN 20
typedef struct {
    int version;
    int header_size;
    unsigned char src[4], dst[4]; /* ipv4 addrs */
    int protocol;
} ip_header;

#define UDP_HEADER_LEN 8
typedef struct {
    int src, dst; /* ports */
    int size, checksum;
} udp_header;

#define RTP_HEADER_MIN 12
typedef struct {
    int version;
    int type;
    int pad, ext, cc, mark;
    int seq, time;
    int ssrc;
    int *csrc;
    int header_size;
    int payload_size;
} rtp_header;

struct myRtpHeader
{
    //int ssrc : 32;
    //int ts : 32;
    unsigned char csrccount : 4;
    unsigned char extension : 1;
    unsigned char padding : 1;
    unsigned char version : 2;

    unsigned char payloadtype : 7;
    unsigned char marker : 1;

    unsigned short sequencenumber;
    unsigned int timestamp;
    unsigned int ssrc;
};

struct myRtpHeader1
{
    unsigned char version : 2;
    unsigned char p : 1;
    unsigned char x : 1;
    unsigned char cc : 4;
};

int parse_eth_header(const unsigned char *packet, int size, eth_header *eth)
{
    if (!packet || !eth) {
        return -2;
    }
    if (size < ETH_HEADER_LEN) {
        fprintf(stdout, "Packet too short for eth\n");
        return -1;
    }
    memcpy(eth->src, packet + 0, 6);
    memcpy(eth->dst, packet + 6, 6);
    eth->type = rbe16(packet + 12);

    return 0;
}

/* used by the darwin loopback interface, at least */
int parse_loop_header(const unsigned char *packet, int size, loop_header *loop)
{
    if (!packet || !loop) {
        return -2;
    }
    if (size < LOOP_HEADER_LEN) {
        fprintf(stdout, "Packet too short for loopback\n");
        return -1;
    }
    /* protocol is in host byte order on osx. may be big endian on openbsd? */
    loop->family = rne32(packet);

    return 0;
}

int parse_ip_header(const unsigned char *packet, int size, ip_header *ip)
{
    if (!packet || !ip) {
        return -2;
    }
    if (size < IP_HEADER_MIN) {
        fprintf(stdout, "Packet too short for ip\n");
        return -1;
    }

    ip->version = (packet[0] >> 4) & 0x0f;
    if (ip->version != 4) {
        fprintf(stdout, "unhandled ip version %d\n", ip->version);
        return 1;
    }

    /* ipv4 header */
    ip->header_size = 4 * (packet[0] & 0x0f);
    ip->protocol = packet[9];
    memcpy(ip->src, packet + 12, 4);
    memcpy(ip->dst, packet + 16, 4);

    if (size < ip->header_size) {
        fprintf(stdout, "Packet too short for ipv4 with options\n");
        return -1;
    }

    return 0;
}

int parse_udp_header(const unsigned char *packet, int size, udp_header *udp)
{
    if (!packet || !udp) {
        return -2;
    }
    if (size < UDP_HEADER_LEN) {
        fprintf(stdout, "Packet too short for udp\n");
        return -1;
    }

    udp->src = rbe16(packet);
    udp->dst = rbe16(packet + 2);
    udp->size = rbe16(packet + 4);
    udp->checksum = rbe16(packet + 6);

    return 0;
}


int parse_rtp_header(const unsigned char *packet, int size, rtp_header *rtp)   //����RTPͷ��   //���Ľ�����ʽ�ǣ��������ǵĴ������ת������С�����ݣ��������кܶ���λ����
{
    if (!packet || !rtp) {
        return -2;
    }
    if (size < RTP_HEADER_MIN) {
        fprintf(stdout, "Packet too short for rtp\n");
        return -1;
    }
	//��������RTPͷ��������Ҫ������ȫ�������˳���
    rtp->version = (packet[0] >> 6) & 3;
    rtp->pad = (packet[0] >> 5) & 1;
    rtp->ext = (packet[0] >> 4) & 1;
    rtp->cc = packet[0] & 7;
    rtp->header_size = 12 + 4 * rtp->cc;
    if (rtp->ext == 1) {
        uint16_t ext_length;
        rtp->header_size += 4;
        ext_length = rbe16(packet + rtp->header_size - 2);
        rtp->header_size += ext_length * 4;
    }
    rtp->payload_size = size - rtp->header_size;

    rtp->mark = (packet[1] >> 7) & 1;  /////////////////////mark
    rtp->type = (packet[1]) & 127;
    //rtp->seq = rbe16(packet + 2);
    //rtp->time = rbe32(packet + 4);
    //rtp->ssrc = rbe32(packet + 8);
    unsigned short s = 0;
    memcpy(&s,(packet + 2),2);
    rtp->seq = ntohs(s);

    unsigned int t = 0;
    memcpy(&t,packet + 4,4);
    rtp->time = ntohl(t);   //////////////////���ǵ�ʱ���
    
    unsigned int ssrc = 0;    ///////////////���ǵ�SSRC
    memcpy(&ssrc,packet + 8,4);
    rtp->ssrc = ntohl(ssrc);
    rtp->csrc = NULL;
    if (size < rtp->header_size) {
        fprintf(stdout, "Packet too short for RTP header\n");
        return -1;
    }

    return 0;
}

//int parse_rtp_header(const unsigned char *packet, int size, rtp_header *rtp)
//{
//    if (!packet || !rtp) {
//        return -2;
//    }
//
//    if (size < RTP_HEADER_MIN) {
//        fprintf(stdout, "Packet too short for rtp\n");
//        return -1;
//    }
//
//    myRtpHeader *pRtpheader = (myRtpHeader*)packet;
//    int v = pRtpheader->version;
//    int x = pRtpheader->extension;
//    int pt = pRtpheader->payloadtype;
//    int seq = ntohs(pRtpheader->sequencenumber);
//    int ssrc = ntohl(pRtpheader->ssrc);
//
//    printf("======> v %d\n",v);
//    printf("======> x %d\n", x);
//    printf("======> seq %d\n", seq);
//    printf("======> pt %d\n", pt);
//    printf("======> ssrc 0x%x\n", ssrc);
//
//    return -1;
//}

int serialize_rtp_header(unsigned char *packet, int size, rtp_header *rtp)
{
    int i;

    if (!packet || !rtp) {
        return -2;
    }
    if (size < RTP_HEADER_MIN) {
        fprintf(stdout, "Packet buffer too short for RTP\n");
        return -1;
    }
    if (size < rtp->header_size) {
        fprintf(stdout, "Packet buffer too short for declared RTP header size\n");
        return -3;
    }
    packet[0] = ((rtp->version & 3) << 6) |
        ((rtp->pad & 1) << 5) |
        ((rtp->ext & 1) << 4) |
        ((rtp->cc & 7));
    packet[1] = ((rtp->mark & 1) << 7) |
        ((rtp->type & 127));
    be16(packet + 2, rtp->seq);
    be32(packet + 4, rtp->time);
    be32(packet + 8, rtp->ssrc);
    if (rtp->cc && rtp->csrc) {
        for (i = 0; i < rtp->cc; i++) {
            be32(packet + 12 + i * 4, rtp->csrc[i]);
        }
    }

    return 0;
}

int update_rtp_header(rtp_header *rtp)
{
    rtp->header_size = 12 + 4 * rtp->cc;
    return 0;
}

#define DYNAMIC_PAYLOAD_TYPE_MIN 96

CPCAPManager* CPCAPManager::m_pInstance = NULL;

CPCAPManager* CPCAPManager::GetInstance()
{
    if (NULL == m_pInstance)
    {
        m_pInstance = new CPCAPManager;
    }

    return m_pInstance;
}

void CPCAPManager::Release()
{
    if (NULL != m_pInstance)
    {
        delete m_pInstance;
        m_pInstance = NULL;
    }
}



//pcap_loop(pcap_t *p, int cnt,   pcap_handler callback,   u_char *user)�����������ǻص�������ԭ������:
//pcap_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
//���в���packet_content��ʾ�Ĳ��񵽵����ݰ������ݲ���argument�ǴӺ���pcap_loop()���ݹ����ġ�  pcap_loop��callback֮�����������ϵ��pcap_loop�����һ������user�������û�ʹ�õģ���callback����
//�õ�ʱ�����ֵ�ᴫ�ݸ�callback�ĵ�һ������(Ҳ��user)��callback�����һ������pָ��һ���ڴ�ռ䣬����ռ��д�ŵľ���pcap_loopץ�������ݰ���
void CPCAPManager::GetPacket(unsigned char* args, const struct pcap_pkthdr* header, const unsigned char* data)
//���������ʵҲ����winpcap lib����ص���һ���ӿڣ�������������������׵������ص�����ȥ��   �������Ƕ����ǵ�һ�����ݰ������������ǵ�ץ���ļ���RTP�ģ�rtp�ǻ���udp�ģ�udp���滹��IP����������һ����
//������Ĺ��̡�
{
    eth_header eth;
    loop_header loop;
    ip_header ip;
    udp_header udp;
    rtp_header rtp;

    CPCAPManager *params = (CPCAPManager *)(void *)args;

    fprintf(stdout, "Got %d byte packet (%d bytes captured)\n",
        header->len, header->caplen);
    
    const unsigned char *packet = data;
    int size = header->caplen;

    /* parse the link-layer header */
    switch (params->m_iLinkType)     //�������Ĺ���
    {
        //��̫��֡����  ���Ƚ�������������֡���ж���ʲô֡
        case DLT_EN10MB:
        {
            if (parse_eth_header(packet, size, &eth))
            {
                fprintf(stdout, "error parsing eth header\n");
                return;
            }

            fprintf(stdout, "  eth 0x%04x", eth.type);
            fprintf(stdout, " %02x:%02x:%02x:%02x:%02x:%02x ->",
                eth.src[0], eth.src[1], eth.src[2],
                eth.src[3], eth.src[4], eth.src[5]);

            fprintf(stdout, " %02x:%02x:%02x:%02x:%02x:%02x\n",
                eth.dst[0], eth.dst[1], eth.dst[2],
                eth.dst[3], eth.dst[4], eth.dst[5]);

            if (eth.type != 0x0800)
            {
                fprintf(stdout, "skipping packet: no IPv4\n");
                return;
            }

            packet += ETH_HEADER_LEN;
            size -= ETH_HEADER_LEN;
            break;
        }

        case DLT_NULL:
        {
            if (parse_loop_header(packet, size, &loop))
            {
                fprintf(stdout, "error parsing loopback header\n");
                return;
            }
            fprintf(stdout, "  loopback family %d\n", loop.family);
            if (loop.family != PF_INET) {
                fprintf(stdout, "skipping packet: not IP\n");
                return;
            }
            packet += LOOP_HEADER_LEN;
            size -= LOOP_HEADER_LEN;
            break;
        }
        default:
        {
            fprintf(stdout, "  skipping packet: unrecognized linktype %d\n",
                params->m_iLinkType);
        }

        return;
    }

    //����IPЭ��
    if (parse_ip_header(packet, size, &ip))
    {
        fprintf(stdout, "error parsing ip header\n");
        return;
    }

    fprintf(stdout, "  ipv%d protocol %d", ip.version, ip.protocol);

    char szSrcIP[18] = { 0 };
    sprintf(szSrcIP, " %d.%d.%d.%d ->",
        ip.src[0], ip.src[1], ip.src[2], ip.src[3]);
    std::cout << szSrcIP;

    char szDstIP[18] = { 0 };
    sprintf(szDstIP, " %d.%d.%d.%d",
        ip.dst[0], ip.dst[1], ip.dst[2], ip.dst[3]);
    std::cout << szDstIP;

    fprintf(stdout, "  header %d bytes\n", ip.header_size);
    if (ip.protocol != 17) {
        fprintf(stdout, "skipping packet: not UDP\n");
        return;
    }

    packet += ip.header_size;
    size -= ip.header_size;

    //����udpЭ��
    if (parse_udp_header(packet, size, &udp)) {
        fprintf(stdout, "error parsing udp header\n");
        return;
    }
    fprintf(stdout, "  udp  %d bytes %d -> %d crc 0x%04x\n",
         udp.size, udp.src, udp.dst, udp.checksum);
    packet += UDP_HEADER_LEN;
    size -= UDP_HEADER_LEN;

    int iUDPSrcPort = udp.src;
    int iUDPDstPort = udp.dst;

    //����rtpЭ��  ������rtp���ݴ������ǵĽ�������
    if (parse_rtp_header(packet, size, &rtp)) {
        fprintf(stdout, "error parsing rtp header\n");
        return;
    }
    
    char szSSRC[15] = { 0 };
    sprintf(szSSRC, "0x%x", rtp.ssrc);
    
    fprintf(stdout, "  rtp 0x%08x %d %d %d",
        rtp.ssrc, rtp.type, rtp.seq, rtp.time);

    fprintf(stdout, "  v%d %s%s%s CC %d", rtp.version,
        rtp.pad ? "P" : ".", rtp.ext ? "X" : ".",
        rtp.mark ? "M" : ".", rtp.cc);
    fprintf(stdout, " %5d bytes\n", rtp.payload_size);

    packet += rtp.header_size;   //������rtp head��ȥȡpayload������
    size -= rtp.header_size;

    SRTPInfo info;  ///////////////////////////���ǻ����Ҫ��ע��һЩ�ֶη��뵽SRTPInfo
    info.iPayloadType = rtp.type;
    info.iSeq = rtp.seq;
    info.iUDPDstPort = udp.dst;
    info.iUDPSrcPort = udp.src;
    info.strSrcIP = szSrcIP;
    info.strDstIP = szDstIP;
    info.strSSRC = szSSRC;
    info.bMark = rtp.mark !=0?true:false;

    //������ȡ�����Ժ󣬻������Ӧ�Ľ������ص�����init()�����ѽ������ص�ע���ȥ��  h264�ľ͵�h264�Ļص� ���������ص�  ����init�����ѽ������ص�ע���ȥ�������H264�ģ��ͻ��H264�Ļص���  
    params->m_funcParse(info, (unsigned char*)packet, size);    //size:payload�ĳ���
}



//������ԭ��Ҳ���ǻ����������ص��������洢��ͬ�Ľ�������Parsef����Ҫ��64����h265ʱ���ͷֱ�h264��h265�Ľ�������
int CPCAPManager::Init(const std::string& strPcapFile, const ParseFunc& Parsef, const LoopEndFunc& LoopEndf)  //strPcapFile����һ����������Ҫ������pcap���ļ����� Parsef�����ǽ������Ļص�������
   //LoopEndf:����ѭ�������Ļص�����
{
    char szErrbuf[PCAP_ERRBUF_SIZE] = { 0 };
    m_pPcap = pcap_open_offline(strPcapFile.c_str(), szErrbuf); //����winpcap�������API����pcap�ļ���
	//pcap_t * 	pcap_open_offline (const char *fname, char *errbuf)
	//��һ�� tcpdump/libpcap ��ʽ�Ĵ洢�ļ�������ȡ���ݰ�

    if (NULL == m_pPcap)
    {
        std::cout << "open pcap file " << strPcapFile << " failed,error info " << szErrbuf << std::endl;
        return -1;
    }

    m_iLinkType = pcap_datalink(m_pPcap);  //�ж�pcap����һ��ʲô����֡���ͣ�
	//int 	pcap_datalink (pcap_t *p)
	//��������������·��

    m_funcParse = Parsef;    //�ѻص� �洢��pcap manager�����棬 ���Ƕ����std��function���͵Ļص��Ļ��и��ô���ֱ�ӿ��Դ洢�ģ�
    m_funcLoopEnd = LoopEndf;
    m_strPcapFile = strPcapFile;   //���ļ���Ҳ�洢����
    return 0;
}

void CPCAPManager::ReadLoop()  //winpcap��һ��ѭ���ģ����ǵ�ReadLoop  Ҳ������� ѭ��
{
    //�ļ�����ѭ��
    pcap_loop(m_pPcap, !m_strPcapFile.empty()?0:300, CPCAPManager::GetPacket, (unsigned char *)this);  //pcap_loop��winpcap����ĺ��������Ƕ�pcap�ļ����н����Ĺ��ܣ����᲻ͣ��ѭ��һֱ�����������ļ���
	//ĩβ���ļ��������������ѭ����m_pPcap��pcap�ļ���ʱ�ľ����   �ڶ�����������Ӧ���ļ�������ֵ      GetPacket��������pcap loopʱ��  ����ȥ����  ���ݣ�����ͨ���ص��������׸����ǣ����Ƕ������
	//�ݽ��н�������ô���Ǿ���Ӧ�ذ�һ�����ǽ������ݵĻص�ע���ȥ��  ���һ��������������������Ҫ�ص�ʱ�������ǵ�һ�����󣬵�loop��ʼ�������Ժ�ֻ�ᵽ�����ļ���ȡ�����Ժ�Ż�ֹͣ���Ż᷵�أ������Ժ��������Ǵ洢�� m_funcLoopEnd()�ص�������

	//int 	pcap_loop (pcap_t *p, int cnt, pcap_handler callback, u_char *user)    �ռ�һ�����ݰ�
	//

    m_funcLoopEnd();
}


//������Ҳ�ܼ򵥣�����ʵ��ԭ��Ҳ���ǻ����������ص��������洢��ͬ�Ľ�����������ҪH264����H265��ʱ����ô�ͷֱ�H264��H265�Ľ�����Init����const ParseFunc& Parsef��������������ҵ���һ�ֿ�ܡ�
