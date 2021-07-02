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


int parse_rtp_header(const unsigned char *packet, int size, rtp_header *rtp)   //解析RTP头的   //它的解析方式是：它将我们的大端数据转换成了小端数据，所以它有很多移位操作
{
    if (!packet || !rtp) {
        return -2;
    }
    if (size < RTP_HEADER_MIN) {
        fprintf(stdout, "Packet too short for rtp\n");
        return -1;
    }
	//它把我们RTP头里面所需要的数据全部解析了出来
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
    rtp->time = ntohl(t);   //////////////////我们的时间戳
    
    unsigned int ssrc = 0;    ///////////////我们的SSRC
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



//pcap_loop(pcap_t *p, int cnt,   pcap_handler callback,   u_char *user)第三个参数是回调函数其原型如下:
//pcap_callback(u_char* argument, const struct pcap_pkthdr* packet_header, const u_char* packet_content)
//其中参数packet_content表示的捕获到的数据包的内容参数argument是从函数pcap_loop()传递过来的。  pcap_loop和callback之间参数存在联系：pcap_loop的最后一个参数user是留给用户使用的，当callback被调
//用的时候这个值会传递给callback的第一个参数(也叫user)，callback的最后一个参数p指向一块内存空间，这个空间中存放的就是pcap_loop抓到的数据包。
void CPCAPManager::GetPacket(unsigned char* args, const struct pcap_pkthdr* header, const unsigned char* data)
//这个函数其实也就是winpcap lib里面回调的一个接口，它会把它解析的数据抛到函数回调里面去，   这里面是对我们的一个数据包层层解析。我们的抓包文件是RTP的，rtp是基于udp的，udp下面还有IP，所以它是一个层
//层解析的过程。
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
    switch (params->m_iLinkType)     //层层解析的过程
    {
        //以太网帧类型  首先解析我们物理层的帧，判断是什么帧
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

    //解析IP协议
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

    //解析udp协议
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

    //解析rtp协议  ，最后把rtp数据传给我们的解析器，
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

    packet += rtp.header_size;   //跳过了rtp head，去取payload的数据
    size -= rtp.header_size;

    SRTPInfo info;  ///////////////////////////我们会把需要关注的一些字段放入到SRTPInfo
    info.iPayloadType = rtp.type;
    info.iSeq = rtp.seq;
    info.iUDPDstPort = udp.dst;
    info.iUDPSrcPort = udp.src;
    info.strSrcIP = szSrcIP;
    info.strDstIP = szDstIP;
    info.strSSRC = szSSRC;
    info.bMark = rtp.mark !=0?true:false;

    //将数据取出来以后，会调用相应的解析器回调，在init()里面会把解析器回调注册进去。  h264的就调h264的回调 码流解析回调  （在init里面会把解析器回调注册进去，如果是H264的，就会调H264的回调）  
    params->m_funcParse(info, (unsigned char*)packet, size);    //size:payload的长度
}



//这个框架原理也就是基于这两个回调函数来存储不同的解析器，Parsef：需要好64或者h265时，就分别传h264和h265的解析器，
int CPCAPManager::Init(const std::string& strPcapFile, const ParseFunc& Parsef, const LoopEndFunc& LoopEndf)  //strPcapFile：第一个是我们需要解析的pcap的文件名， Parsef：我们解析器的回调函数，
   //LoopEndf:我们循环结束的回调函数
{
    char szErrbuf[PCAP_ERRBUF_SIZE] = { 0 };
    m_pPcap = pcap_open_offline(strPcapFile.c_str(), szErrbuf); //调用winpcap库里面的API：打开pcap文件，
	//pcap_t * 	pcap_open_offline (const char *fname, char *errbuf)
	//打开一个 tcpdump/libpcap 格式的存储文件，来读取数据包

    if (NULL == m_pPcap)
    {
        std::cout << "open pcap file " << strPcapFile << " failed,error info " << szErrbuf << std::endl;
        return -1;
    }

    m_iLinkType = pcap_datalink(m_pPcap);  //判断pcap它是一个什么样的帧类型，
	//int 	pcap_datalink (pcap_t *p)
	//返回适配器的链路层

    m_funcParse = Parsef;    //把回调 存储到pcap manager类里面， 我们定义成std：function类型的回调的话有个好处是直接可以存储的，
    m_funcLoopEnd = LoopEndf;
    m_strPcapFile = strPcapFile;   //把文件名也存储下来
    return 0;
}

void CPCAPManager::ReadLoop()  //winpcap有一个循环的，我们的ReadLoop  也就是这个 循环
{
    //文件解析循环
    pcap_loop(m_pPcap, !m_strPcapFile.empty()?0:300, CPCAPManager::GetPacket, (unsigned char *)this);  //pcap_loop是winpcap库里的函数，它是对pcap文件进行解析的功能，它会不停地循环一直解析到我们文件的
	//末尾，文件读完后它会跳出循环。m_pPcap：pcap文件打开时的句柄，   第二个参数：对应的文件的类型值      GetPacket：当我们pcap loop时候  ，它去解析  数据，它会通过回调将数据抛给我们，我们对这个数
	//据进行解析，那么我们就相应地把一个我们解析数据的回调注册进去，  最后一个参数传给它就是它需要回调时传给我们的一个对象，当loop开始跑起来以后，只会到我们文件读取完了以后才会停止，才会返回，返回以后会调用我们存储的 m_funcLoopEnd()回调函数。

	//int 	pcap_loop (pcap_t *p, int cnt, pcap_handler callback, u_char *user)    收集一组数据包
	//

    m_funcLoopEnd();
}


//这个框架也很简单，整个实现原理也就是基于这两个回调函数来存储不同的解析器，当需要H264或者H265的时候，那么就分别传H264和H265的解析器Init（，const ParseFunc& Parsef，），它是脱离业务的一种框架。
