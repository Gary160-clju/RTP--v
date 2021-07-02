#ifndef PCAP_MANAGER_H
#define PCAP_MANAGER_H

#include <stdlib.h>
#include <string>
#include <functional>
#include "pcap.h"
#include "typedef.h"


typedef std::function<void(const SRTPInfo& rtpInfo,unsigned char* pData, int iPayloadSize)> ParseFunc;    //解析器的回调函数,它是一个函数对象，  pData：rtp  payload的数据。iPayloadSize：负载的长度。
typedef std::function<void()> LoopEndFunc;     //循环结束的回调函数，

//这个类是一个框架类，它的主要作用其实也就是封装了我们winpcap的API，我们pcap文件的解析，以及将我们解析出来的RTP数据传入我们相应的解析器，
//与解析器无关的一个解析pcap文件的一个封装类，作用主要是封装了WinPCAP的API，我们pcap文件的解析，以及将我们解析出来的RTP数据传入我们相应的解析器，
class CPCAPManager  //winpcap库里API的使用，
{
    public:
        static CPCAPManager* GetInstance();     //是一个单例模式
        static void Release();

    private:
        //winpcap解析抓包文件时的获取包数据的回调
        static void GetPacket(unsigned char* args, const struct pcap_pkthdr* header, const unsigned char* data);
    private:
        CPCAPManager() :m_pPcap(NULL), m_iLinkType(-1)
        {

        }

        ~CPCAPManager()
        {
            pcap_close(m_pPcap);
        }

    public:
        //初始化
        /*
        * Parsef 解析码流的回调
        * LoopEndf 当pcap文件读取完后的回调
        *
        */
        int Init(const std::string& strPcapFile, const ParseFunc& Parsef, const LoopEndFunc& LoopEndf);
        //解析pcap文件的循环
        void ReadLoop();
    private:
        static CPCAPManager* m_pInstance;
    private:
        pcap_t *m_pPcap;
        int m_iLinkType;
        ParseFunc m_funcParse;     //CH264Parser::ParserH264
        LoopEndFunc m_funcLoopEnd;
        std::string m_strPcapFile;

};
#endif