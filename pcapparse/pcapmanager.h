#ifndef PCAP_MANAGER_H
#define PCAP_MANAGER_H

#include <stdlib.h>
#include <string>
#include <functional>
#include "pcap.h"
#include "typedef.h"


typedef std::function<void(const SRTPInfo& rtpInfo,unsigned char* pData, int iPayloadSize)> ParseFunc;    //�������Ļص�����,����һ����������  pData��rtp  payload�����ݡ�iPayloadSize�����صĳ��ȡ�
typedef std::function<void()> LoopEndFunc;     //ѭ�������Ļص�������

//�������һ������࣬������Ҫ������ʵҲ���Ƿ�װ������winpcap��API������pcap�ļ��Ľ������Լ������ǽ���������RTP���ݴ���������Ӧ�Ľ�������
//��������޹ص�һ������pcap�ļ���һ����װ�࣬������Ҫ�Ƿ�װ��WinPCAP��API������pcap�ļ��Ľ������Լ������ǽ���������RTP���ݴ���������Ӧ�Ľ�������
class CPCAPManager  //winpcap����API��ʹ�ã�
{
    public:
        static CPCAPManager* GetInstance();     //��һ������ģʽ
        static void Release();

    private:
        //winpcap����ץ���ļ�ʱ�Ļ�ȡ�����ݵĻص�
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
        //��ʼ��
        /*
        * Parsef ���������Ļص�
        * LoopEndf ��pcap�ļ���ȡ���Ļص�
        *
        */
        int Init(const std::string& strPcapFile, const ParseFunc& Parsef, const LoopEndFunc& LoopEndf);
        //����pcap�ļ���ѭ��
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