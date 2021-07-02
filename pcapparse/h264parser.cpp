#include <iostream>
#include "h264parser.h"
#include "h264frameunpack.h"

CH264Parser* CH264Parser::m_pInstance = NULL;

CH264Parser* CH264Parser::GetInstance()
{
    if (NULL == m_pInstance)
    {
        m_pInstance = new CH264Parser;
    }

    return m_pInstance;
}

void CH264Parser::Release()
{
    if (NULL != m_pInstance)
    {
        delete m_pInstance;
        m_pInstance = NULL;
    }
}

int CH264Parser::Init(int iPayloadType, const std::string& strSSRC, std::string& strOutputFile,
    const std::string& strSrcIP, int iSrcPort, const std::string& strDstIP, int iDstPort)     //将命令行解析的过滤条件存储到相应的解析器里面
{
    m_strSrcIP = strSrcIP;
    m_strDstIP = strDstIP;
    m_iSrcPort = iSrcPort;
    m_iDstPort = iDstPort;
    m_strSSRC = strSSRC;
    m_iPayLoadType = iPayloadType;
    m_iCurretnKeyFrame = 0;
    m_pOutputFile = fopen(strOutputFile.c_str(), "wb");
    if (NULL == m_pOutputFile)
    {
        return -1;
    }

    return 0;
}


//void CPCAPManager::GetPacket  P439调用该函数
void CH264Parser::ParserH264(const SRTPInfo& rtpInfo, unsigned char* pData, int iPayloadSize)   //框架里面它调用我们回调以后他会传rtpInfo，pData：panload数据
{
    if ((rtpInfo.strSSRC != m_strSSRC) || rtpInfo.iPayloadType != m_iPayLoadType ||
        (rtpInfo.iUDPDstPort != m_iDstPort))
    {
        return;  //不是我们需要的数据
    }


    int iRet = ProcessH264Video(pData, iPayloadSize, rtpInfo.bMark, m_h264Frame);  //对fu-A的包和single的包进行解析的操作
    if (-1 == iRet)
    {
        return;
    }

    if (rtpInfo.bMark)  //解析完了以后，判断mark值，一帧的数据在RTP包里面是通过mark去体现的
    {
		//标示一帧数据的完结
        unsigned char* pWirteData = m_h264Frame.GetFramePtr();  //将缓存里的数据取出来
        int iDataSize = m_h264Frame.GetFrameSize();

        if (m_pOutputFile)
        {
            fwrite(pWirteData, iDataSize, 1, m_pOutputFile); //把码流提取出来，组成一个完整帧以后，存文件
        }

        m_h264Frame.ResetFramePool(); //对缓存进行重置，因为这个缓存每次只存一帧
    }
}

//里面是对H264 Fu-A和single单个NALU单元的RTP包进行解析的，处理函数 **
int CH264Parser::ProcessH264Video(unsigned char* pData, unsigned int iSize, bool isMark, CH264FrameUnpack &h264unpack)  
{
    if (NULL == pData)
    {
        return -1;
    }

    unsigned char* pHeaderStart = pData;
    unsigned int PacketSize = iSize;
    // 0x1F的二进制为0001 1111,pHeaderStart[0]为rtp数据的一个字节(FU indicator)为大端序,取出type的值
    int type = pHeaderStart[0] & 0x1F;
    int iPacketSize = iSize;
    if (type == 28)
    {//FU-A
     //pHeaderStart[1]为rtp数据的第二字节(FU header)为大端序,取出S标识
        unsigned char startBit = pHeaderStart[1] >> 7;
        //0x40的二进制为0100 0000,右移6位转换位小端,取出E标识
        unsigned char endBit = (pHeaderStart[1] & 0x40) >> 6;

        SH264PacketParams params;
        params.bMark = isMark;

        if (startBit)
        {//FU-A的起始
            pData += 2;
            iPacketSize -= 2;
            params.type = enNaluType_FUAStart;
            //组成nal header
            //Nal header = Forbidden_bit(1位) + nal_reference_bit(2位) + Nal_unit_type(5位)
            params.H264NalHeader = ((*(pData - 2)) & 0xE0) | ((*(pData - 1)) & 0x1F);   //感觉有问题,我改对了
        }
        else
        {// end
            pData += 2;
            iPacketSize -= 2;
            if (endBit)
                params.type = enNaluType_FUAEnd;
            else
                params.type = enNaluType_FUA;

        }

        h264unpack.SetFrameData(pData, iPacketSize, params);
    }
    else if (24 == type)
    {//STAP_A
        return 0;
    }
    else
    {//Single
        SH264PacketParams params;
        params.type = enNaluType_Single;
        params.H264NalHeader = pData[0];

        h264unpack.SetFrameData(pData + 1, iPacketSize - 1, params);

    }

    return 0;
}

void CH264Parser::ParserEndProcess()
{
    if (NULL != m_pOutputFile)
    {
        fclose(m_pOutputFile);    //在循环完以后将我们码流文件关闭
        m_pOutputFile = NULL;
    }
}