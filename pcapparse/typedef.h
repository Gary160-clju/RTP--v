#ifndef TYPEDEF_H
#define TYPEDEF_H
#include <string>
struct SRTPInfo
{
    bool bMark;
    int iPayloadType;
    int iSeq;
    int iUDPSrcPort;
    int iUDPDstPort;
    std::string strSrcIP;
    std::string strDstIP;
    std::string strSSRC;
};

enum enNaluType
{
    enNaluType_UnKnow = -1,
    //单帧即一个rtp包中就带了一帧数据
    enNaluType_Single = 0,
    //FUA的开头
    enNaluType_FUAStart = 1,
    //FUA数据帧
    enNaluType_FUA = 2,
    //FUA的结束
    enNaluType_FUAEnd = 3
};

enum enFUAState  //标识我们Fu-A解析的一个状态
{
    enFUAState_Init = 0,
    enFUAState_Start,
    enFUAState_Data,
    enFUAState_End,
    enFUAState_Terminate    //组帧完成后，对当前帧结束状态的一个标示
};

struct SH265PacketParams
{
    SH265PacketParams()
    {
        bMark = false;
        type = enNaluType_UnKnow;
        memset(H265NalHeader, 0, 2);
    }

    bool bMark;
    enNaluType type;
    //Nal单元的头一个字节用于判断帧类型
    unsigned char H265NalHeader[2];
};

struct SH264PacketParams
{
    SH264PacketParams()
    {
        bMark = false;
        type = enNaluType_UnKnow;
    }

    bool bMark;
    enNaluType type;
    //Nal单元的头一个字节用于判断帧类型
    unsigned char H264NalHeader;   // H264 nal头只是有一个字节
};

#endif