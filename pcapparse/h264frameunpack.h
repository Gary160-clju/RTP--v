#ifndef H264_FRAME_H
#define H264_FRAME_H
#include "typedef.h"
 
//H264解包类，实现组帧操作  ， 它相当于一个缓存，会缓存我们的一帧数据，
class CH264FrameUnpack
{
    public:
 
        CH264FrameUnpack();
        ~CH264FrameUnpack();
 
        void ResetFramePool();
        //传入原始视频数据
        int SetFrameData(unsigned char* pData,int iSize,SH264PacketParams params);
        int GetFrameSize()
        {
            return m_iEncodeFrameLen;
        }
 
        //获取组成的H264一帧数据
        unsigned char* GetFramePtr()
        {
            return m_pEncodeFrame;
        }
 
    private:
        //将数据加入缓存中
        /* pData 帧片段数据
        *  iData 数据的长度
        *  pNaluHeader Nalu的头
        *  bAddHeader是否添加头标识
        */
        void AddData(unsigned char* pData,int iDataLen,unsigned char pNaluHeader,bool bAddHeader);
    private:
        //存储一帧数据
        unsigned char *m_pEncodeFrame;
        //一帧数据的长度
        unsigned int m_iEncodeFrameLen;
        //一帧数据的最大长度
        unsigned int  m_iEncodeFrameMax;
};
 
#endif