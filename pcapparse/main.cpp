//���ʵ��һ��Բ��ԣ�Ȼ�󷢵�github�ϡ���һ�η����Ǹ��������ϣ��ڶ����ٸĵ���

#include <iostream>
#include <string>
#include "boost/program_options.hpp"
#include "pcapmanager.h"
//#include "opusparser.h"
//#include "h265parser.h"
#include "h264parser.h"

int main(int argc, char*argv[])
{
    //����  ����֧�ֵ�������ѡ��      ȥ���������в�����   ���������ǳ���֧�ֵ������в���ѡ��           namespace alias :namespace po = boost::program_options;
    boost::program_options::options_description desc("Allowed options");   ////ѡ��������,�����Ϊ��������������   //���������в���
    desc.add_options()   //Ϊѡ������������ѡ��
        ("c", boost::program_options::value<std::string>(), "choose codec")    //c,s,t,o,e,d�������в���
        ("s", boost::program_options::value<std::string>(), "ssrc")
        ("t", boost::program_options::value<int>(), "payload type")   // /* �в�����ѡ���ʽ :  "������", "����˵��", "����˵��" * /
        ("o", boost::program_options::value<std::string>(), "out put file name")
        ("e", boost::program_options::value<std::string>(), "input pcap file name")
        ("d", boost::program_options::value<int>(), "dst port");

    //����������   �����н�������ôʹ�ã����Կ�����Ӧ��API�ĵ���
    boost::program_options::variables_map vm;  //ѡ��洢��,�̳���map����     //���������� , �洢��variables_map ��ı����С�variables_map ���������洢���崫��������ݵ��� , ��map������. ʹ��as�ӿ���������
    try  //ע��: �������û�ж����ѡ��, ���׳��쳣!
    {
        //�ȶ�����������Ĳ���������,���������ѡ��洢��
    //���������δ�����ѡ�������׳��쳣�����ԶԽ�������Ҫ��try-catch���Χ
        // //parse_command_line()�������ѡ��������
        //store()��������Ľ������ѡ��洢��
        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);  //store(parse_command_line(ac, av, desc), vm);  ac ���ǲ������� , av ���ǲ����б�ָ��
    }
    catch (const std::exception& e)
    {
        std::cout << "unknow option" << std::endl;
        return -1;
    }

    boost::program_options::notify(vm);

    //��������ѡ�����ж�   �����������к󣬸��������в�������һ���жϣ�������Ӧ��ҵ���߼�����
    //����������ϣ�����ʵ����Ϣ.  count()����ѡ���Ƿ�����
    if (vm.count("help"))     //{//����������helpѡ��                        //�ж������Ƿ񴥷�, �� help Ϊ�� ,  variables_map ʹ�� count �ӿ����жϾ���ѡ���Ƿ񴥷� 
    {
        std::cout << desc << std::endl;    //�Զ���ӡ���е�ѡ����Ϣ  /*����������������˵�� , option_description �������� << ��Ϊ, ����ʽ�����������˵��* /
        return 0;
    }

	//ͨ����������������в������н�����Ӧ��ҵ���߼�����
   // std::vector<std::string> vecSupportCodec = { "h265","opus" };
    std::vector<std::string> vecSupportCodec = { "h265","opus","h264" };//vecSupportCodec�����м���h264��Ȼ�����±��롣������������Ҫע�������ѡ��: --c h264 --t 96(��
    //��Ϊֵpcapץ���ļ��е�rtp payloadֵ) --s ssrcֵ(����ֵΪpcapץ
    //���ļ��е�rtp ssrcֵ)
    std::string strCodec;
    if (vm.count("c"))
    {  
        strCodec = vm["c"].as<std::string>();   // mapֱ��ʹ�ü�ֵ��index , Ȼ��ʹ��as< ��������> �ӿ���ȡ�� ����� ����
        std::vector<std::string> ::iterator findIt = std::find(vecSupportCodec.begin(), vecSupportCodec.end(), strCodec);
        if (vecSupportCodec.end() == findIt)
        {
            std::cout << "unsupport codec " << strCodec << std::endl;
        }
    }
    else
    {
        std::cout << "need codec" << std::endl;
        return -1;
    }

    std::string strInputFile;
    if (vm.count("e"))
    {
        strInputFile = vm["e"].as<std::string>();
    }
    else
    {
        std::cout << "need input pcap file" << std::endl;
        return -1;
    }

    std::string strOutputFile;
    if (vm.count("o"))
    {
        strOutputFile = vm["o"].as<std::string>();
    }
    else
    {
        std::cout << "need out put filed" << std::endl;
        return -1;
    }

    std::string strSSRC;
    if (vm.count("s"))
    {
        strSSRC = vm["s"].as<std::string>();
    }
    else
    {
        std::cout << "need ssrc" << std::endl;
        return -1;
    }

    int iDstPort = -1;
    if (vm.count("d"))
    {
        iDstPort = vm["d"].as<int>();
    }
    else
    {
        std::cout << "need dst port" << std::endl;
        return -1;
    }

    int iPayloadType = -1;
    if (vm.count("t"))
    {
        iPayloadType = vm["t"].as<int>();
    }
    else
    {
        std::cout << "need t" << std::endl;
        return -1;
    }

#if  0
    if ("opus" == strCodec)
    {//opus����   opus����Ƶ���룬���Ǵ���opus�Ľ�������
        COpusparser::GetInstance()->Init(iPayloadType, strSSRC, strOutputFile, 8000, 1, "", 0, "", iDstPort);
        CPCAPManager::GetInstance()->Init(strInputFile, std::bind(&COpusparser::ParserOpus, COpusparser::GetInstance(), std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
            std::bind(&COpusparser::ParserEndProcess, COpusparser::GetInstance()));
    }
    else if ("h265" == strCodec)   // ������������-c���� ��H265
    {//h265�Ĵ���      ������H265�Ĵ�������
        CH265Parser::GetInstance()->Init(iPayloadType, strSSRC, strOutputFile, "", 0, "", iDstPort);
        CPCAPManager::GetInstance()->Init(strInputFile, std::bind(&CH265Parser::ParserH265, CH265Parser::GetInstance(), std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
            std::bind(&CH265Parser::ParserEndProcess, CH265Parser::GetInstance()));
    }

#endif

	//����ͨ�������н����ж�������һ�����͵ı����ʽ��  std::bind(&CH264Parser::ParserH264������h264�������ص�
    //else if ("h264" == strCodec)
    if ("h264" == strCodec)
    {//h264�Ĵ���   ����ͨ����&CH264Parser::ParserH264�󶨵����ǿ��������   �Ļص�����  �ͽ�h264�������Ϳ�ܽ�����ϵ��
        CH264Parser::GetInstance()->Init(iPayloadType, strSSRC, strOutputFile, "", 0, "", iDstPort);
        CPCAPManager::GetInstance()->Init(strInputFile, std::bind(&CH264Parser::ParserH264, CH264Parser::GetInstance(), std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
            std::bind(&CH264Parser::ParserEndProcess, CH264Parser::GetInstance()));   //��initʱ����  h264��������CH264Parser::ParserH264������fu-A�İ���single Nalu�İ����Ļص�    ��   std::bind(&CH264Parser::ParserEndProcess ��ѭ�������Ժ�Ļص�
         //�����ǽ�������Ӧ�Ľ��������󶨵�������棬  ֮ǰ˵�������ص�������ͨ��std:functionȥ�����ģ��������ǿ��Խ��std:bind������һ����ĳ�Ա����CH264Parser::ParserH264�󶨳����ǵ�function��
		//�ͣ�
	}


    CPCAPManager::GetInstance()->ReadLoop();
}
