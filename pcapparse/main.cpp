//最后实验一遍对不对，然后发到github上。第一次发把那个错误留上，第二次再改掉它

#include <iostream>
#include <string>
#include "boost/program_options.hpp"
#include "pcapmanager.h"
//#include "opusparser.h"
//#include "h265parser.h"
#include "h264parser.h"

int main(int argc, char*argv[])
{
    //设置  程序支持的命令行选项      去解析命令行参数，   下面是我们程序支持的命令行参数选项           namespace alias :namespace po = boost::program_options;
    boost::program_options::options_description desc("Allowed options");   ////选项描述器,其参数为该描述器的名字   //解析命令行参数
    desc.add_options()   //为选项描述器增加选项
        ("c", boost::program_options::value<std::string>(), "choose codec")    //c,s,t,o,e,d是命令行参数
        ("s", boost::program_options::value<std::string>(), "ssrc")
        ("t", boost::program_options::value<int>(), "payload type")   // /* 有参赛的选项格式 :  "命令名", "参数说明", "命令说明" * /
        ("o", boost::program_options::value<std::string>(), "out put file name")
        ("e", boost::program_options::value<std::string>(), "input pcap file name")
        ("d", boost::program_options::value<int>(), "dst port");

    //解析命令行   命令行解析库怎么使用，可以看下相应的API文档。
    boost::program_options::variables_map vm;  //选项存储器,继承自map容器     //解析命令行 , 存储在variables_map 类的变量中。variables_map 类是用来存储具体传入参数数据的类 , 和map很相似. 使用as接口来传出数
    try  //注意: 如果传入没有定义的选项, 会抛出异常!
    {
        //先对命令行输入的参数做解析,而后将其存入选项存储器
    //如果输入了未定义的选项，程序会抛出异常，所以对解析代码要用try-catch块包围
        // //parse_command_line()对输入的选项做解析
        //store()将解析后的结果存入选项存储器
        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);  //store(parse_command_line(ac, av, desc), vm);  ac 就是参数个数 , av 就是参数列表指针
    }
    catch (const std::exception& e)
    {
        std::cout << "unknow option" << std::endl;
        return -1;
    }

    boost::program_options::notify(vm);

    //对命令行选项做判断   解析完命令行后，根据命令行参数进行一个判断，进行相应的业务逻辑处理
    //参数解析完毕，处理实际信息.  count()检测该选项是否被输入
    if (vm.count("help"))     //{//若参数中有help选项                        //判断命令是否触发, 以 help 为例 ,  variables_map 使用 count 接口来判断具体选项是否触发 
    {
        std::cout << desc << std::endl;    //自动打印所有的选项信息  /*如果触发就输出命令说明 , option_description 类重载了 << 行为, 将格式化的输出命令说明* /
        return 0;
    }

	//通过我们输入的命令行参数进行进行相应的业务逻辑处理
   // std::vector<std::string> vecSupportCodec = { "h265","opus" };
    std::vector<std::string> vecSupportCodec = { "h265","opus","h264" };//vecSupportCodec变量中加入h264，然后重新编译。在命令行中需要注意的三个选项: --c h264 --t 96(具
    //体为值pcap抓包文件中的rtp payload值) --s ssrc值(具体值为pcap抓
    //包文件中的rtp ssrc值)
    std::string strCodec;
    if (vm.count("c"))
    {  
        strCodec = vm["c"].as<std::string>();   // map直接使用键值当index , 然后使用as< 具体类型> 接口来取出 传入的 参数
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
    {//opus处理   opus是音频编码，这是处理opus的解析器，
        COpusparser::GetInstance()->Init(iPayloadType, strSSRC, strOutputFile, 8000, 1, "", 0, "", iDstPort);
        CPCAPManager::GetInstance()->Init(strInputFile, std::bind(&COpusparser::ParserOpus, COpusparser::GetInstance(), std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
            std::bind(&COpusparser::ParserEndProcess, COpusparser::GetInstance()));
    }
    else if ("h265" == strCodec)   // 比如我们输入-c参数 是H265
    {//h265的处理      它会走H265的处理流程
        CH265Parser::GetInstance()->Init(iPayloadType, strSSRC, strOutputFile, "", 0, "", iDstPort);
        CPCAPManager::GetInstance()->Init(strInputFile, std::bind(&CH265Parser::ParserH265, CH265Parser::GetInstance(), std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
            std::bind(&CH265Parser::ParserEndProcess, CH265Parser::GetInstance()));
    }

#endif

	//我们通过命令行进行判断它是哪一种类型的编码格式，  std::bind(&CH264Parser::ParserH264：传入h264解析器回调
    //else if ("h264" == strCodec)
    if ("h264" == strCodec)
    {//h264的处理   我们通过将&CH264Parser::ParserH264绑定到我们框架类里面   的回调函数  就将h264解析器和框架进行联系了
        CH264Parser::GetInstance()->Init(iPayloadType, strSSRC, strOutputFile, "", 0, "", iDstPort);
        CPCAPManager::GetInstance()->Init(strInputFile, std::bind(&CH264Parser::ParserH264, CH264Parser::GetInstance(), std::placeholders::_1, std::placeholders::_2, std::placeholders::_3),
            std::bind(&CH264Parser::ParserEndProcess, CH264Parser::GetInstance()));   //在init时传入  h264解析器（CH264Parser::ParserH264：解析fu-A的包和single Nalu的包）的回调    ，   std::bind(&CH264Parser::ParserEndProcess ：循环完了以后的回调
         //将我们解析器相应的解析函数绑定到框架里面，  之前说框架里面回调函数是通过std:function去声明的，所以我们可以结合std:bind将我们一个类的成员函数CH264Parser::ParserH264绑定成我们的function类
		//型，
	}


    CPCAPManager::GetInstance()->ReadLoop();
}
