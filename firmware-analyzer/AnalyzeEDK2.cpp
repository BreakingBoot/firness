#include "AnalyzeHelpers.h"
#include "JSONHelpers.h"
#include "Action.h"

std::vector<Service> output_results;
std::vector<std::string> Includes;
std::set<std::string> input;

static llvm::cl::OptionCategory MyToolCategory("my-tool options");

std::vector<Service> get_results()
{
    std::vector<Service> results;
    std::vector<std::string> merged;
    for (Service serv : output_results)
    {
        if (std::find(merged.begin(), merged.end(), serv.Service) == merged.end())
        {
            merged.push_back(serv.Service);
            Service maxService = serv;
            for(Service inner_serv : output_results)
            {
                if ((inner_serv.get_score() > maxService.get_score()) && (inner_serv.Service == serv.Service))
                {
                    maxService = inner_serv;
                }
            }
            results.push_back(maxService);
        }
    }

    return results;
}

std::set<std::string> read_input(const std::string& filename)
{
    nlohmann::json in;
    std::ifstream inputFile(filename);

    if (!inputFile.is_open()) {
        std::cerr << "Could not open the file - '" << filename << "'" << std::endl;
    }

    inputFile >> in;
    inputFile.close();

    std::set<std::string> return_set;

    if(in.contains("HarnessServices") && in["HarnessServices"].is_array())
    {
        for(const auto& elem : in["HarnessServices"])
        {
            return_set.insert(elem.get<std::string>());
        }
    }
    else
    {
        std::cerr << "JSON object does not contain a 'HarnessServices' array" << std::endl;
    }

    return return_set;
}


std::vector<std::string> files_to_parse(const std::string& compile_commands)
{
    nlohmann::json in;
    std::ifstream inputFile(compile_commands + "/compile_commands.json");

    if (!inputFile.is_open()) {
        std::cerr << "Could not open the file - 'compile_commands.json'" << std::endl;
    }

    inputFile >> in;
    inputFile.close();

    std::vector<std::string> file_list;
    for(auto entry: in)
    {
        file_list.push_back(entry["file"]);
    }

    return file_list;
}


int main(int argc, const char **argv)
{
        if(argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " <functions_filename> <source_code_path>" << std::endl;
        return 1;
    }

    const std::string functionsFilename = argv[1];
    const std::string sourceCodePath = argv[2];

    int totalResult = 0;
    auto input = read_input(functionsFilename);
    std::vector<std::string> input_files = files_to_parse(sourceCodePath);

    for (auto p : input_files)
    {

        std::vector<std::string> args = {
            argv[0],
            argv[1],
            argv[2],
            p,
        };
        int argcFake = args.size();
        const char **argvFake = new const char *[argcFake];
        for (int i = 0; i < argcFake; ++i)
        {
            argvFake[i] = args[i].c_str();
        }

        Expected<CommonOptionsParser> ExpectedOptions =
            CommonOptionsParser::create(argcFake, argvFake, MyToolCategory);
        if (!ExpectedOptions)
        {
            llvm::errs() << ExpectedOptions.takeError();
            delete[] argvFake;
            return 1;
        }
        CommonOptionsParser &OptionsParser = ExpectedOptions.get();
        ClangTool Tool(OptionsParser.getCompilations(),
                       OptionsParser.getSourcePathList());
        int result = Tool.run(newFrontendActionFactory<Action>().get());
        totalResult += result;
        Includes.clear();

        delete[] argvFake;
    }
    Analysis all_analysis;
    all_analysis.ServiceInfo = output_results;
    all_analysis.Includes = Includes;

    generate_json("all_service_results.json", all_analysis);

    Analysis compressed_analysis;
    compressed_analysis.ServiceInfo = get_results();
    compressed_analysis.Includes = Includes;

    generate_json("compressed_service_results.json", compressed_analysis);

    return totalResult;
}

// clang++ -I/usr/lib/clang/15.0.7/include -I/usr/lib/llvm-15/include -L/usr/lib/llvm-15/lib $(llvm-config-15 --cxxflags) $(llvm-config-15 --ldflags --libs --system-libs) -lclang -lclangAST -lclangASTMatchers -lclangAnalysis -lclangBasic -lclangDriver -lclangEdit -lclangFrontend -lclangFrontendTool -lclangLex -lclangParse -lclangSema -lclangEdit -lclangRewrite -lclangRewriteFrontend -lclangStaticAnalyzerFrontend -lclangStaticAnalyzerCheckers -lclangStaticAnalyzerCore -lclangSerialization -lclangToolingCore -lclangTooling -lclangFormat tutorial.cpp -o tutorial