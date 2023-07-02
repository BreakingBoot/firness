#include "AnalyzeHelpers.h"
#include "JSONHelpers.h"
#include "Action.h"

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

int main(int argc, const char **argv)
{
    if (argc < 2)
    {
        llvm::errs() << "Usage: " << argv[0] << " <dir>\n";
        return 1;
    }

    fs::path rootPath(argv[3]);
    if (!fs::exists(rootPath) || !fs::is_directory(rootPath))
    {
        llvm::errs() << "Error: '" << rootPath << "' is not a directory.\n";
        return 1;
    }

    int totalResult = 0;

    for (auto &p : fs::recursive_directory_iterator(rootPath))
    {
        if (p.path().extension() == ".c") // Adjust this if needed
        {
            std::vector<std::string> args = {
                argv[0],
                argv[1],
                argv[2],
                p.path().string(),
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

            delete[] argvFake;
        }
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