#include "FCPAction.h"

std::map<TypedefDecl*, TypeData> varTypeInfo;
std::map<RecordDecl*, TypeData> varRecordInfo;

std::set<std::string> FunctionNames;
std::map<VarDecl*, std::stack<Assignment>> VarAssignments;
std::map<std::string, TypeData> FinalTypes;
std::map<CallExpr*, VarMap> CallExprMap;
std::map<CallExpr*, std::map<Expr*, ParameterDirection>> CallArgMap;
std::vector<Call> CallMap;
std::map<std::string, MacroDef> PreDefinedConstants;
std::vector<std::string> EnumConstants;
std::map<std::string, std::set<std::string>> EnumMap;
std::map<CallExpr*, VarMap> GeneratorFunctionsMap;
std::vector<Call> GeneratorMap;
std::set<std::string> IncludeDirectives;
std::set<std::pair<std::string, std::string>> SingleTypedefs;
std::set<std::string> GeneratorTypes;
std::set<std::pair<std::string, std::string>> HarnessFunctions;


// Define command-line options for input file and output dir
static llvm::cl::opt<std::string> InputFileName(
    "i", llvm::cl::desc("Specify the input filename"), llvm::cl::value_desc("filename"));

static llvm::cl::opt<std::string> OutputFileName(
    "o", llvm::cl::desc("Specify the output directory"), llvm::cl::value_desc("filename"));


int main(int argc, const char **argv) {
    llvm::cl::OptionCategory ToolingSampleCategory("Function Call Pass");
    Expected<CommonOptionsParser> ExpectedParser = CommonOptionsParser::create(argc, argv, ToolingSampleCategory);
    if (!ExpectedParser) {
        llvm::errs() << ExpectedParser.takeError();
        return 1;
    }

    CommonOptionsParser &OptionsParser = ExpectedParser.get();

    // Get the filename and output dir from command-line options
    std::string input_filename = InputFileName.getValue();
    std::string output_filename = OutputFileName.getValue();

    // Use the filename to create a ClangTool instance
    ClangTool Tool(OptionsParser.getCompilations(), OptionsParser.getCompilations().getAllFiles()); // For compilation database input
    // ClangTool Tool(OptionsParser.getCompilations(), OptionsParser.getSourcePathList()); // For Single file input

    if(!input_filename.empty())
    {
        FunctionNames = FileOps::processFunctionNames(input_filename);
        HarnessFunctions = FileOps::processHarnessFunctions(input_filename);
    }
    else
    {
        llvm::errs() << "Missing Input File\n";
        exit(1);
    }
    Tool.run(newFrontendActionFactory<FCPAction>().get());

    if(!output_filename.empty())
    {
        FileOps::outputCallMap(output_filename, CallMap);
        FileOps::outputTypeStructs(output_filename, FinalTypes);
        FileOps::outputGeneratorMap(output_filename, GeneratorMap);
        FileOps::outputTypedefs(output_filename, SingleTypedefs);
        FileOps::outputMacros(output_filename, PreDefinedConstants);
        FileOps::outputEnums(output_filename, EnumMap);
    }
    else
        FileOps::printCallMap(CallMap);

    return 0;
}