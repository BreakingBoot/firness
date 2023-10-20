

// Define command-line options for input file and output dir
static llvm::cl::opt<std::string> InputFileName(
    "f", llvm::cl::desc("Specify the input filename"), llvm::cl::value_desc("filename"));

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
    //ClangTool Tool = createClangTool(OptionsParser);
    ClangTool Tool(OptionsParser.getCompilations(), OptionsParser.getCompilations().getAllFiles()); // For compilation database input
    //ClangTool Tool(OptionsParser.getCompilations(), OptionsParser.getSourcePathList()); // For Single file input

    if(!input_filename.empty())
        processFunctionNames(input_filename);
    else
    {
        llvm::errs() << "Missing Input File\n";
        exit(1);
    }
    Tool.run(newFrontendActionFactory<FCPAction>().get());

    if(!output_filename.empty())
    {
        outputCallMap(output_filename);
        outputTypeStruct(output_filename);
    }
    else
        printCallMap(CallMap);

    return 0;
}