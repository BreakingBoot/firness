#ifndef _ACTION_H_
#define _ACTION_H_

class Action : public clang::ASTFrontendAction
{
public:
    Action() {}

    virtual std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
        clang::CompilerInstance &Compiler, llvm::StringRef InFile)
    {
        const std::set<std::string> input = {"Demo1BobDataProvider",
                                             "Demo1AliceProvideData",
                                             "Demo1GenerateAccessKey",
                                             "Demo1ValidateAccessKey",
                                             "SetAccessVariable",
                                             "GetAccessVariable"};
        return std::unique_ptr<clang::ASTConsumer>(
            new Consumer(&Compiler.getASTContext(), input));
    }
};

#endif