#ifndef _ACTION_H_
#define _ACTION_H_

#include "AnalyzeHelpers.h"
#include "Consumer.h"

class Action : public clang::ASTFrontendAction
{
public:
    Action() {}

    virtual std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
        clang::CompilerInstance &Compiler, llvm::StringRef InFile)
    {
        return std::unique_ptr<clang::ASTConsumer>(
            new Consumer(&Compiler.getASTContext(), input));
    }
};

#endif