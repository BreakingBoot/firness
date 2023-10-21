#ifndef __FCP_ACTION_H__
#define __FCP_ACTION_H__

#include "FCPConsumer.h"

class FCPAction : public clang::ASTFrontendAction {
public:
    std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
        clang::CompilerInstance &Compiler, llvm::StringRef InFile) override {
        return std::unique_ptr<clang::ASTConsumer>(
            new FCPConsumer(&Compiler.getASTContext()));
    }
};

#endif