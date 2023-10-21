#ifndef __FCP_CONSUMER_H__
#define __FCP_CONSUMER_H__

#include "VariableFlow.h"
#include "CallSiteAnalysis.h"
#include "FileOperationHelpers.h"

class FCPConsumer : public clang::ASTConsumer {
public:
    explicit FCPConsumer(ASTContext *Context)
        : VariableVisitor(Context), FunctionVisitor(Context) {}

    void HandleTranslationUnit(clang::ASTContext &Context) override {
        VariableVisitor.TraverseDecl(Context.getTranslationUnitDecl());
        FunctionVisitor.TraverseDecl(Context.getTranslationUnitDecl());
    }
private:
    VariableFlow VariableVisitor;
    CallSiteAnalysis FunctionVisitor;
};

#endif 