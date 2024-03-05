#ifndef __FCP_CONSUMER_H__
#define __FCP_CONSUMER_H__

#include "VariableFlow.h"
#include "GeneratorAnalysis.h"
#include "CallSiteAnalysis.h"
#include "FileOperationHelpers.h"
#include "FunctionDeclAnalysis.h"

class FCPConsumer : public clang::ASTConsumer {
public:
    explicit FCPConsumer(ASTContext *Context)
        : VariableVisitor(Context), FunctionVisitor(Context), GeneratorVisitor(Context), CallVisitor(Context) {}

    void HandleTranslationUnit(clang::ASTContext &Context) override {
        VariableVisitor.TraverseDecl(Context.getTranslationUnitDecl());
        FunctionVisitor.TraverseDecl(Context.getTranslationUnitDecl());
        GeneratorVisitor.TraverseDecl(Context.getTranslationUnitDecl());
        CallVisitor.TraverseDecl(Context.getTranslationUnitDecl());
        CallArgMap.clear();
    }
private:
    VariableFlow VariableVisitor;
    CallSiteAnalysis CallVisitor;
    GeneratorAnalysis GeneratorVisitor;
    FunctionDeclAnalysis FunctionVisitor;
};

#endif 