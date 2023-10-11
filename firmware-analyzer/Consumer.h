#ifndef _CONSUMER_H_
#define _CONSUMER_H_

#include "AnalyzeHelpers.h"
#include "Visitor.h"

class Consumer : public clang::ASTConsumer
{
public:
    explicit Consumer(ASTContext *Context, std::set<std::string> input)
        : visitor(Context, input) {}

    virtual void HandleTranslationUnit(clang::ASTContext &Context)
    {
        visitor.TraverseDecl(Context.getTranslationUnitDecl());
        output_results = visitor.getResults();
    }

    Visitor &getVisitor() { return visitor; }

private:
    Visitor visitor;
};

#endif