#ifndef _CONSUMER_H_
#define _CONSUMER_H_

#include "AnalyzeHelpers.h"
#include "Visitor.h"

class Consumer : public clang::ASTConsumer
{
public:
    explicit Consumer(ASTContext *Context, std::set<std::string> input)
        : Visitor(Context, input) {}

    virtual void HandleTranslationUnit(clang::ASTContext &Context)
    {
        Visitor.TraverseDecl(Context.getTranslationUnitDecl());
        Visitor::results = Visitor.getResults();
    }

    Visitor &getVisitor() { return Visitor; }

private:
    Visitor Visitor;
};

#endif