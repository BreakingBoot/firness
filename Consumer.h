#ifndef _CONSUMER_H_
#define _CONSUMER_H_

class FirmwareConsumer : public clang::ASTConsumer
{
public:
    explicit FirmwareConsumer(ASTContext *Context, std::set<std::string> input)
        : Visitor(Context, input) {}

    virtual void HandleTranslationUnit(clang::ASTContext &Context)
    {
        Visitor.TraverseDecl(Context.getTranslationUnitDecl());
        FirmwareVisitor::results = Visitor.getResults();
    }

    FirmwareVisitor &getVisitor() { return Visitor; }

private:
    FirmwareVisitor Visitor;
};

#endif