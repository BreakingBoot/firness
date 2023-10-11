#include <iostream>
#include <clang/AST/ASTConsumer.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Frontend/FrontendAction.h>
#include <clang/Tooling/CommonOptionsParser.h>
#include <clang/Tooling/Tooling.h>
#include <llvm/Support/CommandLine.h>

using namespace clang;
using namespace clang::driver;
using namespace clang::tooling;
using namespace llvm;

class FunctionVisitor : public RecursiveASTVisitor<FunctionVisitor> {
public:
    explicit FunctionVisitor(ASTContext *Context) : Context(Context) {}

    bool VisitFunctionDecl(FunctionDecl *Func) {
        if (Func->isThisDeclarationADefinition() && Context->getSourceManager().isInMainFile(Func->getLocation())) {
            std::cout << "Function " << Func->getNameInfo().getName().getAsString() << "\n";
            for (auto param : Func->parameters()) {
                std::cout << "\tParam: " << param->getNameAsString() << " of type " << param->getType().getAsString() << "\n";
            }
        }
        return true;
    }

private:
    ASTContext *Context;
};

class FunctionConsumer : public clang::ASTConsumer {
public:
    explicit FunctionConsumer(ASTContext *Context) : Visitor(Context) {}

    virtual void HandleTranslationUnit(clang::ASTContext &Context) {
        Visitor.TraverseDecl(Context.getTranslationUnitDecl());
    }

private:
    FunctionVisitor Visitor;
};

class FunctionAction : public clang::ASTFrontendAction {
public:
    virtual std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(clang::CompilerInstance &Compiler, llvm::StringRef InFile) {
        return std::unique_ptr<clang::ASTConsumer>(new FunctionConsumer(&Compiler.getASTContext()));
    }
};

static llvm::cl::OptionCategory ToolingSampleCategory("Function Extractor");

int main(int argc, const char **argv) {
    auto ExpectedParser = CommonOptionsParser::create(argc, argv, ToolingSampleCategory);
    if (!ExpectedParser) {
        llvm::errs() << ExpectedParser.takeError();
        return 1;
    }
    CommonOptionsParser& op = ExpectedParser.get();

    ClangTool tool(op.getCompilations(), op.getSourcePathList());
    return tool.run(newFrontendActionFactory<FunctionAction>().get());
}
