#include <iostream>
#include <set>
#include <string>
#include <clang/AST/ASTConsumer.h>
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Tooling/CommonOptionsParser.h>
#include <clang/Tooling/Tooling.h>
#include <llvm/Support/CommandLine.h>
#include "clang/Lex/Lexer.h"


using namespace clang;
using namespace clang::driver;
using namespace clang::tooling;

std::set<std::string> FunctionNames = {"SetVariable", "GetVariable", "CopyMem"}; // Replace with your target function names

class FindNamedFunctionVisitor : public RecursiveASTVisitor<FindNamedFunctionVisitor> {
public:
    explicit FindNamedFunctionVisitor(ASTContext *Context)
        : Context(Context) {}

    bool VisitFunctionDecl(FunctionDecl *Func) {
        if (FunctionNames.count(Func->getNameInfo().getName().getAsString())) {
            llvm::outs() << "Function definition found: " << Func->getNameInfo().getName().getAsString() << "\n";

            SourceRange FuncRange = Func->getSourceRange();

            if (FuncRange.isValid()) { 
                ASTContext &Ctx = Func->getASTContext();
                SourceManager &SM = Ctx.getSourceManager();
                const LangOptions &LangOpts = Ctx.getLangOpts();
                CharSourceRange Range = CharSourceRange::getTokenRange(FuncRange);
                std::string FuncText = Lexer::getSourceText(Range, SM, LangOpts).str();

                llvm::outs() << "Function definition:\n" << FuncText << "\n";
            }
        }
        return true;
    }


    void PrintFoundFunction(Expr *E, ASTContext &Ctx)
    {
        if (!E) return;
        SourceManager &SM = Ctx.getSourceManager();
        const LangOptions &LangOpts = Ctx.getLangOpts();
        CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
        std::string ExprText = Lexer::getSourceText(Range, SM, LangOpts).str();

        llvm::outs() << E->getStmtClassName() << ": " << ExprText << "\n";
    }


    bool PrintExprAndSubExprs(Expr *E, ASTContext &Ctx) {
        if (!E) return false;
        bool found = false;
        if (MemberExpr* MemExpr = dyn_cast<MemberExpr>(E)) {
            // If the Function Pointer Called matches the one we are looking for
            if (FunctionNames.count(MemExpr->getMemberNameInfo().getName().getAsString())) {
                return true;
            }
        }

        for (Stmt *child : E->children()) {
            if (Expr *childExpr = dyn_cast<Expr>(child)) {
                if(PrintExprAndSubExprs(childExpr, Ctx))
                {
                    found = true;
                    break;
                }
            }
        }
        return found;
    }

    bool VisitCallExpr(CallExpr *Call) {
        if(PrintExprAndSubExprs(Call, *this->Context))
            PrintFoundFunction(Call, *this->Context);
        return true;
    }


private:
    ASTContext *Context;
};

class FindNamedFunctionConsumer : public clang::ASTConsumer {
public:
    explicit FindNamedFunctionConsumer(ASTContext *Context)
        : Visitor(Context) {}

    void HandleTranslationUnit(clang::ASTContext &Context) override {
        Visitor.TraverseDecl(Context.getTranslationUnitDecl());
    }
private:
    FindNamedFunctionVisitor Visitor;
};

class FindNamedFunctionAction : public clang::ASTFrontendAction {
public:
    std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
        clang::CompilerInstance &Compiler, llvm::StringRef InFile) override {
        return std::unique_ptr<clang::ASTConsumer>(
            new FindNamedFunctionConsumer(&Compiler.getASTContext()));
    }
};

int main(int argc, const char **argv) {
    llvm::cl::OptionCategory ToolingSampleCategory("Tooling Sample");
    Expected<CommonOptionsParser> ExpectedParser = CommonOptionsParser::create(argc, argv, ToolingSampleCategory);
    if (!ExpectedParser) {
        llvm::errs() << ExpectedParser.takeError();
        return 1;
    }
    CommonOptionsParser &OptionsParser = ExpectedParser.get();

    ClangTool Tool(OptionsParser.getCompilations(),
                   OptionsParser.getSourcePathList());

    return Tool.run(newFrontendActionFactory<FindNamedFunctionAction>().get());
}
