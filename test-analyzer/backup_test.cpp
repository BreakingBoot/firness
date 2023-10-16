#include <iostream>
#include <set>
#include <string>
#include <clang/AST/ASTConsumer.h>
#include "clang/AST/ParentMapContext.h"
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Tooling/CommonOptionsParser.h>
#include <clang/Tooling/Tooling.h>
#include <llvm/Support/CommandLine.h>
#include <sstream>

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


    void PrintFunctionCall(Expr *E, ASTContext &Ctx)
    {
        if (!E) return;
        SourceManager &SM = Ctx.getSourceManager();
        const LangOptions &LangOpts = Ctx.getLangOpts();
        CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
        std::string ExprText = Lexer::getSourceText(Range, SM, LangOpts).str();

        llvm::outs() << E->getStmtClassName() << ": " << ExprText << "\n";
    }


    Stmt *getEnclosingFunctionBody(const Stmt *S, ASTContext &Ctx) {
        const auto &Parents = Ctx.getParents(*S);
        if (Parents.empty()) return nullptr;

        const auto &Parent = Parents[0];
        if (const Stmt *ParentStmt = Parent.get<Stmt>()) {
            return getEnclosingFunctionBody(ParentStmt, Ctx);
        } else if (const auto *FD = Parent.get<FunctionDecl>()) {
            return FD->getBody();
        } else if (const auto *MD = Parent.get<CXXMethodDecl>()) {
            return MD->getBody();
        }

        return nullptr;
    }


    // bool traceVariableAssignment(VarDecl *VD, Stmt *StartingPoint, ASTContext &Ctx) {
    //     if (!VD || !StartingPoint) return false;

    //     for (Stmt *child : StartingPoint->children()) {
    //         if (auto *Call = dyn_cast<CallExpr>(child)) {
    //             for (unsigned i = 0; i < Call->getNumArgs(); ++i) {
    //                 Expr *Arg = Call->getArg(i)->IgnoreCasts();
    //                 if (UnaryOperator *UO = dyn_cast<UnaryOperator>(Arg)) {
    //                     if (UO->getOpcode() == UO_AddrOf) {
    //                         if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(UO->getSubExpr())) {
    //                             if (DRE->getDecl() == VD) {
    //                                 // Found a function call where the variable's address is taken
    //                                 PrintFoundFunction(Call, Ctx);
    //                                 return true;
    //                             }
    //                         }
    //                     }
    //                 }
    //             }
    //         }
    //         // Recursive tracing
    //         if (traceVariableAssignment(VD, child, Ctx)) {
    //             return true;
    //         }
    //     }
    //     return false;
    // }
    bool traceVariableAssignment(VarDecl *VD, Stmt *StartingPoint, ASTContext &Ctx) {
        if (!VD || !StartingPoint) return false;

        for (Stmt *child : StartingPoint->children()) {
            if (auto *Call = dyn_cast<CallExpr>(child)) {
                for (unsigned i = 0; i < Call->getNumArgs(); ++i) {
                    Expr *Arg = Call->getArg(i)->IgnoreCasts();
                    if (UnaryOperator *UO = dyn_cast<UnaryOperator>(Arg)) {
                        if (UO->getOpcode() == UO_AddrOf) {
                            if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(UO->getSubExpr())) {
                                if (DRE->getDecl() == VD) {
                                    // Found a function call where the variable's address is taken
                                    PrintFunctionCall(Call, Ctx);
                                    return true;
                                }
                            }
                        }
                    }
                }
            } 
            else if (auto *BinOp = dyn_cast<BinaryOperator>(child)) {
                if (BinOp->getOpcode() == BO_Assign) {
                    Expr *LHS = BinOp->getLHS()->IgnoreImpCasts();
                    if (auto *DRE = dyn_cast<DeclRefExpr>(LHS)) {
                        if (DRE->getDecl() == VD) {
                            // Found an assignment to the variable
                            llvm::outs() << "Found assignment: ";
                            BinOp->printPretty(llvm::outs(), nullptr, PrintingPolicy(Ctx.getLangOpts()));
                            llvm::outs() << "\n";
                            return true;
                        }
                    }
                }
            }

            // Recursive tracing
            if (traceVariableAssignment(VD, child, Ctx)) {
                return true;
            }
        }
        return false;
    }

    void HandleMatchingExpr(Stmt *S, ASTContext &Ctx)
    {
        if (!S) return;
        if (auto *Call = dyn_cast<CallExpr>(S)) {
            // Get the callee expression
            Expr *callee = Call->getCallee()->IgnoreCasts();
            
            // Check if it's a member expression
            if (auto *MemExpr = dyn_cast<MemberExpr>(callee)) {
                // Get the base of the member expression
                Expr *Base = MemExpr->getBase()->IgnoreCasts();
                
                if (auto *DeclRef = dyn_cast<DeclRefExpr>(Base)) {
                    // Get the declaration of Variable
                    ValueDecl *VD = DeclRef->getDecl();
                    
                    // Get the type of VD and strip away any typedefs
                    QualType QT = VD->getType();
                    if (QT->isPointerType()) {
                        QT = QT->getPointeeType();
                    }

                    // Strip away any typedefs
                    while (auto *TDT = dyn_cast<TypedefType>(QT)) {
                        QT = TDT->getDecl()->getUnderlyingType();
                    }
                    const Type *underlyingType = QT.getTypePtr();

                    // If it's an elaborated type, drill down further
                    if (auto *ET = dyn_cast<ElaboratedType>(underlyingType)) {
                        underlyingType = ET->getNamedType().getTypePtr();
                    }
                    // Assuming it's a record type (like a struct or class)
                    if (auto *RTD = dyn_cast<RecordType>(underlyingType)) {
                        // Iterate over the members of the struct/class
                        for (auto Field : RTD->getDecl()->fields()) {
                            if (FunctionNames.count(Field->getNameAsString())) {
                                QualType FieldType = Field->getType();

                                if (const TypedefType *TDT = dyn_cast<TypedefType>(FieldType)) {
                                    TypedefNameDecl *TypedefDecl = TDT->getDecl();
                                    SourceManager &SM = Ctx.getSourceManager();
                                    LangOptions LO;  // Typically, you'd fetch this from context, but for token length it might not matter
                                    CharSourceRange Range = CharSourceRange::getTokenRange(TypedefDecl->getSourceRange());
                                    std::string ExprText = Lexer::getSourceText(Range, SM, LO).str();
                                    
                                    llvm::outs() << ExprText << "\n";

                                }

                            }
                        }
                    }
                }
            }
        }


        for (Stmt *child : S->children()) {
            // std::string stmtStr;
            // llvm::raw_string_ostream os(stmtStr);
            // child->printPretty(os, nullptr, PrintingPolicy(Ctx.getLangOpts()));
            // llvm::outs() << os.str() << "\n";
            // if (MemberExpr* MemExpr = dyn_cast<MemberExpr>(child)) {
            //     // If the Function Pointer Called matches the one we are looking for
            //     Expr *Base = MemExpr->getBase();

            //     // Strip away any implicit casts to get to the real expression.
            //     Base = Base->IgnoreImpCasts();
            //     if (auto *DeclRef = dyn_cast<DeclRefExpr>(Base)) {
            //         // Get the declaration
            //         if(VarDecl *VD = dyn_cast<VarDecl>(DeclRef->getDecl())) {
            //             // From here, VD represents the declaration of 'Variable'.
            //             // You can then extract any needed information from VD.
            //             traceVariableAssignment(VD, getEnclosingFunctionBody(S, Ctx), Ctx);
            //         }
            //     }
            // }
            // else 
            if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(child)) {
                if(VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
                    // From here, VD represents the declaration of 'Variable'.
                    // You can then extract any needed information from VD.
                    llvm::outs() << VD->getNameAsString() << "\n";
                    traceVariableAssignment(VD, getEnclosingFunctionBody(S, Ctx), Ctx);
                    llvm::outs() << "\n";
                }
            }
            else
            {
                HandleMatchingExpr(child, Ctx);
            }
        }
        
    }

    bool doesCallMatch(Expr *E, ASTContext &Ctx) {
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
                if(doesCallMatch(childExpr, Ctx))
                {
                    found = true;
                    break;
                }
            }
        }
        return found;
    }

    bool VisitCallExpr(CallExpr *Call) {
        if(doesCallMatch(Call, *this->Context))
        {
            PrintFunctionCall(Call, *this->Context);
            HandleMatchingExpr(Call, *this->Context);
        }
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
