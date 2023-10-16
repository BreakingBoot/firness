#include <iostream>
#include <set>
#include <string>
#include <regex>
#include <clang/AST/ASTConsumer.h>
#include "clang/AST/ParentMapContext.h"
#include <clang/AST/RecursiveASTVisitor.h>
#include <clang/Frontend/FrontendActions.h>
#include <clang/Frontend/CompilerInstance.h>
#include <clang/Tooling/CommonOptionsParser.h>
#include <clang/Tooling/Tooling.h>
#include <llvm/Support/CommandLine.h>
#include <clang/Basic/SourceManager.h>
#include <sstream>
#include "clang/AST/ASTContext.h"
#include "clang/AST/Decl.h"
#include "clang/AST/Type.h"
#include "clang/AST/TypeLoc.h"


#include "clang/Lex/Lexer.h"


using namespace clang;
using namespace clang::driver;
using namespace clang::tooling;

std::set<std::string> FunctionNames = {"SetVariable", "GetVariable", "CopyMem"}; // Replace with your target function names
std::map<VarDecl*, std::stack<Expr*>> VarAssignments;
std::map<CallExpr*, std::map<VarDecl*, std::stack<Expr*>>> CallExprMap;

class VarDeclVisitor : public RecursiveASTVisitor<VarDeclVisitor> {
public:
    explicit VarDeclVisitor(ASTContext *Context)
        : Context(Context) {}

    bool VisitVarDecl(VarDecl *VD)
    {
        // If the VarDecl has an initializer, store it; otherwise, store nullptr.
        VarAssignments[VD].push(VD->hasInit() ? VD->getInit() : nullptr);
        return true;
    }
    
    // 
    // Responsible for getting all Tracing the function definitions
    // 
    int DoesFunctionAssign(int Param, CallExpr *CE) {
        // Get the callee expression
        Expr *Callee = CE->getCallee()->IgnoreCasts();

        // Check if it's a member expression
        if (auto *MemExpr = dyn_cast<MemberExpr>(Callee)) {
            Expr *Base = MemExpr->getBase()->IgnoreCasts();
            
            if (auto *DeclRef = dyn_cast<DeclRefExpr>(Base)) {
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
                // Needed for EDK2 since they have multiple levels
                // e.g. typedef struct _EFI_PEI_READ_ONLY_VARIABLE2_PPI EFI_PEI_READ_ONLY_VARIABLE2_PPI;
                if (auto *ET = dyn_cast<ElaboratedType>(underlyingType)) {
                    underlyingType = ET->getNamedType().getTypePtr();
                }
                
                // Assuming it's a record type (like a struct or class)
                // Commonplace in EDK2
                if (auto *RTD = dyn_cast<RecordType>(underlyingType)) {
                    // Iterate over the members of the struct/class
                    for (auto Field : RTD->getDecl()->fields()) {
                        if (MemExpr->getMemberDecl()->getNameAsString() == Field->getNameAsString()) {
                            QualType FieldType = Field->getType();
                            if (auto *TDT = dyn_cast<TypedefType>(FieldType)) {
                                // Once the correct type has been determined then handle parsing it
                                // For IN/OUT declerations on the arguments 
                                TypedefNameDecl *TypedefNameDeclaration = TDT->getDecl();
                                if (auto *TypedefDeclaration = dyn_cast<TypedefDecl>(TypedefNameDeclaration)) {
                                    return HandleTypedefArgs(Param, TypedefDeclaration);
                                }
                            }
                        }
                    }
                }
            }
        } else if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(Callee)) {
            ValueDecl *VD = DRE->getDecl();
            QualType QT = VD->getType();

            // Check for function pointer calls
            if (const PointerType *PT = QT->getAs<PointerType>()) {
                QualType PointeeType = PT->getPointeeType();
                if (PointeeType->isFunctionType()) {
                    if (const TypedefType *TDT = PointeeType->getAs<TypedefType>()) {
                        TypedefNameDecl *TDN = TDT->getDecl();
                        llvm::outs() << "Found typedef: " << TDN->getName().str() << "\n";
                    } else {
                        llvm::outs() << "Function pointer call without typedef.\n";
                    }
                }
            } 
            // Check for direct function calls
            else if (QT->isFunctionType()) {
                // Currently just printing off the function definition
                if (FunctionDecl *Func = dyn_cast<FunctionDecl>(VD)) {
                    SourceRange FuncRange = Func->getSourceRange();

                    if (FuncRange.isValid()) { 
                        ASTContext &Ctx = Func->getASTContext();
                        SourceManager &SM = Ctx.getSourceManager();
                        const LangOptions &LangOpts = Ctx.getLangOpts();
                        CharSourceRange Range = CharSourceRange::getTokenRange(FuncRange);
                        std::string FuncText = Lexer::getSourceText(Range, SM, LangOpts).str();

                        return DetermineArgumentType(Param, FuncText);
                    }
                }
            }
        }
        return 1;
    }

    int DetermineArgumentType(int Param, std::string FuncText) {
        // Check for presence of "IN" and "OUT" qualifiers
        std::regex paramRegex(R"(\b(IN\s+OUT|OUT\s+IN|IN|OUT)\b\s+[\w_]+\s+\**\s*[\w_]+)");

        std::smatch match;
        size_t index = 0;

        std::string::const_iterator searchStart(FuncText.cbegin());
        while (std::regex_search(searchStart, FuncText.cend(), match, paramRegex)) {
            if (index == Param) {
                std::string qualifier = match[1].str();
                // Check the matched string
                if (qualifier == "IN") return 1;
                else if (qualifier == "IN OUT" || qualifier == "OUT IN") return 0;
                else if (qualifier == "OUT") return -1;
            }
            searchStart = match.suffix().first;
            index++;
        }

        // If nth parameter doesn't exist, return false by default
        return 1;
    }

    int HandleTypedefArgs(int Param, TypedefDecl *typedefDecl) {
        ASTContext &Ctx = typedefDecl->getASTContext();
        SourceManager &SM = Ctx.getSourceManager();
        const LangOptions &LangOpts = Ctx.getLangOpts();

        // Get the start and tentative end of the typedef
        SourceLocation StartLoc = typedefDecl->getBeginLoc();
        SourceLocation EndLoc = typedefDecl->getEndLoc();

        // Advance until we find the matching semi-colon or closing parenthesis
        while (true) {
            Token Tok;
            Lexer::getRawToken(EndLoc, Tok, SM, LangOpts);
            if (Tok.is(tok::semi)) {
                EndLoc = Tok.getEndLoc();
                break;
            }
            EndLoc = EndLoc.getLocWithOffset(1);
        }

        CharSourceRange Range = CharSourceRange::getTokenRange(SourceRange(StartLoc, EndLoc));
        std::string FuncText = Lexer::getSourceText(Range, SM, LangOpts).str();

        return DetermineArgumentType(Param, FuncText);
    }

    //
    // Get all CallExpr for when Variables are set inside functions
    //
    bool VisitCallExpr(CallExpr *CE) {
        for (unsigned i = 0; i < CE->getNumArgs(); ++i) {
            Expr *Arg = CE->getArg(i)->IgnoreCasts();
            if (UnaryOperator *UO = dyn_cast<UnaryOperator>(Arg)) {
                if (UO->getOpcode() == UO_AddrOf) {
                    if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(UO->getSubExpr())) {
                        if (VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
                            if (VarAssignments.find(VD) != VarAssignments.end()) {
                                int DoesAssign = DoesFunctionAssign(i, CE);
                                // Add the assignment if its an OUT variable,
                                if(DoesAssign <= 0)
                                {
                                    VarAssignments[VD].push(CE); // Store as unassigned
                                }
                            }
                        }
                    }
                }
            }
        }
        return true;
    }
    
    //
    // Get all of the direct assignments for different variables
    //
    bool VisitBinaryOperator(BinaryOperator *BO) {
        if (BO->isAssignmentOp()) {
            Expr *LHS = BO->getLHS()->IgnoreImpCasts();
            if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(LHS)) {
                if (VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
                    if (VarAssignments.find(VD) != VarAssignments.end()) {
                        VarAssignments[VD].push(BO->getRHS());
                    }
                }
            }
        }
        return true;
    }

private:
    ASTContext *Context;
};

class FindNamedFunctionVisitor : public RecursiveASTVisitor<FindNamedFunctionVisitor> {
public:
    explicit FindNamedFunctionVisitor(ASTContext *Context)
        : Context(Context) {}

    void PrintFunctionCall(Expr *E, ASTContext &Ctx)
    {
        if (!E) return;
        SourceManager &SM = Ctx.getSourceManager();
        const LangOptions &LangOpts = Ctx.getLangOpts();
        CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
        std::string ExprText = Lexer::getSourceText(Range, SM, LangOpts).str();

        llvm::outs() << E->getStmtClassName() << ": " << ExprText << "\n";
    }

    
    void HandleMatchingExpr(Stmt *S, ASTContext &Ctx)
    {
        if (!S) return;

        for (Stmt *child : S->children()) {
            if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(child)) {
                if(VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
                    // From here, VD represents the declaration of 'Variable'.
                    // You can then extract any needed information from VD.
                    VarDeclMap[VD] = VarAssignments[VD];
                }
            }
            else if (StringLiteral *SL = dyn_cast<StringLiteral>(child)) {
                // For simplicity, I am assuming a fictional 'Var' representing the variable where the string literal might be stored.
                // You would typically associate a StringLiteral to a specific VarDecl based on context.
                VarDecl *Var = createPlaceholderVarDecl(Ctx, SL); 
                VarDeclMap[Var].push(SL);
            } 
            else if (IntegerLiteral *IL = dyn_cast<IntegerLiteral>(child)) {
                // For simplicity, I am assuming a fictional 'Var' representing the variable where the integer literal might be stored.
                // You would typically associate an IntegerLiteral to a specific VarDecl based on context.
                VarDecl *Var = createPlaceholderVarDecl(Ctx, IL); 
                VarDeclMap[Var].push(IL);
            } 
            else
            {
                HandleMatchingExpr(child, Ctx);
            }
        }
        
    }

    VarDecl* createPlaceholderVarDecl(ASTContext &Ctx, Stmt *literal) {
        // Get a unique name for the placeholder VarDecl
        // Note: This is just an example naming convention.
        std::string name = "placeholder_";
        QualType type;

        if (isa<StringLiteral>(literal)) {
            name += "string";
            type = Ctx.getPointerType(Ctx.getWCharType());  // Assuming it's a wide string
        } else if (isa<IntegerLiteral>(literal)) {
            name += "int";
            type = Ctx.IntTy;
        } else {
            return nullptr;  // Unsupported literal type
        }

        // Create the VarDecl with the computed name and type
        return VarDecl::Create(Ctx, Ctx.getTranslationUnitDecl(), 
                            SourceLocation(), SourceLocation(), 
                            &Ctx.Idents.get(name), type, 
                            Ctx.getTrivialTypeSourceInfo(type), 
                            SC_None);
    }

    bool doesCallMatch(Expr *E, ASTContext &Ctx) {
        if (!E) return false;
        bool found = false;

        // Check for direct function calls
        if (DeclRefExpr* DRE = dyn_cast<DeclRefExpr>(E)) {
            if (FunctionDecl* FD = dyn_cast<FunctionDecl>(DRE->getDecl())) {
                if (FunctionNames.count(FD->getNameAsString())) {
                    return true;
                }
            }
        }
        else if (MemberExpr* MemExpr = dyn_cast<MemberExpr>(E)) {
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
            VarDeclMap.clear();
            HandleMatchingExpr(Call, *this->Context);
            CallExprMap[Call] = VarDeclMap;
        }
        return true;
    }


private:
    ASTContext *Context;
    std::map<VarDecl*, std::stack<Expr*>> VarDeclMap;
};

class FindNamedFunctionConsumer : public clang::ASTConsumer {
public:
    explicit FindNamedFunctionConsumer(ASTContext *Context)
        : VarVisitor(Context), FunctionVisitor(Context) {}

    void HandleTranslationUnit(clang::ASTContext &Context) override {
        VarVisitor.TraverseDecl(Context.getTranslationUnitDecl());
        FunctionVisitor.TraverseDecl(Context.getTranslationUnitDecl());
    }
private:
    VarDeclVisitor VarVisitor;
    FindNamedFunctionVisitor FunctionVisitor;
};

class FindNamedFunctionAction : public clang::ASTFrontendAction {
private:
    clang::SourceManager* SM = nullptr;

public:
    std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
        clang::CompilerInstance &Compiler, llvm::StringRef InFile) override {
        SM = &Compiler.getSourceManager();
        return std::unique_ptr<clang::ASTConsumer>(
            new FindNamedFunctionConsumer(&Compiler.getASTContext()));
    }

    clang::SourceManager& getSourceManager() {
        assert(SM && "SourceManager is not initialized!");
        return *SM;
    }
};


std::string getSourceCode(Expr *E, SourceManager &SM) {
    SourceRange range = E->getSourceRange();

    if (!E) {
        llvm::outs() << "E is nullptr!\n";
        return "";
    }
    
    // Adjust the range if tokens are expanded from a macro
    // if (range.getBegin().isMacroID())
    //     range.setBegin(SM.getExpansionRange(range.getBegin()).getBegin());
    // if (range.getEnd().isMacroID())
    //     range.setEnd(SM.getExpansionRange(range.getEnd()).getEnd());
    
    const char* beginData = SM.getCharacterData(range.getBegin());
    const char* endData = SM.getCharacterData(range.getEnd());
    if (endData < beginData) {
        llvm::outs() << "Invalid range!\n";
        return "";
    }
    if(!beginData || !endData) {
        // handle error or return an empty string
        return "";
    }
    llvm::outs() << std::string(beginData, endData + 1);
    std::string code = std::string(beginData, endData + 1);

    
    return code;
}

void printCallExprMap(SourceManager &SM) {
    for (auto &callEntry : CallExprMap) {
        llvm::outs() << "CallExpr: " << callEntry.first->getStmtClassName() << "\n";
        
        for (auto &varEntry : callEntry.second) {
            llvm::outs() << "\tVarDecl: " << varEntry.first->getNameAsString() << "\n";

            std::stack<clang::Expr*> &exprStack = varEntry.second;
            std::stack<clang::Expr*> tempStack = exprStack;  // Copy of the stack to iterate through
            while ((tempStack.size()-1) > 0) {
                clang::Expr *expr = tempStack.top();
                llvm::outs() << "\t\tExpr: " << expr->getExprStmt() << "\n";
                tempStack.pop();
            }
        }
    }
}

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

    FindNamedFunctionAction Action;
    Tool.run(newFrontendActionFactory<FindNamedFunctionAction>().get());
    printCallExprMap(Action.getSourceManager());
    return 0;
}
