#include <iostream>
#include <fstream>
#include <algorithm>
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
#include <nlohmann/json.hpp>

#include "clang/Lex/Lexer.h"


using namespace clang;
using namespace clang::driver;
using namespace clang::tooling;

enum class ParameterDirection {
    IN,
    OUT,
    IN_OUT,
    UNKNOWN,
    DIRECT
};

std::set<std::string> FunctionNames = {"SetVariable", "GetVariable", "CopyMem"}; // Replace with your target function names
std::map<VarDecl*, std::stack<std::pair<Expr*, ParameterDirection>>> VarAssignments;
std::map<CallExpr*, std::map<VarDecl*, std::pair<Expr*, ParameterDirection>>> CallExprMap;
std::map<std::string, std::map<std::string, std::string>> CallMap;

class VarDeclVisitor : public RecursiveASTVisitor<VarDeclVisitor> {
public:
    explicit VarDeclVisitor(ASTContext *Context)
        : Context(Context) {}

    bool VisitVarDecl(VarDecl *VD)
    {
        // If the VarDecl has an initializer, store it; otherwise, store nullptr.
        VarAssignments[VD].push(std::make_pair((VD->hasInit() ? VD->getInit() : nullptr), ParameterDirection::UNKNOWN));
        return true;
    }
    
    // 
    // Responsible for getting all Tracing the function definitions
    // 
    ParameterDirection DoesFunctionAssign(int Param, CallExpr *CE) {
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
        return ParameterDirection::UNKNOWN;
    }

    ParameterDirection DetermineArgumentType(int Param, std::string FuncText) {
        // Check for presence of "IN" and "OUT" qualifiers
        std::regex paramRegex(R"(\b(IN\s+OUT|OUT\s+IN|IN|OUT)\b\s+[\w_]+\s+\**\s*[\w_]+)");

        std::smatch match;
        int index = 0;

        std::string::const_iterator searchStart(FuncText.cbegin());
        while (std::regex_search(searchStart, FuncText.cend(), match, paramRegex)) {
            if (index == Param) {
                std::string qualifier = match[1].str();
                // Check the matched string
                if (qualifier == "IN") return ParameterDirection::IN;
                else if (qualifier == "IN OUT" || qualifier == "OUT IN") return ParameterDirection::IN_OUT;
                else if (qualifier == "OUT") return ParameterDirection::OUT;
            }
            searchStart = match.suffix().first;
            index++;
        }

        // If nth parameter doesn't exist, return false by default
        return ParameterDirection::UNKNOWN;
    }

    ParameterDirection HandleTypedefArgs(int Param, TypedefDecl *typedefDecl) {
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
                                VarAssignments[VD].push(std::make_pair(CE, DoesFunctionAssign(i, CE))); 
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
                        VarAssignments[VD].push(std::make_pair(BO->getRHS(), ParameterDirection::DIRECT));
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

    
    void HandleMatchingExpr(Stmt *S, ASTContext &Ctx, Expr* CurrentExpr)
    {
        if (!S) return;

        for (Stmt *child : S->children()) {
            if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(child)) {
                if(VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
                    // From here, VD represents the declaration of 'Variable'.
                    // You can then extract any needed information from VD.
                    // If the top Expr in the stack of VarAssignments[VD]
                    // is the same as the current CallExpr then get the second one
                    if(VarAssignments[VD].top().first == CurrentExpr)
                        VarAssignments[VD].pop();
                    VarDeclMap[VD] = VarAssignments[VD].top();
                }
            }
            else if (StringLiteral *SL = dyn_cast<StringLiteral>(child)) {
                // For simplicity, I am assuming a fictional 'Var' representing the variable where the string literal might be stored.
                // You would typically associate a StringLiteral to a specific VarDecl based on context.
                VarDecl *Var = createPlaceholderVarDecl(Ctx, SL); 
                VarDeclMap[Var] = std::make_pair(SL, ParameterDirection::DIRECT);
            } 
            else if (IntegerLiteral *IL = dyn_cast<IntegerLiteral>(child)) {
                // For simplicity, I am assuming a fictional 'Var' representing the variable where the integer literal might be stored.
                // You would typically associate an IntegerLiteral to a specific VarDecl based on context.
                VarDecl *Var = createPlaceholderVarDecl(Ctx, IL); 
                VarDeclMap[Var] = std::make_pair(IL, ParameterDirection::DIRECT);
            } 
            else
            {
                HandleMatchingExpr(child, Ctx, CurrentExpr);
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

    std::string getSourceCode(Expr *E)
    {
        if (!E) return "";
        SourceManager &SM = Context->getSourceManager();
        const LangOptions &LangOpts = Context->getLangOpts();
        CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
        std::string ExprText = Lexer::getSourceText(Range, SM, LangOpts).str();

        return ExprText;
    }

    std::string reduceWhitespace(const std::string& str) {
        // Replace all sequences of whitespace with a single space
        std::string result = std::regex_replace(str, std::regex("\\s+"), " ");

        // Trim leading and trailing spaces if desired
        if (!result.empty() && result[0] == ' ') {
            result.erase(result.begin());
        }
        if (!result.empty() && result[result.size() - 1] == ' ') {
            result.erase(result.end() - 1);
        }

        return result;
    }

    std::map<std::string, std::string> GetVarDeclMap(std::map<VarDecl*, std::pair<Expr*, ParameterDirection>> OriginalMap)
    {
        std::map<std::string, std::string> ConvertedMap;

        for(auto& pair : OriginalMap)
        {
            VarDecl* VD = pair.first;

            std::pair<Expr*, ParameterDirection> ExprPair = pair.second;
            ConvertedMap[VD->getNameAsString()] = reduceWhitespace(getSourceCode(ExprPair.first));;
        }
        return ConvertedMap;
    }

    bool AddToSourceCodeMap(Expr* EX)
    {
        if (!EX) return false;
        bool found = false;

        // Get the function Call as a String
        std::string CallExprString;
        if (DeclRefExpr* DRE = dyn_cast<DeclRefExpr>(EX)) {
            if (FunctionDecl* FD = dyn_cast<FunctionDecl>(DRE->getDecl())) {
                CallExprString = FD->getNameAsString();
                CallMap[CallExprString] = GetVarDeclMap(VarDeclMap);
                return true;
            }
        }
        else if (MemberExpr* MemExpr = dyn_cast<MemberExpr>(EX)) {
            CallExprString = MemExpr->getMemberNameInfo().getName().getAsString();
            CallMap[CallExprString] = GetVarDeclMap(VarDeclMap);
            return true;
        }
        for (Stmt *child : EX->children()) {
            if (Expr *childExpr = dyn_cast<Expr>(child)) {
                if(AddToSourceCodeMap(childExpr))
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
            HandleMatchingExpr(Call, *this->Context, Call);
            CallExprMap[Call] = VarDeclMap;
            AddToSourceCodeMap(Call);
        }
        return true;
    }


private:
    ASTContext *Context;
    std::map<VarDecl*, std::pair<Expr*, ParameterDirection>> VarDeclMap;
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
public:
    std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
        clang::CompilerInstance &Compiler, llvm::StringRef InFile) override {
        return std::unique_ptr<clang::ASTConsumer>(
            new FindNamedFunctionConsumer(&Compiler.getASTContext()));
    }
};


void printCallMap(const std::map<std::string, std::map<std::string, std::string>> &calls) {
    for (const auto &callEntry : calls) {
        llvm::outs() << "Caller: " << callEntry.first << "\n";
        
        for (const auto &varEntry : callEntry.second) {
            llvm::outs() << "\tCallee: " << varEntry.first << "\n";

            std::string var = varEntry.second;  // Copy of the stack to iterate through
            llvm::outs() << "\t\tExpr: " << var << "\n";
        }
    }
}


std::set<std::string> readAndProcessFile(const std::string& filename) {
    std::set<std::string> lines;
    std::ifstream file(filename);

    if (!file.is_open()) {
        std::cerr << "Error opening file: " << filename << std::endl;
        exit(1);
    }
    FunctionNames.clear();
    std::string line;
    while (std::getline(file, line)) {
        // Remove leading and trailing whitespace
        line.erase(line.begin(), std::find_if(line.begin(), line.end(), [](int ch) { return !std::isspace(ch); }));
        line.erase(std::find_if(line.rbegin(), line.rend(), [](int ch) { return !std::isspace(ch); }).base(), line.end());

        // Remove extra whitespace between words
        line = std::regex_replace(line, std::regex("\\s+"), " ");

        if (!line.empty()) {
            lines.insert(line);
        }
    }

    file.close();
    return lines;
}

// int main(int argc, const char **argv) {
//     llvm::cl::OptionCategory ToolingSampleCategory("Tooling Sample");
//     Expected<CommonOptionsParser> ExpectedParser = CommonOptionsParser::create(argc, argv, ToolingSampleCategory);
//     if (!ExpectedParser) {
//         llvm::errs() << ExpectedParser.takeError();
//         return 1;
//     }
//     CommonOptionsParser &OptionsParser = ExpectedParser.get();

//     ClangTool Tool(OptionsParser.getCompilations(),
//                    OptionsParser.getSourcePathList());

//     FindNamedFunctionAction Action;
//     Tool.run(newFrontendActionFactory<FindNamedFunctionAction>().get());
//     printCallExprMap(Action.getSourceManager());
//     return 0;
// }

void outputCallExprMapToJSON(std::string filename) {
    nlohmann::json jsonOutput;

    for (const auto& outerMapEntry : CallMap) {
        // Create a JSON object for the outer map entry
        nlohmann::json outerObject;
        std::string outerKey = outerMapEntry.first;
        const std::map<std::string, std::string>& innerMap = outerMapEntry.second;

        for (const auto& innerMapEntry : innerMap) {
            // Create a JSON array for the inner map entry
            //nlohmann::json innerArray;
            std::string innerKey = innerMapEntry.first;
            std::string temp = innerMapEntry.second; // Copying the stack to temp to pop without modifying the original
            //innerArray.push_back(tempStack.top());

            outerObject[innerKey] = temp;
        }

        jsonOutput[outerKey] = outerObject;
    }

    // Write the JSON object to a file
    std::ofstream outFile(filename);
    outFile << jsonOutput.dump(4); // Indent the JSON output for readability
    outFile.close();
}


// Define command-line options for filename and source code
static llvm::cl::opt<std::string> InputFileName(
    "f", llvm::cl::desc("Specify the input filename"), llvm::cl::value_desc("filename"));

static llvm::cl::opt<std::string> OutputFileName(
    "o", llvm::cl::desc("Specify the output filename"), llvm::cl::value_desc("filename"));

static llvm::cl::opt<std::string> SourceCode(
    "s", llvm::cl::desc("Specify the source code"), llvm::cl::value_desc("source_code"));


int main(int argc, const char **argv) {
    llvm::cl::OptionCategory ToolingSampleCategory("Tooling Sample");
    Expected<CommonOptionsParser> ExpectedParser = CommonOptionsParser::create(argc, argv, ToolingSampleCategory);
    if (!ExpectedParser) {
        llvm::errs() << ExpectedParser.takeError();
        return 1;
    }

    CommonOptionsParser &OptionsParser = ExpectedParser.get();

    // Get the filename and source code from command-line options
    std::string input_filename = InputFileName.getValue();
    std::string output_filename = OutputFileName.getValue();
    llvm::outs() << "Input file: " << input_filename << "\n";
    llvm::outs() << "Output file: " << output_filename << "\n";

    // Use the filename to create a ClangTool instance
    ClangTool Tool(OptionsParser.getCompilations(), OptionsParser.getSourcePathList());
    if(!input_filename.empty())
        readAndProcessFile(input_filename);

    Tool.run(newFrontendActionFactory<FindNamedFunctionAction>().get());
    printCallMap(CallMap);
    if(!output_filename.empty())
        outputCallExprMapToJSON(output_filename);

    return 0;
}

// static llvm::cl::opt<std::string> CompilationDatabasePath(
//     "p", llvm::cl::desc("Specify the compilation database path"), llvm::cl::value_desc("path"));

// int main(int argc, const char **argv) {
//     llvm::cl::OptionCategory ToolingSampleCategory("Tooling Sample");
//     Expected<CommonOptionsParser> ExpectedParser = CommonOptionsParser::create(argc, argv, ToolingSampleCategory);
//     if (!ExpectedParser) {
//         llvm::errs() << ExpectedParser.takeError();
//         return 1;
//     }

//     CommonOptionsParser &OptionsParser = ExpectedParser.get();

//     // Get the compilation database path from the command-line option
//     std::string compilationDatabasePath = CompilationDatabasePath.getValue();

//     // Create a ClangTool instance with the compilation database
//     ClangTool Tool(CompilationDatabase::loadFromDirectory(compilationDatabasePath, OptionsParser.getCompilations()));

//     FindNamedFunctionAction Action;
//     Tool.runToolOnCode(newFrontendActionFactory<FindNamedFunctionAction>().get());

//     // Analyze each file in the compilation database
//     for (const auto &file : Tool.getFiles()) {
//         Tool.run(newFrontendActionFactory<FindNamedFunctionAction>().get(), file);
//         printCallExprMap(Action.getSourceManager());
//     }

//     return 0;
// }





