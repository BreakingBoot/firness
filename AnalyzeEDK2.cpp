#include "clang/AST/AST.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Driver/Options.h"
#include "clang/Frontend/ASTConsumers.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "clang/AST/ParentMap.h"
#include "clang/AST/ExprCXX.h"
#include <nlohmann/json.hpp>
#include <fstream>
#include <algorithm>
#include <filesystem>
#include <string>
#include <cctype>
#include<bits/stdc++.h>

namespace fs = std::filesystem;
using namespace clang;
using namespace clang::tooling;

struct Parameter
{
    std::string Variable;
    std::string Type;
    std::string Identifier;
    std::string Fuzzable;
    std::string CallValue;
    bool empty() const{
        return Variable.empty() && Type.empty() && Identifier.empty() && Fuzzable.empty() && CallValue.empty();
    }
    int filled() const{
        int number = 0;
        if (!Variable.empty())
            number++;
        if (!Type.empty())
            number++;
        if (!Identifier.empty())
            number++;
        if (!Fuzzable.empty())
            number++;
        if (!CallValue.empty())
            number++;
        return number;
    }
};

struct Service
{
    std::string Service;
    std::string ServiceType;
    std::string ServiceGUID;
    std::string ServiceDefName;
    std::vector<Parameter> Parameters;

    int get_score() const{
        int score = 0;
        for (Parameter p: Parameters)
        {
            score += p.filled();
        }
        return score;
    }
};

void to_json(nlohmann::json &j, const Parameter &p)
{
    j = nlohmann::json{{"Variable", p.Variable}, {"Type", p.Type}, {"Identifier", p.Identifier}, {"Fuzzable", p.Fuzzable}, {"CallValue", p.CallValue}};
}

void to_json(nlohmann::json &j, const Service &s)
{
    j = nlohmann::json{{"Service", s.Service}, {"ServiceType", s.ServiceType}, {"ServiceGUID", s.ServiceGUID}, {"ServiceDefName", s.ServiceDefName}, {"Parameters", s.Parameters}};
}

class FirmwareVisitor : public RecursiveASTVisitor<FirmwareVisitor>
{
public:
    explicit FirmwareVisitor(ASTContext *Context, std::set<std::string> input)
        : Context(Context), services(input) {}

    const auto &getResults() const { return results; }


    bool VisitImplicitCastExpr(ImplicitCastExpr *castExpr)
    {
        if(foundCallExpr)
        {
            Expr *childNode = castExpr->getSubExpr();

            if(castExpr->getCastKind() == clang::CK_FunctionToPointerDecay)
            {
                isFunctionPointer = true;
            }
            if(foundFunction)
            {
                if (castExpr->getCastKind() == clang::CK_NullToPointer)
                {
                    //currentParameter.Type = castExpr->getType().getAsString();
                    (currentService.Parameters)[paramCount].CallValue = "NULL";
                    foundParam = true;
                    return true;
                }
                else if (childNode) {
                    if (clang::isa<clang::IntegerLiteral>(childNode) || clang::isa<clang::FloatingLiteral>(childNode) || clang::isa<clang::StringLiteral>(childNode)) 
                    {
                        if (clang::isa<clang::IntegerLiteral>(childNode)) {
                            auto literal = clang::cast<clang::IntegerLiteral>(childNode);
                            // if(auto expr = llvm::dyn_cast<clang::Expr>(childNode)) ASTContext{
                            //     currentParameter.Type = expr->getType().getAsString();
                            // }
                            //literal->getValue().toString(currentParameter.CallValue, 10, true);
                            llvm::errs() << "Type: IntegerLiteral, Value: " << literal->getValue() << "\n";
                            foundParam = true;
                        } 
                        else if (clang::isa<clang::FloatingLiteral>(childNode)) {
                            auto literal = clang::cast<clang::FloatingLiteral>(childNode);
                            // if(auto expr = llvm::dyn_cast<clang::Expr>(childNode)) {
                            //     currentParameter.Type = expr->getType().getAsString();
                            // }
                            (currentService.Parameters)[paramCount].CallValue = llvm::APFloat(literal->getValue()).convertToDouble();
                            foundParam = true;
                        } 
                        else if (clang::isa<clang::StringLiteral>(childNode)) {
                            auto literal = clang::cast<clang::StringLiteral>(childNode);
                            // if(auto expr = llvm::dyn_cast<clang::Expr>(childNode)) {
                            //     currentParameter.Type = expr->getType().getAsString();
                            // }
                            std::string str = literal->getString().str();
                            str.erase(std::remove(str.begin(), str.end(), '\0'), str.end());
                            (currentService.Parameters)[paramCount].CallValue = str;
                            foundParam = true;
                        }
                        return true;
                    }
                }
            }

            // Traverse into the child expression
            //TraverseStmt(childNode);
        }
        return true; // Continue traversal
    }

    bool VisitMemberExpr(MemberExpr *memberExpr)
    {
        if(foundCallExpr)
        {
            // Get the member declaration
            ValueDecl *memberDecl = memberExpr->getMemberDecl();
            if(!foundFunction)
            {
                auto it = std::find(std::begin(services), std::end(services), memberDecl->getNameAsString());

                if(it == std::end(services))
                {
                    foundCallExpr = false;
                    foundFunction = false;
                    return true;
                }
                currentService.Service = memberDecl->getNameAsString();
                foundFunction = true;
                if (auto fieldDecl = llvm::dyn_cast<clang::FieldDecl>(memberDecl)) {
                    auto fieldType = fieldDecl->getType();
                    if (auto pointerType = fieldType->getAs<clang::PointerType>()) {
                        auto pointeeType = pointerType->getPointeeType();
                        if (auto functionType = pointeeType->getAs<clang::FunctionProtoType>()) {
                            for (unsigned i = 0; i < functionType->getNumParams(); ++i) {
                                auto paramType = functionType->getParamType(i);
                                currentParameter = Parameter();
                                if((paramType.getAsString()).back() == '*')
                                {
                                    std::string type = paramType.getAsString();
                                    type.pop_back();
                                    type.pop_back();
                                    currentParameter.Type = type;
                                    currentParameter.Identifier = "*";
                                }
                                else
                                {
                                    currentParameter.Type = paramType.getAsString();
                                }
                                totalParamsCount++;
                                (currentService.Parameters).push_back(currentParameter);
                            }
                            getServiceType(memberExpr->getBase());
                            Expr* baseExpr = memberExpr->getBase();
                            if(auto base = llvm::dyn_cast<clang::ImplicitCastExpr>(baseExpr)) {
                                getServiceDef(base);
                            }
                            return true;
                        }
                    }
                }
            }

        }
        return true; // Continue traversal
    }

    bool VisitDeclRefExpr(DeclRefExpr *decRefExpr)
    {
        if(foundCallExpr)
        {
            if(isFunctionPointer)
            {
                if(auto* FD = llvm::dyn_cast<clang::FunctionDecl>(decRefExpr->getDecl())) {
                    std::string functionName = FD->getNameInfo().getAsString();
                    if(!foundFunction)
                    {
                        auto it = std::find(std::begin(services), std::end(services), functionName);

                        if(it == std::end(services))
                        {
                            foundCallExpr = false;
                            foundFunction = false;
                            return true;
                        }
                        currentService.Service = functionName;
                        foundFunction = true;
                    }
                }
                isFunctionPointer = false;
            }
            else
            {
                if(foundFunction && isParam)
                {
                    (currentService.Parameters)[paramCount].Variable = decRefExpr->getDecl()->getNameAsString();
                    if((currentService.Parameters)[paramCount].CallValue.empty())
                    {                    
                        (currentService.Parameters)[paramCount].CallValue = decRefExpr->getDecl()->getNameAsString();
                    }                    
                    foundParam = true;
                }
            }
        }
        return true;
    }

    bool VisitUnaryOperator(UnaryOperator *UO)
    {
        if(foundCallExpr)
        {
            std::string opStr = UO->getOpcodeStr(UO->getOpcode()).str();
            if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(UO->getSubExpr()))
            {
                ValueDecl *decl = DRE->getDecl();
                std::string varName = decl->getNameAsString();
                QualType varType = decl->getType();
                std::string varTypeStr = varType.getAsString();

                //currentParameter.Type = varTypeStr;
                //currentParameter.Identifier = opStr;
                if(isGUID(varTypeStr))
                {
                    currentService.ServiceGUID = varName;
                }
                varName = opStr + varName;
                (currentService.Parameters)[paramCount].CallValue = varName;
                foundParam = true;
            }
        }
        return true;
    }

    bool VisitParenExpr(ParenExpr *parenExpr) {
        if(foundFunction)
        {
            Expr *containedExpr = parenExpr->getSubExpr();
            if (auto *castExpr = llvm::dyn_cast<clang::CastExpr>(containedExpr)) {
                if (castExpr->getCastKind() == clang::CK_NullToPointer)
                {
                    (currentService.Parameters)[paramCount].CallValue = "NULL";
                    foundParam = true;
                    return true;
                }
            }
        }
        return true;
    }

    bool VisitBinaryOperator(BinaryOperator *bop) {
        if(foundFunction)
        {
            if (bop->isComparisonOp()) {  // Check if it's a comparison operation
                Expr *lhs = bop->getLHS()->IgnoreParenImpCasts();  // Get the left-hand side operand
                Expr *rhs = bop->getRHS()->IgnoreParenImpCasts();  // Get the right-hand side operand

                if (isa<IntegerLiteral>(lhs) && isa<IntegerLiteral>(rhs)) {
                    IntegerLiteral *lhs_lit = cast<IntegerLiteral>(lhs);
                    IntegerLiteral *rhs_lit = cast<IntegerLiteral>(rhs);

                    if(lhs_lit->getValue() == rhs_lit->getValue())
                    {
                        (currentService.Parameters)[paramCount].CallValue = "TRUE";
                    }
                    (currentService.Parameters)[paramCount].CallValue = "FALSE";
                    foundParam = true;
                }
            }
        }
        return true;
    }

    bool isGUID(std::string input)
    {
        std::transform(input.begin(), input.end(), input.begin(), ::tolower);
        if(input.find("guid") != std::string::npos)
        {
            return true;
        }
        return false;
    }

    void getServiceDef(ImplicitCastExpr *castExpr)
    {
        Expr*  expr = castExpr->getSubExpr();
        if(auto decl = llvm::dyn_cast<clang::DeclRefExpr>(expr))
        {
            if(isProtocol)
            {
                currentService.ServiceDefName = decl->getDecl()->getNameAsString();
            }
        }
    }

    void getServiceType(Expr *expr)
    {
        auto type = expr->getType();
        std::string typeStr = type.getAsString();
        std::transform(typeStr.begin(), typeStr.end(), typeStr.begin(), ::tolower);

        if(typeStr.find("runtime") != std::string::npos)
        {
            currentService.ServiceType = "Runtime";
        }
        else if(typeStr.find("boot") != std::string::npos)
        {
            currentService.ServiceType = "Boot";
        }
        else if(typeStr.find("protocol") != std::string::npos)
        {
            currentService.ServiceType = "Protocol";
            isProtocol = true;
        }
    }

    bool VisitCallExpr(CallExpr *CallExpression)
    {
        ParentMap PMap(CallExpression);

        // Now loop through the children of the binary operator
        foundCallExpr = true;
        paramCount = 0;
        for (Stmt::child_iterator I = CallExpression->child_begin(), E = CallExpression->child_end(); I != E; ++I)
        {
            if(foundFunction && isa<CallExpr>(PMap.getParent(*I)))
            {
                isParam = true;
            }
            if (*I)
            {
                TraverseStmt(*I);
            }
            if(!foundCallExpr)
            {
                break;
            }
            if(foundParam && isParam)
            {
                paramCount++;
                foundParam = false;
            }
            if(paramCount >= totalParamsCount)
            {
                break;
            }
        }
        isParam = false;
        totalParamsCount = 0;
        if(foundCallExpr && !(currentService.Service).empty())
        {
            results.push_back(currentService);
        }
        foundFunction = false;
        isProtocol = false;
        foundCallExpr = false;
        currentService = Service();
        paramCount = 0;
        return true;
    }

    static std::vector<Service> results;

private:
    bool isProtocol = false;
    int paramCount = 0;
    bool isParam = false;
    int totalParamsCount = 0;
    bool foundParam = false;
    bool foundFunction = false;
    bool isFunctionPointer = false;
    bool foundCallExpr = false;
    ASTContext *Context;
    Service currentService;
    Parameter currentParameter;
    std::set<std::string> services;
    std::string fName;
};
std::vector<Service> FirmwareVisitor::results;
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

class FirmwareAction : public clang::ASTFrontendAction
{
public:
    FirmwareAction() {}

    virtual std::unique_ptr<clang::ASTConsumer> CreateASTConsumer(
        clang::CompilerInstance &Compiler, llvm::StringRef InFile)
    {
        const std::set<std::string> input = {"Demo1BobDataProvider",
                                             "Demo1AliceProvideData",
                                             "Demo1GenerateAccessKey",
                                             "Demo1ValidateAccessKey",
                                             "SetAccessVariable",
                                             "GetAccessVariable"};
        return std::unique_ptr<clang::ASTConsumer>(
            new FirmwareConsumer(&Compiler.getASTContext(), input));
    }
};

static llvm::cl::OptionCategory MyToolCategory("my-tool options");

std::vector<Service> get_results()
{
    std::vector<Service> results;
    std::vector<std::string> merged;
    for (Service serv : FirmwareVisitor::results)
    {
        if (std::find(merged.begin(), merged.end(), serv.Service) == merged.end())
        {
            merged.push_back(serv.Service);
            Service maxService = serv;
            for(Service inner_serv : FirmwareVisitor::results)
            {
                if ((inner_serv.get_score() > maxService.get_score()) && (inner_serv.Service == serv.Service))
                {
                    maxService = inner_serv;
                }
            }
            results.push_back(maxService);
        }
    }

    return results;
}

int main(int argc, const char **argv)
{
    if (argc < 2)
    {
        llvm::errs() << "Usage: " << argv[0] << " <dir>\n";
        return 1;
    }

    fs::path rootPath(argv[3]);
    if (!fs::exists(rootPath) || !fs::is_directory(rootPath))
    {
        llvm::errs() << "Error: '" << rootPath << "' is not a directory.\n";
        return 1;
    }

    int totalResult = 0;

    for (auto &p : fs::recursive_directory_iterator(rootPath))
    {
        if (p.path().extension() == ".c") // Adjust this if needed
        {
            std::vector<std::string> args = {
                argv[0],
                argv[1],
                argv[2],
                p.path().string(),
            };
            int argcFake = args.size();
            const char **argvFake = new const char *[argcFake];
            for (int i = 0; i < argcFake; ++i)
            {
                argvFake[i] = args[i].c_str();
            }

            Expected<CommonOptionsParser> ExpectedOptions =
                CommonOptionsParser::create(argcFake, argvFake, MyToolCategory);
            if (!ExpectedOptions)
            {
                llvm::errs() << ExpectedOptions.takeError();
                delete[] argvFake;
                return 1;
            }
            CommonOptionsParser &OptionsParser = ExpectedOptions.get();
            ClangTool Tool(OptionsParser.getCompilations(),
                           OptionsParser.getSourcePathList());
            int result = Tool.run(newFrontendActionFactory<FirmwareAction>().get());
            totalResult += result;

            delete[] argvFake;
        }
    }

    nlohmann::json all_results = FirmwareVisitor::results;
    std::ofstream all_file("all_service_results.json"); // This will overwrite the file for each .cpp file. Consider changing this.
    all_file << all_results.dump(4) << std::endl;

    nlohmann::json analyzed_results = get_results();
    std::ofstream analyzed_file("compressed_service_results.json"); // This will overwrite the file for each .cpp file. Consider changing this.
    analyzed_file << analyzed_results.dump(4) << std::endl;
    return totalResult;
}

// clang++ -I/usr/lib/clang/15.0.7/include -I/usr/lib/llvm-15/include -L/usr/lib/llvm-15/lib $(llvm-config-15 --cxxflags) $(llvm-config-15 --ldflags --libs --system-libs) -lclang -lclangAST -lclangASTMatchers -lclangAnalysis -lclangBasic -lclangDriver -lclangEdit -lclangFrontend -lclangFrontendTool -lclangLex -lclangParse -lclangSema -lclangEdit -lclangRewrite -lclangRewriteFrontend -lclangStaticAnalyzerFrontend -lclangStaticAnalyzerCheckers -lclangStaticAnalyzerCore -lclangSerialization -lclangToolingCore -lclangTooling -lclangFormat tutorial.cpp -o tutorial