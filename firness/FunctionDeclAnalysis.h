#ifndef __FUNCTIONDECLANALYSIS_H__
#define __FUNCTIONDECLANALYSIS_H__

#include "PassHelpers.h"
#include "clang/AST/DeclBase.h"

class FunctionDeclAnalysis : public RecursiveASTVisitor<FunctionDeclAnalysis> {
public:
    explicit FunctionDeclAnalysis(ASTContext *Context)
        : Context(Context) {}

    // Don't add repeat function decl of the same number of args
    bool ContainsFunction(FunctionDecl *FD) {
        for (auto &Func : FunctionDeclMap) {
            if (Func.FunctionName == FD->getNameAsString() && Func.Parameters.size() == FD->getNumParams()) {
                return true;
            }
        }
        return false;
    }


    std::string DetermineDirection(int Param, std::string FuncText) {
        std::vector<std::string> parameters;
        size_t pos = 0;
        size_t found;
        while ((found = FuncText.find(",", pos)) != std::string::npos) {
            parameters.push_back(FuncText.substr(pos, found - pos));
            pos = found + 1;
        }
        // Add the last parameter (no trailing comma)
        parameters.push_back(FuncText.substr(pos));

        if (Param < parameters.size()) {
            std::string param = parameters[Param];
            

            // Now you can analyze 'param' to determine the direction
            // use regular expressions to find "IN" and "OUT" qualifiers in 'param'.
            std::regex paramRegex(R"(\b(IN\s*OUT|OUT\s*IN|IN|OUT)\b\s+[\w_]+\s*\**\s*[\w_]+)");
            if(std::regex_search(param, paramRegex)) {
                std::smatch match;
                std::regex_search(param, match, paramRegex);
                std::string qualifier = match[1].str();
                // Check the matched string
                if (qualifier == "IN"){
                    return "IN";
                }else if (qualifier == "IN OUT" || qualifier == "OUT IN") {
                    return "IN_OUT";
                }else if (qualifier == "OUT") {
                    return "OUT";
                }
            }

        }
        // If nth parameter doesn't exist, return false by default
        return "UNKNOWN";
    }

    bool VisitFunctionDecl(FunctionDecl *Func) {
        if (FunctionNames.count(Func->getNameAsString()) && !ContainsFunction(Func)) {
            FunctionInfo.FunctionName = Func->getNameAsString();
            std::string arg_ID = "Arg_";
            for (unsigned i = 0; i < Func->getNumParams(); ++i) {
                Argument arg;
                ParmVarDecl *Param = Func->getParamDecl(i);
                
                SourceManager &SM = Context->getSourceManager();
                const LangOptions &LangOpts = Context->getLangOpts();
                CharSourceRange Range = CharSourceRange::getTokenRange(Func->getSourceRange());
                QualType OriginalType = Param->getOriginalType();
                std::string ExprText = Lexer::getSourceText(Range, SM, LangOpts).str();

                arg.arg_type = Param->getType().getAsString();
                arg.variable = Param->getNameAsString();
                // capture the other qualifiers for the argument
                // Need to do it via the lexer
                arg.arg_dir = DetermineDirection(i, ExprText);
                FunctionInfo.Parameters[arg_ID+std::to_string(i)] = arg;
            }
            //return type
            FunctionInfo.return_type = Func->getReturnType().getAsString();
            FunctionDeclMap.push_back(FunctionInfo);
            FunctionInfo.clear();
        }
        return true;
    }

private:
    ASTContext *Context;
    Function FunctionInfo;
};

#endif