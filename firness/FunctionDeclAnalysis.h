#ifndef __FUNCTIONDECLANALYSIS_H__
#define __FUNCTIONDECLANALYSIS_H__

#include "PassHelpers.h"

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


    bool VisitFunctionDecl(FunctionDecl *Func) {
        if (FunctionNames.count(Func->getNameAsString()) && !ContainsFunction(Func)) {
            FunctionInfo.FunctionName = Func->getNameAsString();
            for (unsigned i = 0; i < Func->getNumParams(); ++i) {
                ParmVarDecl *Param = Func->getParamDecl(i);
                FunctionInfo.Parameters.push_back(std::make_pair(Param->getNameAsString(), Param->getType().getAsString()));
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