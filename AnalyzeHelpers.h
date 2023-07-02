#ifndef _ANALYZE_HELPERS_H_
#define _ANALYZE_HELPERS_H_

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

struct Analysis
{
    std::vector<Service> ServiceInfo;
    std::vector<std::string> Includes;
};

std::vector<Service> output_results;
std::vector<std::string> Includes;

#endif