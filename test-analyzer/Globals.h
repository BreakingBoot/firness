#include <iostream>
#include <fstream>
#include <algorithm>
#include <set>
#include <string>
#include <regex>
#include <clang/AST/ASTConsumer.h>
#include <clang/AST/ParentMap.h>
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

enum class ParameterDirection {
    IN,
    OUT,
    IN_OUT,
    UNKNOWN,
    DIRECT,
    INDIRECT,
    IN_DIRECT
};

struct Argument {
    std::string data_type;
    std::string variable;
    std::string assignment;
    std::string usage;
    std::string arg_dir;
    std::string arg_type;

    // Function to clear the Argument object
    void clear() {
        data_type.clear();
        variable.clear();
        assignment.clear();
        usage.clear();
        arg_dir.clear();
        arg_type.clear();
    }
};

struct Argument_AST {
    Expr* Arg;
    Expr* Assignment;
    int ArgNum;
    ParameterDirection direction;

    void clear() {
        Arg = nullptr;
        Assignment = nullptr;
        ArgNum = 0;
        direction = ParameterDirection::UNKNOWN; 
    }
};

struct FieldInfo {
    std::string Name;
    std::string Type;
    FieldDecl* FieldType;
};
struct TypeData {
    std::string TypeName;
    TypedefDecl* TypeDec;
    RecordDecl *record;
    std::vector<FieldInfo> Fields;
};

std::map<TypedefDecl*, TypeData> varTypeInfo;
std::map<RecordDecl*, TypeData> varRecordInfo;


typedef std::pair<Expr*, ParameterDirection> Assignment;

typedef std::map<VarDecl*, std::vector<Argument_AST>> VarMap;

struct Call {
    std::string Function;
    std::map<std::string, Argument> Arguments;

    // Function to clear the Call object
    void clear() {
        Function.clear();
        for (auto& pair : Arguments) {
            pair.second.clear();
        }
        Arguments.clear();
    }
};

std::set<std::string> FunctionNames;
std::map<VarDecl*, std::stack<Assignment>> VarAssignments;
std::map<std::string, TypeData> FinalTypes;
std::map<CallExpr*, VarMap> CallExprMap;
std::map<CallExpr*, std::map<Expr*, ParameterDirection>> CallArgMap;
std::vector<Call> CallMap;
