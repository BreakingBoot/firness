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
std::map<RecordDecl*, TypeData> FinalTypes;
std::map<CallExpr*, VarMap> CallExprMap;
std::map<CallExpr*, std::map<Expr*, ParameterDirection>> CallArgMap;
std::vector<Call> CallMap;


class VarDeclVisitor : public RecursiveASTVisitor<VarDeclVisitor> {
public:
    explicit VarDeclVisitor(ASTContext *Context)
        : Context(Context) {}

    bool VisitVarDecl(VarDecl *VD) {
        // If the VarDecl has an initializer, store it; otherwise, store nullptr.
        VarAssignments[VD].push(std::make_pair((VD->hasInit() ? VD->getInit() : nullptr), ParameterDirection::UNKNOWN));
        return true;
    }

    bool VisitTypedefDecl(TypedefDecl *TD) {
        const Type *T = TD->getUnderlyingType().getTypePtr();
        // Check if it's an ElaboratedType
        if (const ElaboratedType *ET = dyn_cast<ElaboratedType>(T)) {
            // Get the RecordType from the ElaboratedType
            const RecordType *RT = dyn_cast<RecordType>(ET->getNamedType().getTypePtr());
            if (RT) {
                // Get the RecordDecl from the RecordType
                RecordDecl *RD = RT->getDecl();
                if (RD->isThisDeclarationADefinition()) {
                    TypeData Type_Data;
                    Type_Data.TypeName = TD->getNameAsString();
                    Type_Data.record = RD;
                    Type_Data.TypeDec = TD;
                    for (auto Field : RD->fields()) {
                        FieldInfo Field_Info;
                        Field_Info.FieldType = Field;
                        Field_Info.Name = Field->getNameAsString();
                        Field_Info.Type = Field->getType().getAsString();
                        Type_Data.Fields.push_back(Field_Info);
                    }
                    varTypeInfo[TD] = Type_Data;
                    varRecordInfo[RD] = Type_Data;
                }
            }
        }
        return true;
    }
    
    // 
    // Responsible for getting all Tracing the function definitions
    // 
    ParameterDirection DoesFunctionAssign(int Param, CallExpr *CE, Expr* Arg) {
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
                                    return HandleTypedefArgs(Param, TypedefDeclaration, Arg, CE);
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
                        llvm::outs() << "Function pointer call without typedef: " << VD->getNameAsString() << "\n";
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

                        return DetermineArgumentType(Param, FuncText, Arg, CE);
                    }
                }
            }
        }
        return ParameterDirection::UNKNOWN;
    }

    ParameterDirection DetermineArgumentType(int Param, std::string FuncText, Expr* Arg, CallExpr* CE) {
        // Check for presence of "IN" and "OUT" qualifiers
        std::regex paramRegex(R"(\b(IN\s+OUT|OUT\s+IN|IN|OUT)\b\s+[\w_]+\s+\**\s*[\w_]+)");

        std::smatch match;
        int index = 0;

        std::string::const_iterator searchStart(FuncText.cbegin());
        while (std::regex_search(searchStart, FuncText.cend(), match, paramRegex)) {
            if (index == Param) {
                std::string qualifier = match[1].str();
                // Check the matched string
                if (qualifier == "IN"){
                    CallArgMap[CE][Arg] = ParameterDirection::IN;
                    return ParameterDirection::IN;
                }else if (qualifier == "IN OUT" || qualifier == "OUT IN") {
                    CallArgMap[CE][Arg] = ParameterDirection::IN_OUT;
                    return ParameterDirection::IN_OUT;
                }else if (qualifier == "OUT") {
                    CallArgMap[CE][Arg] = ParameterDirection::OUT;
                    return ParameterDirection::OUT;
                }
            }
            searchStart = match.suffix().first;
            index++;
        }
        CallArgMap[CE][Arg] = ParameterDirection::UNKNOWN;
        // If nth parameter doesn't exist, return false by default
        return ParameterDirection::UNKNOWN;
    }

    ParameterDirection HandleTypedefArgs(int Param, TypedefDecl *typedefDecl, Expr* Arg, CallExpr *CE) {
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

        return DetermineArgumentType(Param, FuncText, Arg, CE);
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
                                VarAssignments[VD].push(std::make_pair(CE, DoesFunctionAssign(i, CE, CE->getArg(i)))); 
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

    unsigned getLineNumber(Expr *E, ASTContext &Ctx) {
        SourceManager &SM = Ctx.getSourceManager();
        SourceLocation Loc = E->getExprLoc();
        if (Loc.isValid()) {
            return SM.getExpansionLineNumber(Loc);
        }
        return 0; // Return an invalid line number or handle the error as suitable
    }

    // Assume ParameterDirection is an enum with values INPUT and OUTPUT
    Expr* getMostRelevantAssignment(VarDecl* var, int exprLineNumber, ASTContext &Ctx) {
        std::stack<std::pair<clang::Expr *, ParameterDirection>> assignmentsStack = VarAssignments[var];

        // This loop checks the assignments from the most recent (top of the stack) to the earliest.
        while (!assignmentsStack.empty() && assignmentsStack.top().first != nullptr) {
            std::pair<clang::Expr *, ParameterDirection> assignmentInfo = assignmentsStack.top();

            Expr* assignmentExpr = assignmentInfo.first;
            ParameterDirection direction = assignmentInfo.second;

            // Retrieve the line number of the assignmentExpr.
            int assignmentLineNumber = getLineNumber(assignmentExpr, Ctx);

            // If the direction indicates it's an assignment and it's before our expression of interest
            if ((direction == ParameterDirection::OUT || direction == ParameterDirection::IN_OUT || direction == ParameterDirection::DIRECT)&& assignmentLineNumber < exprLineNumber) {
                return assignmentExpr;
            }

            // Move to the next (earlier) assignment in the stack
            assignmentsStack.pop();
        }

        // Handle the case where no assignment is found, if necessary.
        return nullptr;
    }

    void HandleMatchingExpr(CallExpr* CE, ASTContext &Ctx) {
        for (unsigned i = 0; i < CE->getNumArgs(); i++) {
            ParseArg(CE->getArg(i)->IgnoreCasts(), Ctx, CE, CE->getArg(i), i);
        }
    }

    ParameterDirection HandleParameterDirection(ParameterDirection VariableDirection, CallExpr* CE, Expr* Arg)
    {
        if((VariableDirection == ParameterDirection::DIRECT) && (CallArgMap[CE][Arg] == ParameterDirection::IN))
        {
            return ParameterDirection::IN_DIRECT;
        }
        return CallArgMap[CE][Arg];
    }

    void ParseArg(Stmt *S, ASTContext &Ctx, Expr* CurrentExpr, Expr* CallArg, int ParamNum) {
        if (!S) return;

        if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(S)) {
            if(VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
                // If the top Expr in the stack of VarAssignments[VD]
                // is the same as the current CallExpr then get the second one
                while (!VarAssignments[VD].empty() && VarAssignments[VD].top().first == CurrentExpr) {
                    VarAssignments[VD].pop();
                }
                    
                // If stack is empty after popping, you might want to handle it here
                if (VarAssignments[VD].empty()) {
                    return;  // or some other default action
                }

                // Fetch the most relevant assignment for this variable usage
                Expr* mostRelevantAssignment = getMostRelevantAssignment(VD, getLineNumber(CurrentExpr, Ctx), Ctx);

                if (mostRelevantAssignment) {
                    Argument_AST Arg;
                    Arg.Assignment = mostRelevantAssignment;
                    Arg.Arg = CallArg;
                    Arg.ArgNum = ParamNum;
                    Arg.direction = HandleParameterDirection(VarAssignments[VD].top().second, dyn_cast<CallExpr>(CurrentExpr), CallArg);
                    VarDeclMap[VD].push_back(Arg);
                }
                else
                {
                    Argument_AST Arg;
                    Arg.Assignment = nullptr;
                    Arg.Arg = CallArg;
                    Arg.ArgNum = ParamNum;
                    Arg.direction = HandleParameterDirection(VarAssignments[VD].top().second, dyn_cast<CallExpr>(CurrentExpr), CallArg);
                    VarDeclMap[VD].push_back(Arg);
                }
                return;
            }
        }
        else if (StringLiteral *SL = dyn_cast<StringLiteral>(S)) {
            VarDecl *Var = createPlaceholderVarDecl(Ctx, SL);
            Argument_AST Arg;
            Arg.Assignment = SL;
            Arg.Arg = CallArg;
            Arg.ArgNum = ParamNum;
            Arg.direction = HandleParameterDirection(ParameterDirection::DIRECT, dyn_cast<CallExpr>(CurrentExpr), CallArg);
            VarDeclMap[Var].push_back(Arg);
            return;
        } 
        else if (IntegerLiteral *IL = dyn_cast<IntegerLiteral>(S)) {
            VarDecl *Var = createPlaceholderVarDecl(Ctx, IL); 
            Argument_AST Arg;
            Arg.Assignment = IL;
            Arg.Arg = CallArg;
            Arg.ArgNum = ParamNum;
            Arg.direction = HandleParameterDirection(ParameterDirection::DIRECT, dyn_cast<CallExpr>(CurrentExpr), CallArg);
            VarDeclMap[Var].push_back(Arg);     
            return;       
        }
        else if (UnaryExprOrTypeTraitExpr *UETTE = dyn_cast<UnaryExprOrTypeTraitExpr>(S)) {
            if (UETTE->getKind() == UETT_SizeOf) {
                // It's a sizeof expression.
                // Handle or further process the operand of the sizeof operation.
                VarDecl *Var = createPlaceholderVarDecl(Ctx, UETTE); 
                Argument_AST Arg;
                Arg.Assignment = UETTE;
                Arg.Arg = CallArg;
                Arg.ArgNum = ParamNum;
                Arg.direction = HandleParameterDirection(ParameterDirection::DIRECT, dyn_cast<CallExpr>(CurrentExpr), CallArg);
                VarDeclMap[Var].push_back(Arg);  
                return;
            }
        } 
        else if (CallExpr* CE = dyn_cast<CallExpr>(S)) {
            VarDecl *Var = createPlaceholderVarDecl(Ctx, CE); 
            Argument_AST Arg;
            Arg.Assignment = CE;
            Arg.Arg = CallArg;
            Arg.ArgNum = ParamNum;
            Arg.direction = HandleParameterDirection(ParameterDirection::INDIRECT, dyn_cast<CallExpr>(CurrentExpr), CallArg);
            VarDeclMap[Var].push_back(Arg);  
            return;
        }
        for (Stmt *child : S->children()) {
            ParseArg(child, Ctx, CurrentExpr, CallArg, ParamNum);
        }
        return;
    }

    VarDecl* createPlaceholderVarDecl(ASTContext &Ctx, Stmt *literal) {
        // Get a unique name for the placeholder VarDecl
        // Note: This is just an example naming convention.
        std::string name = "__CONSTANT_";
        QualType type;

        if (isa<StringLiteral>(literal)) {
            name += "STRING__";
            type = Ctx.getPointerType(Ctx.getWCharType());  // Assuming it's a wide string
        } else if (isa<IntegerLiteral>(literal)) {
            name += "INT__";
            type = Ctx.IntTy;
        } else if (UnaryExprOrTypeTraitExpr *sizeofExpr = dyn_cast<UnaryExprOrTypeTraitExpr>(literal)){
            if (sizeofExpr->getKind() == UETT_SizeOf) {
                name += "SIZEOF__";
                // Get the type of the expression argument if it's a type
                if (sizeofExpr->isArgumentType()) {
                    type = sizeofExpr->getArgumentType();
                } else {
                    // If the argument is an expression, get its type
                    type = sizeofExpr->getArgumentExpr()->getType();
                }
            } else {
                return nullptr;  // Unsupported unary expression or type trait
            }
        } else if (CallExpr *CE = dyn_cast<CallExpr>(literal)) {
            name = "__INDIRECT_CALL__";
            type = CE->getCallReturnType(Ctx);
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

    std::string GetAssignmentType(ParameterDirection dir)
    {
        switch(dir)
        {
            case ParameterDirection::DIRECT:
                return "DIRECT";
            case ParameterDirection::UNKNOWN:
                return "UNKNOWN";
            case ParameterDirection::IN:
                return "IN";
            case ParameterDirection::OUT:
                return "OUT";
            case ParameterDirection::IN_OUT:
                return "IN_OUT";
            case ParameterDirection::INDIRECT:
                return "INDIRECT";
            case ParameterDirection::IN_DIRECT:
                return "IN_DIRECT";
            default:
                return "UNKNOWN";
        }
    }

    std::map<std::string, Argument> GetVarDeclMap(VarMap OriginalMap)
    {
        std::map<std::string, Argument> ConvertedMap;
        std::string arg_ID = "Arg_";
        for(auto& pair : OriginalMap)
        {
            VarDecl* VD = pair.first;
            GetVarStruct(VD);
            for(Argument_AST Clang_Arg : pair.second)
            {
                Argument String_Arg;
                String_Arg.data_type = VD->getType().getAsString();
                String_Arg.variable = VD->getNameAsString();
                String_Arg.assignment = reduceWhitespace(getSourceCode(Clang_Arg.Assignment));
                String_Arg.usage = reduceWhitespace(getSourceCode(Clang_Arg.Arg));
                String_Arg.arg_dir = GetAssignmentType(Clang_Arg.direction);
                String_Arg.arg_type = Clang_Arg.Arg->getType().getAsString();
                ConvertedMap[arg_ID+std::to_string(Clang_Arg.ArgNum)] = String_Arg;
            }
        }
        return ConvertedMap;
    }

    void processRecord(RecordDecl *RD) {
        if (!RD || (varRecordInfo.find(RD) == varRecordInfo.end()) || (FinalTypes.find(RD) != FinalTypes.end())) {
            return;
        }
        if((FinalTypes.find(RD) == FinalTypes.end())) {
            FinalTypes[RD] = varRecordInfo[RD];
        }
        //
        for (auto field : RD->fields()) {
            QualType fieldQT = field->getType();
            while (fieldQT->isAnyPointerType() || fieldQT->isReferenceType()) {
                fieldQT = fieldQT->getPointeeType();
            }
            fieldQT = fieldQT.getCanonicalType();

            if (const RecordType *fieldRT = dyn_cast<RecordType>(fieldQT)) {
                processRecord(fieldRT->getDecl());
            } else if (const TypedefType *fieldTDT = dyn_cast<TypedefType>(fieldQT)) {
                //TypedefNameDecl *fieldTND = fieldTDT->getDecl();
                // Handle typedef types if necessary...
            }
        }
    }

    void GetVarStruct(VarDecl *VD) {
        if (!VD) {
            return;
        }
        QualType QT = VD->getType();

        // Work through any typedefs or other sugar to get to the ultimate
        // underlying type.
        while (QT->isAnyPointerType() || QT->isReferenceType()) {
            QT = QT->getPointeeType();
        }
        QT = QT.getCanonicalType();

        // Now, QT should be the actual type of the variable, without any typedefs or other sugar.
        // Check if it's a record type (i.e., a struct or class type).
        if (const RecordType *RT = dyn_cast<RecordType>(QT)) {
            // Get the RecordDecl for the record type.
            if(FinalTypes.find(RT->getDecl()) == FinalTypes.end())
                processRecord(RT->getDecl());
        } else if (const TypedefType *TDT = dyn_cast<TypedefType>(QT)) {
            // Get the TypedefNameDecl for the typedef type.
            TypedefNameDecl *TND = TDT->getDecl();
            llvm::outs() << "Variable " << VD->getNameAsString() << " is of typedef type "
                        << TND->getNameAsString() << "\n";
            // Now, you can do whatever you need with the TypedefNameDecl.
        }
    }

    bool GenCallInfo(Expr* EX)
    {
        if (!EX) return false;
        bool found = false;

        // Get the function Call as a String
        std::string CallExprString;
        if (DeclRefExpr* DRE = dyn_cast<DeclRefExpr>(EX)) {
            if (FunctionDecl* FD = dyn_cast<FunctionDecl>(DRE->getDecl())) {
                CallExprString = FD->getNameAsString();
                CallInfo.Function = CallExprString;
                CallInfo.Arguments = GetVarDeclMap(VarDeclMap);
                return true;
            }
        }
        else if (MemberExpr* MemExpr = dyn_cast<MemberExpr>(EX)) {
            CallExprString = MemExpr->getMemberNameInfo().getName().getAsString();
            CallInfo.Function = CallExprString;
            CallInfo.Arguments = GetVarDeclMap(VarDeclMap);
            return true;
        }
        for (Stmt *child : EX->children()) {
            if (Expr *childExpr = dyn_cast<Expr>(child)) {
                if(GenCallInfo(childExpr))
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
            CallInfo.clear();
            HandleMatchingExpr(Call, *this->Context);
            CallExprMap[Call] = VarDeclMap;
            GenCallInfo(Call);
            CallMap.push_back(CallInfo);
        }
        return true;
    }


private:
    ASTContext *Context;
    VarMap VarDeclMap;
    Call CallInfo;
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


void printCallMap(const std::vector<Call> &calls) {
    for (const auto &callEntry : calls) {
        llvm::outs() << "Function: " << callEntry.Function << "\n";
        
        for (const auto &varEntry : callEntry.Arguments) {
            llvm::outs() << "\tArgument: " << varEntry.first << "\n";
            Argument Arg = varEntry.second;
            llvm::outs() << "\t\tArg_Type: " << Arg.data_type << "\n";
            llvm::outs() << "\t\tArg_Name: " << Arg.variable << "\n";
            llvm::outs() << "\t\tArg_Assign: " << Arg.assignment << "\n";
            llvm::outs() << "\t\tArg_Direction: " << Arg.arg_dir << "\n";
            llvm::outs() << "\t\tArg_Usage: " << Arg.usage << "\n";
        }
    }
}


void readAndProcessFile(const std::string& filename) {
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
            FunctionNames.insert(line);
        }
    }

    file.close();
}

void outputCallExprMapToJSON(const std::string& filename) {
    std::string file_path = filename + "/call-database.json";
    nlohmann::json jsonOutput;

    // Iterate over the CallMap
    for (const auto& call : CallMap) {
        // Create a JSON object for each call
        nlohmann::json callObject;
        callObject["Function"] = call.Function;

        for (const auto& argumentPair : call.Arguments) {
            // Create a JSON object for each argument
            nlohmann::json argObject;
            const Argument& arg = argumentPair.second;
            argObject["data_type"] = arg.data_type;
            argObject["variable"] = arg.variable;
            argObject["assignment"] = arg.assignment;
            argObject["arg_dir"] = arg.arg_dir;
            argObject["arg_type"] = arg.arg_type;
            argObject["usage"] = arg.usage;

            callObject["Arguments"][argumentPair.first] = argObject;
        }

        // Add the call object to the JSON output
        jsonOutput.push_back(callObject);
    }

    // Write the JSON object to a file
    std::ofstream outFile(file_path);
    outFile << jsonOutput.dump(4); // Indent the JSON output for readability
    outFile.close();
}

void writeToJson(const std::string &filename) {
    std::string file_path = filename + "/types.json";
    nlohmann::json j;

    for (const auto& pair : FinalTypes) {
        const TypeData& typeData = pair.second;
        nlohmann::json typeJson;
        typeJson["TypeName"] = typeData.TypeName;

        nlohmann::json fieldsJson;
        for (const FieldInfo& fieldInfo : typeData.Fields) {
            nlohmann::json fieldJson;
            fieldJson["Name"] = fieldInfo.Name;
            fieldJson["Type"] = fieldInfo.Type;
            fieldsJson.push_back(fieldJson);
        }
        typeJson["Fields"] = fieldsJson;

        j.push_back(typeJson);
    }

    std::ofstream file(file_path);
    file << j.dump(4);  // 4 spaces for indentation
    file.close();
}

// Define command-line options for filename and source code
static llvm::cl::opt<std::string> InputFileName(
    "f", llvm::cl::desc("Specify the input filename"), llvm::cl::value_desc("filename"));

static llvm::cl::opt<std::string> OutputFileName(
    "o", llvm::cl::desc("Specify the output filename"), llvm::cl::value_desc("filename"));

clang::tooling::ClangTool createClangTool(CommonOptionsParser &OptionsParser) {
    try {
        return clang::tooling::ClangTool(OptionsParser.getCompilations(), OptionsParser.getSourcePathList());
    }
    catch (...) {
        return clang::tooling::ClangTool(OptionsParser.getCompilations(), OptionsParser.getCompilations().getAllFiles());
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

    // Get the filename and source code from command-line options
    std::string input_filename = InputFileName.getValue();
    std::string output_filename = OutputFileName.getValue();
    llvm::outs() << "Input file: " << input_filename << "\n";
    llvm::outs() << "Output file: " << output_filename << "\n";

    // Use the filename to create a ClangTool instance
    //ClangTool Tool = createClangTool(OptionsParser);
    ClangTool Tool(OptionsParser.getCompilations(), OptionsParser.getCompilations().getAllFiles());
    //ClangTool Tool(OptionsParser.getCompilations(), OptionsParser.getSourcePathList());

    if(!input_filename.empty())
        readAndProcessFile(input_filename);
    else
        FunctionNames = {"GetVariable", "SetVariable", "CopyMem"};
    Tool.run(newFrontendActionFactory<FindNamedFunctionAction>().get());

    if(!output_filename.empty())
    {
        outputCallExprMapToJSON(output_filename);
        writeToJson(output_filename);
    }
    else
        printCallMap(CallMap);

    return 0;
}
