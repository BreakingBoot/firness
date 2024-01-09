#ifndef __VARIABLEFLOW_H__
#define __VARIABLEFLOW_H__

#include "PassHelpers.h"

using namespace PassHelpers;

class VariableFlow : public RecursiveASTVisitor<VariableFlow> {
public:
    explicit VariableFlow(ASTContext *Context)
        : Context(Context) {}

    /*
        Adds all Variable declerations to the VarAssignment map
    */
    bool VisitVarDecl(VarDecl *VD) {
        // If the VarDecl has an initializer, store it; otherwise, store nullptr.
        VarAssignments[VD].push(std::make_pair((VD->hasInit() ? VD->getInit() : nullptr), ParameterDirection::UNKNOWN));
        return true;
    }

    /*
        Capture all of the Enums because they are considered constants
    */
   bool VisitEnumDecl(EnumDecl* ED)
   {
        for (auto it = ED->enumerator_begin(); it != ED->enumerator_end(); ++it) {
            EnumConstants.push_back((*it)->getNameAsString());
        }

        return true;
   }

    /*
        Capture all of the custom structures 
    */
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
        else if(T->getTypeClassName() != "Builtin")
        {
            // Function pointers that are typedefed should be ignored
            if(T->isFunctionPointerType())
                return true;
           SingleTypedefs.insert(std::make_pair(TD->getNameAsString(), TD->getUnderlyingType().getAsString()));
        }
        return true;
    }
    
    // 
    // Responsible for getting all Tracing the function definitions
    // 
    ParameterDirection DoesFunctionAssign(size_t Param, CallExpr *CE, Expr* Arg) {
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
                        // llvm::outs() << "Found typedef: " << TDN->getName().str() << "\n";
                    } else {
                        // llvm::outs() << "Function pointer call without typedef: " << VD->getNameAsString() << "\n";
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

    ParameterDirection DetermineArgumentType(size_t Param, std::string FuncText, Expr* Arg, CallExpr* CE) {
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

        }
        CallArgMap[CE][Arg] = ParameterDirection::UNKNOWN;
        // If nth parameter doesn't exist, return false by default
        return ParameterDirection::UNKNOWN;
    }

    ParameterDirection HandleTypedefArgs(size_t Param, TypedefDecl *typedefDecl, Expr* Arg, CallExpr *CE) {
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
        for (size_t i = 0; i < CE->getNumArgs(); ++i) {
            ParameterDirection direction = DoesFunctionAssign(i, CE, CE->getArg(i));
            Expr *Arg = CE->getArg(i)->IgnoreCasts();
            if (UnaryOperator *UO = dyn_cast<UnaryOperator>(Arg)) {
                if (UO->getOpcode() == UO_AddrOf) {
                    if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(UO->getSubExpr())) {
                        if (VarDecl *VD = dyn_cast<VarDecl>(DRE->getDecl())) {
                            if (VarAssignments.find(VD) != VarAssignments.end()) {
                                VarAssignments[VD].push(std::make_pair(CE, direction)); 
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

#endif