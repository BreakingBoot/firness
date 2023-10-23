#ifndef __GENERATOR_ANALYSIS_H__
#define __GENERATOR_ANALYSIS_H__

#include "PassHelpers.h"

class GeneratorAnalysis : public RecursiveASTVisitor<GeneratorAnalysis> {
public:
    explicit GeneratorAnalysis(ASTContext *Context)
        : Context(Context) {}

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
                Expr* mostRelevantAssignment = getMostRelevantAssignment(VD, PassHelpers::getLineNumber(CurrentExpr, Ctx), Ctx);

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
        else if(BinaryOperator *BO = dyn_cast<BinaryOperator>(S))
        {
            VarDecl *Var = createPlaceholderVarDecl(Ctx, BO);
            Argument_AST Arg;
            Arg.Assignment = BO;
            Arg.Arg = CallArg;
            Arg.ArgNum = ParamNum;
            Arg.direction = HandleParameterDirection(ParameterDirection::DIRECT, dyn_cast<CallExpr>(CurrentExpr), CallArg);
            VarDeclMap[Var].push_back(Arg);
            return;
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

    /*
        This is responible for creating the placeholder variable
        name when the CallExpr argument is directly passed in via
        a literal (i.e. constant)
    */
    VarDecl* createPlaceholderVarDecl(ASTContext &Ctx, Stmt *literal) {
        // Get a unique name for the placeholder VarDecl
        std::string name = "__CONSTANT_";
        QualType type;

        if (isa<StringLiteral>(literal)) {
            name += "STRING__";
            type = Ctx.getPointerType(Ctx.getWCharType());
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
                return nullptr; 
            }
        } else if(auto *BO = dyn_cast<BinaryOperator>(literal)){
            if(BO->getOpcode() == BO_Or)
            {
                name += "INT__";
            }
            /*else
            {
                bool isSubstring = checkOperand(BO, Ctx, PreDefinedConstants, EnumConstants);
                
                if (isSubstring) {
                    name += "INT__";
                }
            }*/
            type = Ctx.IntTy;
        } else if (isa<IntegerLiteral>(literal)) {
            // Get the string representation of the literal
            std::string literalString = getSourceCode(dyn_cast<IntegerLiteral>(literal), Ctx); 

            // Check if any string in PreDefinedConstants is a substring of literalString
            bool isSubstring = false;
            for (const std::string& enums_defs : EnumConstants) {
                if (literalString.find(enums_defs) != std::string::npos) {
                    isSubstring = true;
                    break;
                }
            }

            if (isSubstring) {
                name += "INT__";
            }
            else
            {
                for (const std::string& predefined : PreDefinedConstants) {
                    if (literalString.find(predefined) != std::string::npos) {
                        isSubstring = true;
                        break;
                    }
                }

                if (isSubstring) {
                    name += "MAYBE_INT__";
                }
            }
            type = Ctx.IntTy;
        } else if (CallExpr *CE = dyn_cast<CallExpr>(literal)) {
            name = "__INDIRECT_CALL__";
            type = CE->getCallReturnType(Ctx);
        } else {
            return nullptr;
        }

        // Create the VarDecl with the computed name and type
        return VarDecl::Create(Ctx, Ctx.getTranslationUnitDecl(), 
                            SourceLocation(), SourceLocation(), 
                            &Ctx.Idents.get(name), type, 
                            Ctx.getTrivialTypeSourceInfo(type), 
                            SC_None);
    }

    /*
        Convert the direction flow of data to string
    */
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

    /*
        Converts the Clang AST map to a string map for output/further analysis
    */
    std::map<std::string, Argument> GetVarDeclMap(VarMap OriginalMap)
    {
        std::map<std::string, Argument> ConvertedMap;
        std::string arg_ID = "Arg_";
        for(auto& pair : OriginalMap)
        {
            VarDecl* VD = pair.first;
            for(Argument_AST Clang_Arg : pair.second)
            {
                Argument String_Arg;
                String_Arg.data_type = VD->getType().getAsString();
                String_Arg.variable = VD->getNameAsString();
                String_Arg.assignment = PassHelpers::reduceWhitespace(PassHelpers::getSourceCode(Clang_Arg.Assignment, *this->Context));
                String_Arg.usage = PassHelpers::reduceWhitespace(PassHelpers::getSourceCode(Clang_Arg.Arg, *this->Context));
                String_Arg.arg_dir = GetAssignmentType(Clang_Arg.direction);
                String_Arg.arg_type = Clang_Arg.Arg->getType().getAsString();
                ConvertedMap[arg_ID+std::to_string(Clang_Arg.ArgNum)] = String_Arg;
            }
        }
        return ConvertedMap;
    }


    /*
        Generate the call info by converting the Clang AST
        graph into a string one
    */
    bool GenCallInfo(Expr* EX)
    {
        if (!EX) return false;
        bool found = false;

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
                    
                }
            }
        }
        return ParameterDirection::UNKNOWN;
    }


    bool CheckType(const Expr *arg)
    {
        if((isa<UnaryOperator>(arg) || isa<BinaryOperator>(arg) || isa<MemberExpr>(arg) ||
            isa<CallExpr>(arg) || isa<StringLiteral>(arg) || isa<UnaryExprOrTypeTraitExpr>(arg) || 
            isa<IntegerLiteral>(arg) || isa<CharacterLiteral>(arg) ||
            isa<FloatingLiteral>(arg) || isa<CStyleCastExpr>(arg) || isa<DeclRefExpr>(arg) ||
            isa<ArraySubscriptExpr>(arg) || isa<ConditionalOperator>(arg) || isa<InitListExpr>(arg) ||
            isa<CompoundLiteralExpr>(arg) || isa<CXXThisExpr>(arg) ||
            isa<TypeTraitExpr>(arg) || isa<CXXTypeidExpr>(arg) || isa<LambdaExpr>(arg)) && !isa<CXXOperatorCallExpr>(arg))
        {
            return true;
        }
        return false;
    }

    /*
        Handle gathering all functions that return and/or OUT one of the variables of interest
    */
    bool VisitCallExpr(CallExpr *Call)
    {
        // Check if the call expression is found in CallArgMap
        if (CallArgMap.find(Call) != CallArgMap.end()) {
            // Iterate through the argument-direction map for this call expression
            for (auto& argDirPair : CallArgMap[Call]) {
                if(auto* arg = dyn_cast<Expr>(argDirPair.first))
                {
                    ParameterDirection dir = argDirPair.second;
                    
                    // Check if the argument direction is IN or IN_OUT
                    if (dir == ParameterDirection::OUT || dir == ParameterDirection::IN_OUT) {
                        // Assuming the argument has a method to get its type as a string
                        if (!CheckType(arg)) {
                            continue;
                        }
                        QualType qt = arg->getType();
                        if(!qt.isNull())
                        {
                            // Work through any typedefs to get to the ultimate
                            // underlying type.
                            while (qt->isAnyPointerType() || qt->isReferenceType()) {
                                qt = qt->getPointeeType();
                            }
                            qt = qt.getCanonicalType();

                            // Now, QT should be the actual type of the variable, without any typedefs
                            // Check if it's a record type (i.e., a struct or class type).
                            if (const RecordType *RT = dyn_cast<RecordType>(qt)) {
                                // Get the RecordDecl for the record type.
                                if(!qt.getAsString().empty())
                                {
                                    if(FinalTypes.find(qt.getAsString()) != FinalTypes.end())
                                    {
                                        HandleMatchingExpr(Call, *this->Context);
                                        GeneratorFunctionsMap[Call] = VarDeclMap;
                                        if(GenCallInfo(Call))
                                            GeneratorMap.push_back(CallInfo);
                                        VarDeclMap.clear();
                                        CallInfo.clear();
                                        return true;
                                    }
                                }
                            } else if (const TypedefType *TDT = dyn_cast<TypedefType>(qt)) {
                                // Get the TypedefNameDecl for the typedef type.
                                TypedefNameDecl *TND = TDT->getDecl();
                                llvm::outs() << TND->getNameAsString() << "\n";
                            //     // This is never reached, but I keep incase it is needed in future analysis            
                            }
                        }
                    }
                }
            }
        }
        return true;
    }

private:
    ASTContext *Context;
    VarMap VarDeclMap;
    Call CallInfo;
};

#endif