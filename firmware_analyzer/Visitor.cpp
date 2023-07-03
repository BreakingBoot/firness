#include "Visitor.h"

bool Visitor::VisitImplicitCastExpr(ImplicitCastExpr *castExpr)
{
    if (foundCallExpr)
    {
        Expr *childNode = castExpr->getSubExpr();

        if (castExpr->getCastKind() == clang::CK_FunctionToPointerDecay)
        {
            isFunctionPointer = true;
        }
        if (foundFunction)
        {
            if (castExpr->getCastKind() == clang::CK_NullToPointer)
            {
                // currentParameter.Type = castExpr->getType().getAsString();
                (currentService.Parameters)[paramCount].CallValue = "NULL";
                foundParam = true;
                return true;
            }
            else if (childNode)
            {
                if (clang::isa<clang::IntegerLiteral>(childNode) || clang::isa<clang::FloatingLiteral>(childNode) || clang::isa<clang::StringLiteral>(childNode))
                {
                    if (clang::isa<clang::IntegerLiteral>(childNode))
                    {
                        auto literal = clang::cast<clang::IntegerLiteral>(childNode);
                        // if(auto expr = llvm::dyn_cast<clang::Expr>(childNode)) ASTContext{
                        //     currentParameter.Type = expr->getType().getAsString();
                        // }
                        // literal->getValue().toString(currentParameter.CallValue, 10, true);
                        llvm::errs() << "Type: IntegerLiteral, Value: " << literal->getValue() << "\n";
                        foundParam = true;
                    }
                    else if (clang::isa<clang::FloatingLiteral>(childNode))
                    {
                        auto literal = clang::cast<clang::FloatingLiteral>(childNode);
                        // if(auto expr = llvm::dyn_cast<clang::Expr>(childNode)) {
                        //     currentParameter.Type = expr->getType().getAsString();
                        // }
                        (currentService.Parameters)[paramCount].CallValue = llvm::APFloat(literal->getValue()).convertToDouble();
                        foundParam = true;
                    }
                    else if (clang::isa<clang::StringLiteral>(childNode))
                    {
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
        // TraverseStmt(childNode);
    }
    return true; // Continue traversal
}

bool Visitor::VisitMemberExpr(MemberExpr *memberExpr)
{
    if (foundCallExpr)
    {
        // Get the member declaration
        ValueDecl *memberDecl = memberExpr->getMemberDecl();
        if (!foundFunction)
        {
            auto it = std::find(std::begin(services), std::end(services), memberDecl->getNameAsString());

            if (it == std::end(services))
            {
                foundCallExpr = false;
                foundFunction = false;
                return true;
            }
            currentService.Service = memberDecl->getNameAsString();
            foundFunction = true;
            if (auto fieldDecl = llvm::dyn_cast<clang::FieldDecl>(memberDecl))
            {
                auto fieldType = fieldDecl->getType();
                if (auto pointerType = fieldType->getAs<clang::PointerType>())
                {
                    auto pointeeType = pointerType->getPointeeType();
                    if (auto functionType = pointeeType->getAs<clang::FunctionProtoType>())
                    {
                        for (unsigned i = 0; i < functionType->getNumParams(); ++i)
                        {
                            auto paramType = functionType->getParamType(i);
                            currentParameter = Parameter();
                            if ((paramType.getAsString()).back() == '*')
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
                        Expr *baseExpr = memberExpr->getBase();
                        if (auto base = llvm::dyn_cast<clang::ImplicitCastExpr>(baseExpr))
                        {
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

bool Visitor::VisitDeclRefExpr(DeclRefExpr *decRefExpr)
{
    if (foundCallExpr)
    {
        if (isFunctionPointer)
        {
            if (auto *FD = llvm::dyn_cast<clang::FunctionDecl>(decRefExpr->getDecl()))
            {
                std::string functionName = FD->getNameInfo().getAsString();
                if (!foundFunction)
                {
                    auto it = std::find(std::begin(services), std::end(services), functionName);

                    if (it == std::end(services))
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
            if (foundFunction && isParam)
            {
                (currentService.Parameters)[paramCount].Variable = decRefExpr->getDecl()->getNameAsString();
                if ((currentService.Parameters)[paramCount].CallValue.empty())
                {
                    (currentService.Parameters)[paramCount].CallValue = decRefExpr->getDecl()->getNameAsString();
                }
                foundParam = true;
            }
        }
    }
    return true;
}

bool Visitor::VisitUnaryOperator(UnaryOperator *UO)
{
    if (foundCallExpr)
    {
        std::string opStr = UO->getOpcodeStr(UO->getOpcode()).str();
        if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(UO->getSubExpr()))
        {
            ValueDecl *decl = DRE->getDecl();
            std::string varName = decl->getNameAsString();
            QualType varType = decl->getType();
            std::string varTypeStr = varType.getAsString();

            // currentParameter.Type = varTypeStr;
            // currentParameter.Identifier = opStr;
            if (isGUID(varTypeStr))
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

bool Visitor::VisitParenExpr(ParenExpr *parenExpr)
{
    if (foundFunction)
    {
        Expr *containedExpr = parenExpr->getSubExpr();
        if (auto *castExpr = llvm::dyn_cast<clang::CastExpr>(containedExpr))
        {
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

bool Visitor::VisitBinaryOperator(BinaryOperator *bop)
{
    if (foundFunction)
    {
        if (bop->isComparisonOp())
        {                                                     // Check if it's a comparison operation
            Expr *lhs = bop->getLHS()->IgnoreParenImpCasts(); // Get the left-hand side operand
            Expr *rhs = bop->getRHS()->IgnoreParenImpCasts(); // Get the right-hand side operand

            if (isa<IntegerLiteral>(lhs) && isa<IntegerLiteral>(rhs))
            {
                IntegerLiteral *lhs_lit = cast<IntegerLiteral>(lhs);
                IntegerLiteral *rhs_lit = cast<IntegerLiteral>(rhs);

                if (lhs_lit->getValue() == rhs_lit->getValue())
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

bool Visitor::isGUID(std::string input)
{
    std::transform(input.begin(), input.end(), input.begin(), ::tolower);
    if (input.find("guid") != std::string::npos)
    {
        return true;
    }
    return false;
}

void Visitor::getServiceDef(ImplicitCastExpr *castExpr)
{
    Expr *expr = castExpr->getSubExpr();
    if (auto decl = llvm::dyn_cast<clang::DeclRefExpr>(expr))
    {
        if (isProtocol)
        {
            currentService.ServiceDefName = decl->getDecl()->getNameAsString();
        }
    }
}

void Visitor::getServiceType(Expr *expr)
{
    auto type = expr->getType();
    std::string typeStr = type.getAsString();
    std::transform(typeStr.begin(), typeStr.end(), typeStr.begin(), ::tolower);

    if (typeStr.find("runtime") != std::string::npos)
    {
        currentService.ServiceType = "Runtime";
    }
    else if (typeStr.find("boot") != std::string::npos)
    {
        currentService.ServiceType = "Boot";
    }
    else if (typeStr.find("protocol") != std::string::npos)
    {
        currentService.ServiceType = "Protocol";
        isProtocol = true;
    }
}

bool Visitor::VisitCallExpr(CallExpr *CallExpression)
{
    ParentMap PMap(CallExpression);

    // Now loop through the children of the binary operator
    foundCallExpr = true;
    paramCount = 0;
    for (Stmt::child_iterator I = CallExpression->child_begin(), E = CallExpression->child_end(); I != E; ++I)
    {
        if (foundFunction && isa<CallExpr>(PMap.getParent(*I)))
        {
            isParam = true;
        }
        if (*I)
        {
            TraverseStmt(*I);
        }
        if (!foundCallExpr)
        {
            break;
        }
        if (foundParam && isParam)
        {
            paramCount++;
            foundParam = false;
        }
        if (paramCount >= totalParamsCount)
        {
            break;
        }
    }
    isParam = false;
    totalParamsCount = 0;
    if (foundCallExpr && !(currentService.Service).empty())
    {
        Visitor::results.push_back(currentService);
    }
    foundFunction = false;
    isProtocol = false;
    foundCallExpr = false;
    currentService = Service();
    paramCount = 0;
    return true;
}