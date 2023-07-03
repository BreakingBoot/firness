#ifndef _VISITOR_H_
#define _VISITOR_H_

#include "AnalyzeHelpers.h"

class Visitor : public RecursiveASTVisitor<Visitor>
{
public:
    explicit Visitor(ASTContext *Context, std::set<std::string> input)
        : Context(Context), services(input) {}

    const auto &getResults() const { return results; }


    bool VisitImplicitCastExpr(ImplicitCastExpr *castExpr);
    

    bool VisitMemberExpr(MemberExpr *memberExpr);

    bool VisitDeclRefExpr(DeclRefExpr *decRefExpr);
    

    bool VisitUnaryOperator(UnaryOperator *UO);

    bool VisitParenExpr(ParenExpr *parenExpr);

    bool VisitBinaryOperator(BinaryOperator *bop);

    bool isGUID(std::string input);

    void getServiceDef(ImplicitCastExpr *castExpr);

    void getServiceType(Expr *expr);

    bool VisitCallExpr(CallExpr *CallExpression);

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

#endif