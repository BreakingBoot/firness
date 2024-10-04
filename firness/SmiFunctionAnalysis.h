#ifndef __SMIFUNCTIONANALYSIS_H__
#define __SMIFUNCTIONANALYSIS_H__

#include "PassHelpers.h"

class SmiFunctionAnalysis : public RecursiveASTVisitor<SmiFunctionAnalysis> {
public:
    explicit SmiFunctionAnalysis(ASTContext *Context)
        : Context(Context) {}

    enum SMIParam {
        FunctionHandle,
        Guid,
        DispatchContext
    };
    /*
        Checks if a given function call matches a function
        from the FunctionNames set
    */
    bool doesCallMatch(Expr *E, ASTContext &Ctx) {
        if (!E) return false;
        bool found = false;

        // Check for direct function calls
        if (DeclRefExpr* DRE = dyn_cast<DeclRefExpr>(E)) {
            if (FunctionDecl* FD = dyn_cast<FunctionDecl>(DRE->getDecl())) {
                if (((FD->getNameAsString()).find("SmiHandlerRegister") != std::string::npos) || ((FD->getNameAsString()).find("MmiHandlerRegister") != std::string::npos)) {
                    // llvm::outs() << "Found Match: " << FD->getNameAsString() << "\n";
                    return true;
                }
            }
        }
        else if (MemberExpr* MemExpr = dyn_cast<MemberExpr>(E)) {
            // If the Function Pointer Called matches the one we are looking for
            if(((MemExpr->getMemberNameInfo().getName().getAsString()).find("SmiHandlerRegister") != std::string::npos) || ((MemExpr->getMemberNameInfo().getName().getAsString()).find("MmiHandlerRegister") != std::string::npos)) {
                // llvm::outs() << "Found Match: " << MemExpr->getMemberNameInfo().getName().getAsString() << "\n";
                return true;
            }
        }

        for (Stmt *child : E->children()) {
            if(child) {
                if (Expr *childExpr = dyn_cast<Expr>(child)) {
                    if(doesCallMatch(childExpr, Ctx))
                    {
                        found = true;
                        break;
                    }
                }
            }
        }
        return found;
    }

    void ParseArg(Stmt *S, unsigned arg) {
        if (!S) return;

        if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(S)) {
            switch(arg) {
                case SMIParam::FunctionHandle:
                    CurrentFunction = DRE->getDecl()->getNameAsString();
                    break;
                case SMIParam::Guid:
                    CurrentInfo.Guid = DRE->getDecl()->getNameAsString();
                    break;
                default:
                    break;
            }
        }
        for (Stmt *child : S->children()) {
            ParseArg(child, arg);
        }
        return;
    }


    /*
        TODO: Take into account if the function handler is being stored in a structure of other handlers
    */
    bool VisitCallExpr(CallExpr *call) {
        if(doesCallMatch(call, *this->Context))
        {
            // Print out the function arguments
            for (unsigned i = 0; i < call->getNumArgs(); i++) {
                // print the argument string
                ParseArg(call->getArg(i)->IgnoreCasts(), i);
            }
            if(SmiFunctionSet.find(CurrentFunction) == SmiFunctionSet.end()) {
                SmiFunctionSet.insert(CurrentFunction);
                SmiFunctionGuidMap[CurrentFunction] = CurrentInfo;
            }
            CurrentInfo.clear();
            CurrentFunction.clear();
        }
        return true;
    }

    bool HasCommBuffer(Stmt *S) {
        if (!S) return false;

        if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(S)) {
            if (DRE->getDecl()->getNameAsString() == "CommBuffer") {
                return true;
            }
        }

        for (Stmt *child : S->children()) {
            if (HasCommBuffer(child)) {
                return true;
            }
        }
        return false;
    }

    void GetSmiType(Stmt* S) {
        if(!S) return;

        if (BinaryOperator *BO = dyn_cast<BinaryOperator>(S)) {
            // if(CurrentFunction == "SmmLockBoxHandler")
            //     BO->dump();
            if (BO->getOpcode() == BO_Assign) {
                // the RHS should be CommBuffer
                if(HasCommBuffer(BO->getRHS()))
                {
                    if (DeclRefExpr *DRE2 = dyn_cast<DeclRefExpr>(BO->getLHS())) {
                        // get the type of the structure
                        QualType QT = DRE2->getDecl()->getType();
                        SmiFunctionGuidMap[CurrentFunction].Type = QT.getAsString();
                    }
                }
            }
        }

        for(Stmt *child: S->children())
        {
            GetSmiType(child);
        }
        return;
    }

    // need to look at all function defitions and check if the function name has "Handler" in it
    // and we need to check if the function parameters are as follows:
    /*
        IN EFI_HANDLE  DispatchHandle,
        IN CONST VOID  *Context,
        IN OUT VOID    *CommBuffer,
        IN OUT UINTN   *CommBufferSize
    */
    bool VisitFunctionDecl(FunctionDecl *func) {
        if(SmiFunctionSet.find(func->getNameAsString()) != SmiFunctionSet.end()) {
            // parse the function to find the type of the structure stored in CommBuffer
            // we need to look for an assignment(i.e. a binary operator or a an expression that takes CommBuffer as INPUT usually a CopyMem or something similar)
            // step through the function body
            CurrentFunction = func->getNameAsString();
            GetSmiType(func->getBody());
            CurrentFunction.clear();
        }
        return true;
    }

private:
    ASTContext *Context;
    std::string CurrentFunction;
    SmiInfo CurrentInfo;
};

#endif 