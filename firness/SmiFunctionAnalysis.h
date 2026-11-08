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
        Which registration spelling a call is, or "" if it is not a registration.

        There is more than one way into SMM and they do not share an argument order, so a
        substring test that only knows SmiHandlerRegister finds the GUID-dispatched
        handlers and silently misses the rest. Measured on EVAL-1: 22 handler bodies exist
        in the tree, 10 were found, and the 12 missed included PiSmmCommunicationHandler
        -- the DXE-to-SMM bridge itself -- because they go through
        SmmSwDispatch2->Register instead.

        The spelling also decides what can be done with the handler afterwards, which is
        why it is recorded rather than normalised away. Only the SmiHandlerRegister family
        is dispatched by GUID with a caller-supplied CommBuffer; everything else is raised
        by the platform, and its CommBuffer is built by the dispatcher.
    */
    /*
        Case and underscores removed, so one arm matches every spelling of a name.

        A tree writes the same dispatcher as SmmSwDispatch2, mSwDispatch and
        EFI_SMM_SW_DISPATCH2_PROTOCOL, and a case-sensitive search for "SwDispatch" finds
        the first two and misses the third. The normalised needles below are specific
        enough that nothing else collides with them.
    */
    std::string normalise(const std::string &Name) {
        std::string Out;
        Out.reserve(Name.size());
        for (char Ch : Name) {
            if (Ch == '_') {
                continue;
            }
            Out.push_back((char)((Ch >= 'A' && Ch <= 'Z') ? (Ch - 'A' + 'a') : Ch));
        }
        return Out;
    }

    std::string registrationKind(const std::string &Raw) {
        const std::string Name = normalise(Raw);
        //
        // Ordered longest-distinguishing-first: "register" alone matches far too much, so
        // each arm names the dispatcher. Both the Smm and Mm spellings of every protocol
        // exist in-tree -- the Mm names are the newer PI ones -- and a tree can use either.
        //
        if (Name.find("smihandlerregister") != std::string::npos ||
            Name.find("mmihandlerregister") != std::string::npos) {
            return "SmiHandlerRegister";
        }
        if (Name.find("swdispatch") != std::string::npos) {
            return "SwDispatch";
        }
        if (Name.find("sxdispatch") != std::string::npos) {
            return "SxDispatch";
        }
        if (Name.find("periodictimerdispatch") != std::string::npos) {
            return "PeriodicTimer";
        }
        if (Name.find("usbdispatch") != std::string::npos) {
            return "UsbDispatch";
        }
        if (Name.find("gpidispatch") != std::string::npos) {
            return "GpiDispatch";
        }
        if (Name.find("powerbuttondispatch") != std::string::npos) {
            return "PowerButton";
        }
        if (Name.find("standbybuttondispatch") != std::string::npos) {
            return "StandbyButton";
        }
        if (Name.find("iotrapdispatch") != std::string::npos) {
            return "IoTrap";
        }
        return "";
    }

    /*
        Where the handler pointer sits in the registration's argument list.

        SmiHandlerRegister (Handler, HandlerType, DispatchHandle) puts it first.
        Every root dispatcher's Register is a protocol member and takes This first:
        Register (This, DispatchFunction, RegisterContext, DispatchHandle), so the handler
        is second. Reading argument 0 there yields the protocol variable, which is how a
        dispatcher registration would otherwise be recorded as a handler named
        "SmmSwDispatch2".
    */
    unsigned handlerArgIndex(const std::string &Kind) {
        return (Kind == "SmiHandlerRegister") ? 0u : 1u;
    }

    /*
        Checks whether a call is one of the handler registrations, and says which.
    */
    std::string matchedRegistration(Expr *E, ASTContext &Ctx) {
        if (!E) return "";

        // Check for direct function calls
        if (DeclRefExpr* DRE = dyn_cast<DeclRefExpr>(E)) {
            if (FunctionDecl* FD = dyn_cast<FunctionDecl>(DRE->getDecl())) {
                std::string Kind = registrationKind(FD->getNameAsString());
                if (!Kind.empty()) {
                    return Kind;
                }
            }
        }
        else if (MemberExpr* MemExpr = dyn_cast<MemberExpr>(E)) {
            // If the Function Pointer Called matches the one we are looking for
            std::string Kind = registrationKind(MemExpr->getMemberNameInfo().getName().getAsString());
            if (!Kind.empty()) {
                return Kind;
            }
            //
            // The dispatch protocols spell the member plainly as "Register", so the
            // dispatcher's name is on the object it is reached through -- SmmSwDispatch2
            // or mSwDispatch -- rather than on the member. Ask the base for it.
            //
            if (MemExpr->getMemberNameInfo().getName().getAsString() == "Register") {
                Expr *Base = MemExpr->getBase();
                if (Base != nullptr) {
                    Base = Base->IgnoreParenCasts();
                    std::string BaseName;
                    if (DeclRefExpr *BaseRef = dyn_cast<DeclRefExpr>(Base)) {
                        BaseName = BaseRef->getDecl()->getNameAsString();
                    } else if (MemberExpr *BaseMem = dyn_cast<MemberExpr>(Base)) {
                        BaseName = BaseMem->getMemberNameInfo().getName().getAsString();
                    }
                    if (!BaseName.empty()) {
                        std::string Kind = registrationKind(BaseName);
                        if (!Kind.empty()) {
                            return Kind;
                        }
                    }
                }
            }
        }

        for (Stmt *child : E->children()) {
            if(child) {
                if (Expr *childExpr = dyn_cast<Expr>(child)) {
                    std::string Kind = matchedRegistration(childExpr, Ctx);
                    if(!Kind.empty())
                    {
                        return Kind;
                    }
                }
            }
        }
        return "";
    }

    bool doesCallMatch(Expr *E, ASTContext &Ctx) {
        return !matchedRegistration(E, Ctx).empty();
    }

    void ParseArg(Stmt *S, unsigned arg) {
        if (!S) return;

        if (DeclRefExpr *DRE = dyn_cast<DeclRefExpr>(S)) {
            //
            // The walk descends into every child and the last match wins, so what the slot
            // will ACCEPT has to be narrowed or any identifier in the expression can end up
            // in it. The SMM core registers from a table --
            //
            //   SmiHandlerRegister (mSmmCoreSmiHandlers[Index].Handler, ...)
            //
            // -- and the subscript is the deepest DeclRefExpr, so "Index" was recorded as
            // the name of an SMI handler and appeared as one in the inventory on EVAL-1
            // run 42310220335. A handler slot holds a function and a GUID slot holds a
            // variable, and requiring that costs nothing on the shapes that were already
            // working.
            //
            switch(arg) {
                case SMIParam::FunctionHandle:
                    if (isa<FunctionDecl>(DRE->getDecl())) {
                        CurrentFunction = DRE->getDecl()->getNameAsString();
                    }
                    break;
                case SMIParam::Guid:
                    if (isa<VarDecl>(DRE->getDecl())) {
                        CurrentInfo.Guid = DRE->getDecl()->getNameAsString();
                    }
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
        The array a table-driven registration reads its handlers out of, or nullptr.

        Matches the shape the SMM core and several platform drivers use:

            SmiHandlerRegister (mSmmCoreSmiHandlers[Index].Handler,
                                mSmmCoreSmiHandlers[Index].HandlerType, ...)

        There is no handler name in that expression -- it is a field of whichever row the
        loop is on -- so the names live in the array's initialiser and nowhere else. With
        ParseArg narrowed above, such a call records nothing at all, which is correct but
        loses seven real handlers on EVAL-1: SmmDriverDispatchHandler, SmmReadyToLockHandler,
        SmmLegacyBootHandler, SmmExitBootServicesHandler, SmmReadyToBootHandler,
        SmmEndOfDxeHandler and SmmS3SmmInitDoneHandler. Each is registered against a GUID
        and dispatched by SmiManage, so an SmmCommunicate carrying that GUID reaches it the
        same way any other comm-buffer handler is reached.
    */
    const VarDecl *handlerTable(Expr *E) {
        if (!E) return nullptr;
        E = E->IgnoreParenCasts();
        const MemberExpr *Member = dyn_cast<MemberExpr>(E);
        if (Member == nullptr) {
            return nullptr;
        }
        const Expr *Base = Member->getBase();
        if (Base == nullptr) return nullptr;
        Base = Base->IgnoreParenCasts();
        const ArraySubscriptExpr *Sub = dyn_cast<ArraySubscriptExpr>(Base);
        if (Sub == nullptr) {
            return nullptr;
        }
        const Expr *Arr = Sub->getBase();
        if (Arr == nullptr) return nullptr;
        Arr = Arr->IgnoreParenCasts();
        const DeclRefExpr *Ref = dyn_cast<DeclRefExpr>(Arr);
        if (Ref == nullptr) {
            return nullptr;
        }
        const VarDecl *Var = dyn_cast<VarDecl>(Ref->getDecl());
        if (Var == nullptr || !Var->hasInit()) {
            return nullptr;
        }
        return Var;
    }

    /*
        Every (handler, GUID) pair in a table's initialiser.

        Taken by shape rather than by field index: the row is read for the first element
        that names a function and the first that takes the address of a variable, so a
        table whose fields are declared in another order, or which carries extra fields
        like the DispatchHandle and the BOOLEAN the SMM core's rows end with, still
        resolves. The trailing { NULL, NULL, ... } terminator names neither and is skipped
        by the same rule rather than by counting rows.
    */
    void expandHandlerTable(const VarDecl *Table, const std::string &Kind) {
        const Expr *Init = Table->getInit();
        if (Init == nullptr) return;
        const InitListExpr *Rows = dyn_cast<InitListExpr>(Init->IgnoreParenCasts());
        if (Rows == nullptr) return;

        for (unsigned Row = 0; Row < Rows->getNumInits(); Row++) {
            const Expr *RowExpr = Rows->getInit(Row);
            if (RowExpr == nullptr) continue;
            const InitListExpr *Fields =
                dyn_cast<InitListExpr>(RowExpr->IgnoreParenCasts());
            if (Fields == nullptr) continue;

            std::string Handler;
            std::string Guid;
            for (unsigned Field = 0; Field < Fields->getNumInits(); Field++) {
                const Expr *Value = Fields->getInit(Field);
                if (Value == nullptr) continue;
                Value = Value->IgnoreParenCasts();
                if (const DeclRefExpr *Ref = dyn_cast<DeclRefExpr>(Value)) {
                    if (Handler.empty() && isa<FunctionDecl>(Ref->getDecl())) {
                        Handler = Ref->getDecl()->getNameAsString();
                    }
                    continue;
                }
                if (const UnaryOperator *Addr = dyn_cast<UnaryOperator>(Value)) {
                    if (Addr->getOpcode() != UO_AddrOf) continue;
                    const Expr *Of = Addr->getSubExpr();
                    if (Of == nullptr) continue;
                    if (const DeclRefExpr *Ref =
                            dyn_cast<DeclRefExpr>(Of->IgnoreParenCasts())) {
                        if (Guid.empty() && isa<VarDecl>(Ref->getDecl())) {
                            Guid = Ref->getDecl()->getNameAsString();
                        }
                    }
                }
            }

            if (Handler.empty()) {
                continue;
            }
            if (SmiFunctionSet.find(Handler) != SmiFunctionSet.end()) {
                continue;
            }
            SmiFunctionSet.insert(Handler);
            SmiInfo Info;
            Info.Guid = Guid;
            Info.Dispatch = Kind;
            SmiFunctionGuidMap[Handler] = Info;
        }
    }


    /*
        TODO: Take into account if the function handler is being stored in a structure of other handlers
    */
    bool VisitCallExpr(CallExpr *call) {
        std::string Kind = matchedRegistration(call, *this->Context);
        if(!Kind.empty())
        {
            //
            // The handler is argument 0 of SmiHandlerRegister and argument 1 of every
            // dispatch protocol's Register, which takes This first. ParseArg keys on the
            // SMIParam positions, so the arguments are shifted into those positions rather
            // than teaching ParseArg a second layout: shifting by one maps
            // (This, DispatchFunction, RegisterContext) onto
            // (FunctionHandle, Guid, DispatchContext), which puts the handler where
            // ParseArg expects it and leaves RegisterContext in a slot ParseArg ignores.
            //
            // A dispatcher registration has no GUID at all -- its key is a SwMmiInputValue
            // or an S-state -- so the Guid slot is cleared afterwards rather than being
            // filled with whatever argument happened to land there.
            //
            const unsigned Shift = handlerArgIndex(Kind);
            for (unsigned i = Shift; i < call->getNumArgs(); i++) {
                ParseArg(call->getArg(i)->IgnoreCasts(), i - Shift);
            }
            if (Kind != "SmiHandlerRegister") {
                CurrentInfo.Guid.clear();
            }
            CurrentInfo.Dispatch = Kind;

            //
            // A root handler: registered with HandlerType NULL, so SmiManage calls it on
            // EVERY MMI whatever GUID the header carries, and by contract its CommBuffer
            // is ignored. Two in EVAL-1 -- CpuHotplugMmi ("CommBuffer Ignored, due to
            // CpuHotplugMmi() being a root MMI handler") and SmmSwDispatcher, registered
            // as (..., NULL, &DispatchHandle).
            //
            // Both were previously reported as "dropped for an unresolved CommBuffer type",
            // which sends a reader to look for a type that does not exist. There is no GUID
            // to address them with and no buffer they read, so there is nothing a
            // comm-buffer harness can do with either -- a different statement from "the
            // analyser could not work out the type".
            //
            if (Kind == "SmiHandlerRegister" &&
                CurrentInfo.Guid.empty() &&
                (Shift + 1) < call->getNumArgs())
            {
                const Expr *Type = call->getArg(Shift + 1);
                if (Type != nullptr &&
                    Type->isNullPointerConstant(*this->Context,
                                                Expr::NPC_ValueDependentIsNotNull))
                {
                    CurrentInfo.Dispatch = "RootHandler";
                }
            }

            //
            // Nothing in the argument named a function, so this is either a table-driven
            // registration -- whose names are in the array's initialiser, not here -- or a
            // shape not handled. Try the table before giving up; expandHandlerTable records
            // its own entries and leaves CurrentFunction empty, so the single-handler path
            // below still does nothing.
            //
            if (CurrentFunction.empty() && Shift < call->getNumArgs()) {
                const VarDecl *Table = handlerTable(call->getArg(Shift));
                if (Table != nullptr) {
                    expandHandlerTable(Table, Kind);
                }
            }
            if(!CurrentFunction.empty() && SmiFunctionSet.find(CurrentFunction) == SmiFunctionSet.end()) {
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