class FCPConsumer : public clang::ASTConsumer {
public:
    explicit FCPConsumer(ASTContext *Context)
        : VariableVisitor(Context), FunctionVisitor(Context) {}

    void HandleTranslationUnit(clang::ASTContext &Context) override {
        VariableVisitor.TraverseDecl(Context.getTranslationUnitDecl());
        FunctionVisitor.TraverseDecl(Context.getTranslationUnitDecl());
    }
private:
    VarDeclVisitor VariableVisitor;
    CallExprVisitor FunctionVisitor;
};