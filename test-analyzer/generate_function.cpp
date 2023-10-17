// #include <clang/AST/ASTContext.h>
// #include <clang/AST/Stmt.h>
// #include <clang/Basic/SourceManager.h>
// #include <clang/Basic/TargetInfo.h>
// #include <clang/Frontend/CompilerInstance.h>
// #include <clang/Lex/Preprocessor.h>
// #include <llvm/Support/raw_ostream.h>
// #include <fstream>


// void printFunction(std::ofstream &out, clang::FunctionDecl *func) {
//     // Print the return type
//     out << "int ";

//     // Print the function name
//     out << func->getNameInfo().getName().getAsString();

//     // Print parameters (none for now)
//     out << "() {\n";

//     // Print body (just the simple cases handled here)
//     for (auto stmt : func->getBody()->body()) {
//         if (clang::isa<clang::DeclStmt>(stmt)) {
//             out << "\tint data1 = 42;\n";  // hardcoded for simplicity
//         } else if (clang::isa<clang::ReturnStmt>(stmt)) {
//             out << "\treturn 0;\n";
//         }
//     }

//     out << "}\n";
// }

// int main() {
//     clang::CompilerInstance compiler;
//     compiler.createDiagnostics();

//     std::shared_ptr<clang::TargetOptions> pto = std::make_shared<clang::TargetOptions>();
//     pto->Triple = compiler.getTargetOpts().Triple;
//     clang::TargetInfo *pti = clang::TargetInfo::CreateTargetInfo(compiler.getDiagnostics(), pto);
//     compiler.setTarget(pti);

//     clang::ASTContext astContext(compiler.getLangOpts(), compiler.getSourceManager(),
//         compiler.getPreprocessor().getIdentifierTable(), compiler.getPreprocessor().getSelectorTable(), compiler.getPreprocessor().getBuiltinInfo());

//     // Create the function
//     clang::IdentifierInfo &fooIdent = astContext.Idents.get("foo");
//     clang::FunctionDecl *func = clang::FunctionDecl::Create(astContext, astContext.getTranslationUnitDecl(),
//         clang::SourceLocation(), clang::SourceLocation(), &fooIdent, astContext.IntTy, nullptr, clang::SC_None);

//     // Create the body of the function (CompoundStmt)
//     clang::CompoundStmt *funcBody = clang::CompoundStmt::Create(astContext, {}, clang::SourceLocation(), clang::SourceLocation());


//     // Add variable declaration: data1.type data1 = data1.value;
//     // For illustration, assuming type is int and value is 42
//     clang::VarDecl *varDecl = clang::VarDecl::Create(astContext, func, clang::SourceLocation(), clang::SourceLocation(), &astContext.Idents.get("data1"), astContext.IntTy, nullptr, clang::SC_None);
//     clang::IntegerLiteral *initValue = clang::IntegerLiteral::Create(astContext, llvm::APInt(32, 42), astContext.IntTy, clang::SourceLocation());
//     varDecl->setInit(initValue);
//     clang::DeclStmt *declStmt = new (astContext) clang::DeclStmt(clang::DeclGroupRef(varDecl), clang::SourceLocation(), clang::SourceLocation());

//     funcBody->addStmt(declStmt);

//     // Add return statement
//     clang::ReturnStmt *returnStmt = new (astContext) clang::ReturnStmt(astContext, clang::IntegerLiteral::Create(astContext, llvm::APInt(32, 0), astContext.IntTy, clang::SourceLocation()), clang::SourceLocation(), nullptr);
//     funcBody->addStmt(returnStmt);

//     func->setBody(funcBody);

//     // TODO: Add the function call 'functioncall(data1, data2, ....);'
//     // This would involve creating a CallExpr and adding it to the funcBody.
//     // 1. Include the header
//     std::ofstream outputFile("generatedCode.cpp");
//     outputFile << "#include \"function.h\"" << std::endl;


//     // 2. Declare and define the global structure with the function pointer
//     clang::RecordDecl *structDecl = clang::RecordDecl::Create(astContext, clang::TagDecl::Kind::TK_struct, astContext.getTranslationUnitDecl(),
//         clang::SourceLocation(), clang::SourceLocation(), &astContext.Idents.get("GlobalStruct"));

//     clang::FieldDecl *functionField = clang::FieldDecl::Create(astContext, structDecl, clang::SourceLocation(), clang::SourceLocation(),
//         &astContext.Idents.get("functioncall"), /*Type=*/ nullptr, /*TypeSourceInfo=*/ nullptr, /*BitWidth=*/ nullptr, /*Mutable=*/ false, clang::ICIS_NoInit);

//     structDecl->addDecl(functionField);
//     astContext.getTranslationUnitDecl()->addDecl(structDecl);

//     // 3. Access the function through the global pointer
//     // ... Assume we're inside the function body
//     clang::DeclRefExpr *structRef = new (astContext) clang::DeclRefExpr(astContext, structDecl, false, clang::SourceLocation(), clang::SourceLocation(), clang::VK_LValue, clang::OK_Ordinary);
//     clang::MemberExpr *functionAccess = new (astContext) clang::MemberExpr(structRef, false, clang::SourceLocation(), functionField, clang::SourceLocation(), functionField->getType(), clang::VK_LValue, clang::OK_Ordinary, clang::NOUR_None);

//     // Here, `functionAccess` gives you a reference to `variable->functioncall`. You'd then create a CallExpr with this to invoke the function.



//     // Printing the function's name for simplicity (you'd need to traverse the AST to generate full code)
//     std::ofstream outputFile("generatedCode.cpp");
//     outputFile << "#include \"function.h\"" << std::endl;

//     printFunction(outputFile, func);

//     return 0;
// }
#include <clang/AST/ASTContext.h>
#include <clang/AST/Stmt.h>
#include <clang/Basic/SourceManager.h>
#include <clang/Frontend/CompilerInstance.h>
#include <llvm/Support/raw_ostream.h>

// A function to traverse a statement and print corresponding code
void PrintStmt(const clang::Stmt *S) {
    if (!S) return;

    if (const clang::ReturnStmt *RS = clang::dyn_cast<clang::ReturnStmt>(S)) {
        llvm::outs() << "return ";
        PrintStmt(RS->getRetValue());
        llvm::outs() << ";\n";
    } else if (const clang::IntegerLiteral *IL = clang::dyn_cast<clang::IntegerLiteral>(S)) {
        llvm::outs() << IL->getValue();
    } else {
        for (const auto *Child : S->children()) {
            PrintStmt(Child);
        }
    }
}

int main() {
    clang::CompilerInstance compiler;
    compiler.createDiagnostics();

    // Setting up the TargetInfo (as you've started)
    std::shared_ptr<clang::TargetOptions> pto = std::make_shared<clang::TargetOptions>();
    pto->Triple = llvm::sys::getDefaultTargetTriple();
    clang::TargetInfo *pti = clang::TargetInfo::CreateTargetInfo(compiler.getDiagnostics(), pto);

    // Create the ASTContext using the necessary components
    clang::ASTContext astContext(
        compiler.getLangOpts(),
        compiler.getSourceManager(),
        pti,
        compiler.getPreprocessor().getIdentifierTable(),
        compiler.getPreprocessor().getSelectorTable(),
        compiler.getPreprocessor().getBuiltinInfo()
    );


    // Create a simple function
    clang::IdentifierInfo &funcIdent = astContext.Idents.get("exampleFunction");
    clang::FunctionDecl *func = clang::FunctionDecl::Create(astContext, astContext.getTranslationUnitDecl(),
        clang::SourceLocation(), clang::SourceLocation(), &funcIdent, astContext.IntTy, nullptr, clang::SC_None);

    // Create the body of the function
    clang::CompoundStmt *funcBody = new (astContext) clang::CompoundStmt(astContext, {}, clang::SourceLocation(), clang::SourceLocation());
    
    // Add a return statement with the value 42
    clang::ReturnStmt *returnStmt = new (astContext) clang::ReturnStmt(astContext, clang::IntegerLiteral::Create(astContext, llvm::APInt(32, 42), astContext.IntTy, clang::SourceLocation()), clang::SourceLocation(), nullptr);
    funcBody->addStmt(returnStmt);
    func->setBody(funcBody);

    // Print out the generated function
    llvm::outs() << "int " << func->getNameInfo().getName().getAsString() << "() {\n";
    PrintStmt(func->getBody());
    llvm::outs() << "}\n";

    return 0;
}
