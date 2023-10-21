#ifndef __PASS_HELPERS_H__
#define __PASS_HELPERS_H__

#include "Globals.h"

namespace PassHelpers {

    /*
        Get the source code level string of the given Expr
    */
    std::string getSourceCode(Expr *E, ASTContext &Context)
    {
        if (!E) return "";
        SourceManager &SM = Context.getSourceManager();
        const LangOptions &LangOpts = Context.getLangOpts();
        CharSourceRange Range = CharSourceRange::getTokenRange(E->getSourceRange());
        std::string ExprText = Lexer::getSourceText(Range, SM, LangOpts).str();

        return ExprText;
    }

    /*
        Print out the given expression to stdout
    */
    void PrintExpr(Expr *E, ASTContext &Context)
    {
        llvm::outs() << E->getStmtClassName() << ": " << getSourceCode(E, Context) << "\n";
    }

    /*
        Gets the Line number of a given Expr
    */
    unsigned getLineNumber(Expr *E, ASTContext &Context) {
        SourceManager &SM = Context.getSourceManager();
        SourceLocation Loc = E->getExprLoc();
        if (Loc.isValid()) {
            return SM.getExpansionLineNumber(Loc);
        }
        return 0;
    }

    /*
        Eliminates the extra whitespace for new lines//extra spaces
        in a given string
    */
    std::string reduceWhitespace(const std::string& str) {
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

}; // PassHelpers namespace

#endif