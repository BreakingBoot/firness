#ifndef __FCP_CALLBACKS_H__
#define __FCP_CALLBACKS_H__

#include "Globals.h"

class FCPCallbacks : public PPCallbacks {
public:

    explicit FCPCallbacks(SourceManager &SM, ASTContext *Context) : SM(SM), Context(Context) {}


    std::string filterMacroDefinition(const std::string &name, const std::string &value) {
        size_t pos = value.find(name);
        if (pos != std::string::npos) {
            // Find the space character after the name
            size_t spacePos = value.find(' ', pos + name.length());
            std::string filteredValue = value.substr(spacePos + 1);

            // Remove backslashes and spaces from the filteredValue
            std::string filteredResult;
            bool foundBackslash = false;
            for (char c : filteredValue) {
                if (c == '\\') {
                    foundBackslash = true;
                } else if (!isspace(c) || (isspace(c) && !foundBackslash)) {
                    foundBackslash = false;
                    filteredResult += c;
                }
            }

            return filteredResult;
        }
        return value;
    }

    void MacroDefined(const Token &MacroNameTok, const MacroDirective *MD) override {
        StringRef MacroName = MacroNameTok.getIdentifierInfo()->getName();

        SourceLocation MacroLoc = MD->getMacroInfo()->getDefinitionLoc();

        FileID FID = SM.getFileID(MacroLoc);
        const FileEntry *FE = SM.getFileEntryForID(FID);
        if (FE) {
            StringRef FilePath = FE->tryGetRealPathName();
            if (!FilePath.empty()) {
                MacroDef mac;
                mac.Name = MacroName.str();
                // remove the first 6 directories from the path
                std::string ShortPath = FilePath.str();
                size_t pos = ShortPath.find('/');
                for (int i = 0; i < 6; i++) {
                    pos = ShortPath.find('/', pos + 1);
                }
                ShortPath = ShortPath.substr(pos + 1);
                mac.File = ShortPath;

                const LangOptions &LangOpts = Context->getLangOpts();
                CharSourceRange Range = CharSourceRange::getTokenRange(MD->getMacroInfo()->getDefinitionLoc(), MD->getMacroInfo()->getDefinitionEndLoc());
                mac.Value = Lexer::getSourceText(Range, SM, LangOpts).str();
                mac.Value = PassHelpers::reduceWhitespace(filterMacroDefinition(mac.Name, mac.Value));

                PreDefinedConstants[MacroName.str()] = mac;
            }
        }
    }

    void InclusionDirective (SourceLocation HashLoc, 
                            const Token & IncludeTok, 
                            StringRef FileName, 
                            bool IsAngled, 
                            CharSourceRange FilenameRange, 
                            Optional<clang::FileEntryRef> File, 
                            StringRef SearchPath, 
                            StringRef RelativePath, 
                            const Module * Imported, 
                            SrcMgr::CharacteristicKind FileType) override {
        // Need to also track the function calls -> include directives
        // Store the full path and other information as needed.
        std::string FullPath = SearchPath.str() + "/" + FileName.str();
        // IncludeDirectives.insert(FullPath);
        if("AutoGen.h" != FileName.str())
            IncludeDirectives.insert(FullPath);
    }

private:
    ASTContext *Context;
    SourceManager &SM;
};

#endif