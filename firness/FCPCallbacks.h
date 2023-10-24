#ifndef __FCP_CALLBACKS_H__
#define __FCP_CALLBACKS_H__

#include "Globals.h"

class FCPCallbacks : public PPCallbacks {
public:

    explicit FCPCallbacks(SourceManager &SM) : SM(SM) {}

    void MacroDefined(const Token &MacroNameTok, const MacroDirective *MD) override {
        StringRef MacroName = MacroNameTok.getIdentifierInfo()->getName();

        PreDefinedConstants.push_back(MacroName.str());
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

        IncludeDirectives.insert(FileName.str());
    }

private:
  SourceManager &SM;
};

#endif