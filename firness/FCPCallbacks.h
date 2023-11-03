#ifndef __FCP_CALLBACKS_H__
#define __FCP_CALLBACKS_H__

#include "Globals.h"

class FCPCallbacks : public PPCallbacks {
public:

    explicit FCPCallbacks(SourceManager &SM) : SM(SM) {}

    // void MacroDefined(const Token &MacroNameTok, const MacroDirective *MD) override {
    //     StringRef MacroName = MacroNameTok.getIdentifierInfo()->getName();

    //     PreDefinedConstants.push_back(MacroName.str());
    // }
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
                mac.File = FilePath.str();
                mac.Value = MacroNameTok.getName();

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

        IncludeDirectives.insert(FullPath);
        
        // IncludeDirectives.insert(FileName.str());
    }

private:
  SourceManager &SM;
};

#endif