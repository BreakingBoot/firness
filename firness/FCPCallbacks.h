#ifndef __FCP_CALLBACKS_H__
#define __FCP_CALLBACKS_H__

#include "Globals.h"

class FCPCallbacks : public clang::PPCallbacks {
public:
    void MacroDefined(const clang::Token &MacroNameTok, const clang::MacroDirective *MD) override {
        clang::StringRef MacroName = MacroNameTok.getIdentifierInfo()->getName();

        PreDefinedConstants.push_back(MacroName.str());
    }
};

#endif