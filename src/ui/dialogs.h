#pragma once
#include "app.h"

// modal popups: jump, rename, comment, xrefs, byte search, open raw, attach, ...
namespace dialogs {
void open(app_state& state, dialog_kind kind, uint64_t addr);
void draw(app_state& state);
// the c types dialog, showing one of them
void show_type(app_state& state, const std::string& name);
}
