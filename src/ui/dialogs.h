#pragma once
#include "app.h"

// modal popups: jump, rename, comment, xrefs, byte search, open raw, attach, ...
namespace dialogs {
void open(app_state& state, dialog_kind kind, uint64_t addr);
void draw(app_state& state);
}
