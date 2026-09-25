#pragma once
#include "app.h"

namespace pseudo_view {
void draw(app_state& state);
// the word you clicked in the pseudocode: N renames it (a variable, or what it names in the file),
// Y sets its type (a variable) or edits a prototype (the function, a function it calls), Enter
// jumps to what it names. false when there's nothing to do with it
bool rename_selected(app_state& s);
bool retype_selected(app_state& s);
bool follow_selected(app_state& s);
// stops kuna if it's still working (at exit)
void shutdown();
}
