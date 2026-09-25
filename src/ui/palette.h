#pragma once
#include "app.h"

// the command palette (ctrl+shift+p): every action in one searchable list, with its keys, so
// the things used now and then don't need a button of their own
namespace palette {

void draw(app_state& s, dialog_state& d); // the dialog's body
void run(app_state& s, int index);        // the picked action, once the dialog has closed

}
