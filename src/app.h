#pragma once

struct app_state {
    bool show_functions = true;
    bool show_disasm = true;
    bool show_hex = true;
    bool show_strings = true;
    bool show_log = true;
    bool show_regs = true;
    bool show_demo = false;
    char filter[128] = {};
    int selected_func = 1;
    int selected_line = 4;
    char log_buf[8192] = {};
    int log_len = 0;
    char file_name[256] = "sample.exe";
};

void app_init(app_state& state);
void app_render(app_state& state);
void app_log(app_state& state, const char* text);
