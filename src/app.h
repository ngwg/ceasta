#pragma once

struct app_state {
    bool show_left = true;
    bool show_view = true;
    bool show_right = true;
    bool show_bottom = true;
    bool show_regs = true;
    bool show_demo = false;
    bool graph_mode = false;
    char filter[128] = {};
    char jump_buf[32] = {};
    int selected_func = 1;
    int selected_line = 4;
    int left_tab = 0;
    int right_tab = 0;
    int bottom_tab = 0;
    char log_buf[8192] = {};
    int log_len = 0;
    char file_name[256] = "sample.exe";
    bool layout_done = false;
};

void app_init(app_state& state);
void app_render(app_state& state);
void app_log(app_state& state, const char* text);
