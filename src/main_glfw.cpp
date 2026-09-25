// linux (and any x11 / wayland) gui entry point: glfw + opengl3, around the same app_init /
// app_frame the windows build uses. experimental - the windows build is the primary gui.
#include "app.h"
#include "core/os.h"
#include "theme.h"

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

#include <GLFW/glfw3.h>
#include <GL/gl.h>

#include <cstdio>
#include <cstdlib>
#include <string>
#include <vector>

// one argument for sh: single quotes, with any ' inside closed, escaped and reopened
static std::string shell_quote(const std::string& s)
{
    std::string o = "'";
    for (char c : s)
        o += c == '\'' ? std::string("'\\''") : std::string(1, c);
    return o + "'";
}

// the desktop's file dialog tool: zenity, else kdialog, else none ("")
static const char* dialog_tool()
{
    static const char* tool = std::system("command -v zenity >/dev/null 2>&1") == 0    ? "zenity"
                              : std::system("command -v kdialog >/dev/null 2>&1") == 0 ? "kdialog"
                                                                                        : "";
    return tool;
}

// runs a dialog command, returns what it printed ("" when cancelled)
static std::string run_dialog(const std::string& cmd)
{
    FILE* p = popen(cmd.c_str(), "r");
    if (!p)
        return std::string();
    std::string out;
    char buf[1024];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), p)) > 0)
        out.append(buf, n);
    int rc = pclose(p);
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r'))
        out.pop_back();
    return rc == 0 ? out : std::string();
}

// file dialogs through zenity / kdialog when present; otherwise empty (drag and drop and the
// command line still work)
static std::string open_file_dialog(const char* title)
{
    std::string t = shell_quote(title ? title : "Open"), tool = dialog_tool();
    if (tool == "zenity")
        return run_dialog("zenity --file-selection --title=" + t + " 2>/dev/null");
    if (tool == "kdialog")
        return run_dialog("kdialog --getopenfilename . --title " + t + " 2>/dev/null");
    return std::string();
}

static std::string save_file_dialog(const char* title, const std::string& suggested)
{
    std::string t = shell_quote(title ? title : "Save"), f = shell_quote(suggested), tool = dialog_tool();
    if (tool == "zenity")
        return run_dialog("zenity --file-selection --save --title=" + t + " --filename=" + f + " 2>/dev/null");
    if (tool == "kdialog")
        return run_dialog("kdialog --getsavefilename " + f + " --title " + t + " 2>/dev/null");
    return std::string();
}

// the close button: with unsaved changes, ask first (the answer closes through platform.quit)
static void close_callback(GLFWwindow* w)
{
    app_state* s = (app_state*)glfwGetWindowUserPointer(w);
    if (s && !app_request_close(*s))
        glfwSetWindowShouldClose(w, GLFW_FALSE);
}

static void drop_callback(GLFWwindow* w, int count, const char** paths)
{
    app_state* s = (app_state*)glfwGetWindowUserPointer(w);
    if (s && count > 0)
        app_open(*s, paths[0]);
}

static void glfw_error(int code, const char* desc) { std::fprintf(stderr, "glfw error %d: %s\n", code, desc); }

int main(int argc, char** argv)
{
    std::vector<std::string> args;
    for (int i = 1; i < argc; i++)
        args.push_back(argv[i]);

    glfwSetErrorCallback(glfw_error);
    if (!glfwInit()) {
        std::fprintf(stderr, "couldn't start glfw (no display?)\n");
        return 1;
    }
    // opengl 3.0 + glsl 130, the imgui opengl3 backend's baseline
    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);

    GLFWwindow* window = glfwCreateWindow(1280, 800, "ceasta", nullptr, nullptr);
    if (!window) {
        std::fprintf(stderr, "couldn't create a window\n");
        glfwTerminate();
        return 1;
    }
    glfwMakeContextCurrent(window);
    glfwSwapInterval(1); // vsync

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr; // our own settings.ini lives in the user folder

    float xscale = 1.0f, yscale = 1.0f;
    glfwGetWindowContentScale(window, &xscale, &yscale);
    float scale = xscale > 0 ? xscale : 1.0f;

    theme::apply_theme();
    ImGuiStyle& style = ImGui::GetStyle();
    style.ScaleAllSizes(scale);
    style.FontScaleDpi = scale;
    theme::load_fonts();

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init(glsl_version);

    static app_state state;
    state.dpi_scale = scale;
    glfwSetWindowUserPointer(window, &state);
    glfwSetDropCallback(window, drop_callback);
    glfwSetWindowCloseCallback(window, close_callback);

    platform_api platform;
    platform.open_file_dialog = open_file_dialog;
    platform.save_file_dialog = save_file_dialog;
    platform.set_title = [window](const std::string& t) { glfwSetWindowTitle(window, t.c_str()); };
    platform.quit = [window]() { glfwSetWindowShouldClose(window, 1); };
    app_init(state, platform, args);

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        // while minimized, don't render, but keep the debugger moving
        if (glfwGetWindowAttrib(window, GLFW_ICONIFIED)) {
            if (state.dbg.state() == dbg_state::running)
                state.dbg.poll(10);
            else
                os::sleep_ms(10);
            continue;
        }

        app_pre_frame(state);
        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();
        app_frame(state);
        ImGui::Render();

        int w = 0, h = 0;
        glfwGetFramebufferSize(window, &w, &h);
        glViewport(0, 0, w, h);
        glClearColor(0.07f, 0.08f, 0.10f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());
        glfwSwapBuffers(window);
    }

    app_shutdown(state);
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}
