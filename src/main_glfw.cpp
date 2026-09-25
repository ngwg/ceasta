// linux (x11 / wayland) and macos gui entry point: glfw + opengl3, around the same app_init /
// app_frame the windows build uses.
#include "app.h"
#include "core/os.h"
#include "theme.h"
#include "version.h"

#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"

#ifdef __APPLE__
#define GL_SILENCE_DEPRECATION // opengl still works on macos, it's only marked old
#include <GLFW/glfw3.h>        // brings in <OpenGL/gl.h>
// mac_platform.mm
std::string mac_open_file_dialog(const char* title);
std::string mac_save_file_dialog(const char* title, const std::string& suggested);
void mac_fix_menu();
#else
#include <GLFW/glfw3.h>
#include <GL/gl.h>
#endif

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

// a modal panel swallows the mouse button's release: nothing stays held down after one
static void after_modal()
{
    ImGuiIO& io = ImGui::GetIO();
    io.ClearInputKeys();
    io.ClearInputMouse();
}

// file dialogs: the system's panels on macos; zenity / kdialog when present elsewhere, otherwise
// empty (drag and drop and the command line still work)
static std::string open_file_dialog(const char* title)
{
#ifdef __APPLE__
    std::string r = mac_open_file_dialog(title);
    after_modal();
    return r;
#endif
    std::string t = shell_quote(title ? title : "Open"), tool = dialog_tool();
    if (tool == "zenity")
        return run_dialog("zenity --file-selection --title=" + t + " 2>/dev/null");
    if (tool == "kdialog")
        return run_dialog("kdialog --getopenfilename . --title " + t + " 2>/dev/null");
    return std::string();
}

static std::string save_file_dialog(const char* title, const std::string& suggested)
{
#ifdef __APPLE__
    std::string r = mac_save_file_dialog(title, suggested);
    after_modal();
    return r;
#endif
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
    for (int i = 1; i < argc; i++) {
        std::string a = argv[i];
        if (a == "--version" || a == "-v") {
            std::printf("ceasta %s\n", CEASTA_VERSION);
            return 0;
        }
        if (a == "--help" || a == "-h") {
            std::printf("ceasta %s - disassembler, decompiler and debugger\n\n"
                        "usage: ceasta [file]    opens the file (a program, a .ceasta database or project)\n"
                        "the command line tool is ceasta-cli.\n",
                CEASTA_VERSION);
            return 0;
        }
        if (a.compare(0, 5, "-psn_") == 0)
            continue; // what older macos adds when finder starts an app
        args.push_back(a);
    }

    glfwSetErrorCallback(glfw_error);
    if (!glfwInit()) {
        std::fprintf(stderr, "couldn't start glfw (no display?)\n");
        return 1;
    }
#ifdef __APPLE__
    // macos only gives a modern context as 3.2 core, forward compatible (glsl 150)
    mac_fix_menu();
    const char* glsl_version = "#version 150";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 2);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_OPENGL_FORWARD_COMPAT, GL_TRUE);
#else
    // opengl 3.0 + glsl 130, the imgui opengl3 backend's baseline
    const char* glsl_version = "#version 130";
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 0);
#endif
    // the desktop matches the window to ceasta.desktop (its icon, its name) by this class
    glfwWindowHintString(GLFW_X11_CLASS_NAME, "ceasta");
    glfwWindowHintString(GLFW_X11_INSTANCE_NAME, "ceasta");
#ifdef GLFW_WAYLAND_APP_ID
    glfwWindowHintString(GLFW_WAYLAND_APP_ID, "ceasta");
#endif

    GLFWwindow* window = glfwCreateWindow(1280, 800, "ceasta", nullptr, nullptr);
    if (!window) {
        // the usual reason: no opengl 3 with hardware behind it (a virtual machine without 3d)
        std::fprintf(stderr, "couldn't create a window: no opengl 3 here (no graphics driver, or a virtual machine "
                             "without 3d acceleration). ceasta-cli works without one\n");
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

    // 1 on macos, where the window works in points and a retina screen just has more pixels per
    // point (imgui draws its fonts at that density); the monitor's scale on x11
    float scale = ImGui_ImplGlfw_GetContentScaleForWindow(window);
    if (!(scale > 0))
        scale = 1.0f;

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
        // while minimized, don't render, but keep the debugger (and the ai server) going
        if (glfwGetWindowAttrib(window, GLFW_ICONIFIED)) {
            app_background(state);
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
