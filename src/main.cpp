// windows host: win32 window + directx 11 + dear imgui. everything else lives in app.cpp
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <commdlg.h>
#include <shellapi.h>
#include <d3d11.h>

#include "app.h"
#include "core/os.h"
#include "imgui.h"
#include "imgui_impl_dx11.h"
#include "imgui_impl_win32.h"
#include "theme.h"

static ID3D11Device* g_device = nullptr;
static ID3D11DeviceContext* g_context = nullptr;
static IDXGISwapChain* g_swapchain = nullptr;
static ID3D11RenderTargetView* g_target = nullptr;
static bool g_occluded = false;
static unsigned int g_resize_w = 0, g_resize_h = 0;
static HWND g_hwnd = nullptr;
static app_state* g_app = nullptr;

static bool create_device(HWND hwnd);
static void cleanup_device();
static void create_target();
static void cleanup_target();
static LRESULT WINAPI wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);

static std::string open_file_dialog(const char* title)
{
    wchar_t file[32768] = L"";
    std::wstring wtitle = os::widen(title);
    OPENFILENAMEW ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd;
    ofn.lpstrFilter = L"Programs, libraries and projects (*.exe;*.dll;*.sys;*.ocx;*.elf;*.so;*.bin;*.ceasta)\0*.exe;*.dll;*.sys;*.ocx;*.elf;*.so;*.bin;*.ceasta\0"
                      L"ceasta projects (*.ceasta)\0*.ceasta\0All files (*.*)\0*.*\0";
    ofn.lpstrFile = file;
    ofn.nMaxFile = sizeof(file) / sizeof(file[0]);
    ofn.lpstrTitle = wtitle.c_str();
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_EXPLORER | OFN_NOCHANGEDIR;
    if (!GetOpenFileNameW(&ofn))
        return std::string();
    return os::narrow(file);
}

static std::string save_file_dialog(const char* title, const std::string& suggested)
{
    wchar_t file[32768] = L"";
    std::wstring start = os::widen(suggested);
    size_t n = start.size() < 32767 ? start.size() : 32767;
    for (size_t i = 0; i < n; i++)
        file[i] = start[i];
    file[n] = 0;
    std::wstring wtitle = os::widen(title);
    OPENFILENAMEW ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hwnd;
    ofn.lpstrFilter = L"ceasta projects (*.ceasta)\0*.ceasta\0All files (*.*)\0*.*\0";
    ofn.lpstrDefExt = L"ceasta";
    ofn.lpstrFile = file;
    ofn.nMaxFile = sizeof(file) / sizeof(file[0]);
    ofn.lpstrTitle = wtitle.c_str();
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST | OFN_EXPLORER | OFN_NOCHANGEDIR;
    if (!GetSaveFileNameW(&ofn))
        return std::string();
    return os::narrow(file);
}

int WINAPI WinMain(HINSTANCE instance, HINSTANCE, LPSTR, int)
{
    ImGui_ImplWin32_EnableDpiAwareness();
    float scale = ImGui_ImplWin32_GetDpiScaleForMonitor(::MonitorFromPoint(POINT{0, 0}, MONITOR_DEFAULTTOPRIMARY));

    // utf-16 command line, so paths with any characters work
    std::vector<std::string> args;
    int argc = 0;
    if (LPWSTR* argv = CommandLineToArgvW(GetCommandLineW(), &argc)) {
        for (int i = 1; i < argc; i++)
            args.push_back(os::narrow(argv[i]));
        LocalFree(argv);
    }

    WNDCLASSEXW wc;
    ZeroMemory(&wc, sizeof(wc));
    wc.cbSize = sizeof(wc);
    wc.style = CS_CLASSDC;
    wc.lpfnWndProc = wnd_proc;
    wc.hInstance = instance;
    wc.hIcon = LoadIconW(instance, MAKEINTRESOURCEW(1));
    wc.hIconSm = wc.hIcon;
    wc.hCursor = LoadCursorW(nullptr, IDC_ARROW);
    wc.lpszClassName = L"ceasta";
    ::RegisterClassExW(&wc);
    g_hwnd = ::CreateWindowExW(WS_EX_ACCEPTFILES, wc.lpszClassName, L"ceasta", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT,
        (int)(1440 * scale), (int)(900 * scale), nullptr, nullptr, instance, nullptr);

    if (!create_device(g_hwnd)) {
        cleanup_device();
        ::DestroyWindow(g_hwnd);
        ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
        MessageBoxW(nullptr, L"Direct3D 11 isn't available on this machine.", L"ceasta", MB_ICONERROR);
        return 1;
    }

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.IniFilename = nullptr; // our own settings.ini lives in the user folder
    theme::apply_theme();
    ImGuiStyle& style = ImGui::GetStyle();
    style.ScaleAllSizes(scale);
    style.FontScaleDpi = scale;
    theme::load_fonts();
    ImGui_ImplWin32_Init(g_hwnd);
    ImGui_ImplDX11_Init(g_device, g_context);

    static app_state state;
    g_app = &state;
    state.dpi_scale = scale;
    platform_api platform;
    platform.open_file_dialog = open_file_dialog;
    platform.save_file_dialog = save_file_dialog;
    platform.set_title = [](const std::string& t) { SetWindowTextW(g_hwnd, os::widen(t).c_str()); };
    platform.quit = []() { PostMessageW(g_hwnd, WM_CLOSE, 0, 0); };
    app_init(state, platform, args);

    // window placement from the last run
    if (state.win_w > 200 && state.win_h > 150)
        SetWindowPos(g_hwnd, nullptr, 0, 0, state.win_w, state.win_h, SWP_NOMOVE | SWP_NOZORDER);
    ::ShowWindow(g_hwnd, state.win_max ? SW_SHOWMAXIMIZED : SW_SHOWDEFAULT);
    ::UpdateWindow(g_hwnd);

    const ImVec4 clear = ImVec4(0.07f, 0.08f, 0.10f, 1.0f);
    bool done = false;
    while (!done) {
        MSG msg;
        while (::PeekMessageW(&msg, nullptr, 0U, 0U, PM_REMOVE)) {
            ::TranslateMessage(&msg);
            ::DispatchMessageW(&msg);
            if (msg.message == WM_QUIT)
                done = true;
        }
        if (done)
            break;

        // keep the debugger (and the ai server) going while the window is minimized / hidden
        if (g_occluded && g_swapchain->Present(0, DXGI_PRESENT_TEST) == DXGI_STATUS_OCCLUDED) {
            app_background(state);
            continue;
        }
        g_occluded = false;

        if (g_resize_w != 0 && g_resize_h != 0) {
            cleanup_target();
            g_swapchain->ResizeBuffers(0, g_resize_w, g_resize_h, DXGI_FORMAT_UNKNOWN, 0);
            g_resize_w = g_resize_h = 0;
            create_target();
        }

        app_pre_frame(state);
        ImGui_ImplDX11_NewFrame();
        ImGui_ImplWin32_NewFrame();
        ImGui::NewFrame();
        app_frame(state);
        ImGui::Render();
        const float c[4] = {clear.x, clear.y, clear.z, clear.w};
        g_context->OMSetRenderTargets(1, &g_target, nullptr);
        g_context->ClearRenderTargetView(g_target, c);
        ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
        HRESULT hr = g_swapchain->Present(1, 0);
        g_occluded = (hr == DXGI_STATUS_OCCLUDED);
    }

    app_shutdown(state);
    g_app = nullptr;
    ImGui_ImplDX11_Shutdown();
    ImGui_ImplWin32_Shutdown();
    ImGui::DestroyContext();
    cleanup_device();
    ::DestroyWindow(g_hwnd);
    ::UnregisterClassW(wc.lpszClassName, wc.hInstance);
    return 0;
}

static bool create_device(HWND hwnd)
{
    DXGI_SWAP_CHAIN_DESC desc;
    ZeroMemory(&desc, sizeof(desc));
    desc.BufferCount = 2;
    desc.BufferDesc.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    desc.BufferDesc.RefreshRate.Numerator = 60;
    desc.BufferDesc.RefreshRate.Denominator = 1;
    desc.Flags = DXGI_SWAP_CHAIN_FLAG_ALLOW_MODE_SWITCH;
    desc.BufferUsage = DXGI_USAGE_RENDER_TARGET_OUTPUT;
    desc.OutputWindow = hwnd;
    desc.SampleDesc.Count = 1;
    desc.Windowed = TRUE;
    desc.SwapEffect = DXGI_SWAP_EFFECT_DISCARD;

    D3D_FEATURE_LEVEL level;
    const D3D_FEATURE_LEVEL levels[2] = {D3D_FEATURE_LEVEL_11_0, D3D_FEATURE_LEVEL_10_0};
    HRESULT res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_HARDWARE, nullptr, 0, levels, 2, D3D11_SDK_VERSION,
        &desc, &g_swapchain, &g_device, &level, &g_context);
    if (res == DXGI_ERROR_UNSUPPORTED) // no gpu driver: fall back to the software rasterizer
        res = D3D11CreateDeviceAndSwapChain(nullptr, D3D_DRIVER_TYPE_WARP, nullptr, 0, levels, 2, D3D11_SDK_VERSION, &desc,
            &g_swapchain, &g_device, &level, &g_context);
    if (res != S_OK)
        return false;
    create_target();
    return true;
}

static void cleanup_device()
{
    cleanup_target();
    if (g_swapchain) {
        g_swapchain->Release();
        g_swapchain = nullptr;
    }
    if (g_context) {
        g_context->Release();
        g_context = nullptr;
    }
    if (g_device) {
        g_device->Release();
        g_device = nullptr;
    }
}

static void create_target()
{
    ID3D11Texture2D* back = nullptr;
    g_swapchain->GetBuffer(0, IID_PPV_ARGS(&back));
    if (!back)
        return;
    g_device->CreateRenderTargetView(back, nullptr, &g_target);
    back->Release();
}

static void cleanup_target()
{
    if (g_target) {
        g_target->Release();
        g_target = nullptr;
    }
}

extern IMGUI_IMPL_API LRESULT ImGui_ImplWin32_WndProcHandler(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam);

static void remember_placement(HWND hwnd)
{
    if (!g_app)
        return;
    WINDOWPLACEMENT wp;
    wp.length = sizeof(wp);
    if (GetWindowPlacement(hwnd, &wp)) {
        g_app->win_max = wp.showCmd == SW_SHOWMAXIMIZED;
        g_app->win_w = wp.rcNormalPosition.right - wp.rcNormalPosition.left;
        g_app->win_h = wp.rcNormalPosition.bottom - wp.rcNormalPosition.top;
    }
}

static LRESULT WINAPI wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam)
{
    if (ImGui_ImplWin32_WndProcHandler(hwnd, msg, wparam, lparam))
        return true;

    switch (msg) {
    case WM_SIZE:
        if (wparam == SIZE_MINIMIZED)
            return 0;
        g_resize_w = (UINT)LOWORD(lparam);
        g_resize_h = (UINT)HIWORD(lparam);
        return 0;
    case WM_DROPFILES: {
        HDROP drop = (HDROP)wparam;
        UINT n = DragQueryFileW(drop, 0, nullptr, 0);
        std::wstring path(n + 1, L'\0');
        DragQueryFileW(drop, 0, &path[0], n + 1);
        path.resize(n);
        DragFinish(drop);
        if (g_app && !path.empty())
            app_open(*g_app, os::narrow(path));
        return 0;
    }
    case WM_SYSCOMMAND:
        if ((wparam & 0xfff0) == SC_KEYMENU) // alt shouldn't open the system menu
            return 0;
        break;
    case WM_CLOSE:
        // unsaved changes: ask first; the answer closes the window again through platform.quit
        if (g_app && !app_request_close(*g_app))
            return 0;
        remember_placement(hwnd);
        break;
    case WM_DESTROY:
        ::PostQuitMessage(0);
        return 0;
    }
    return ::DefWindowProcW(hwnd, msg, wparam, lparam);
}
