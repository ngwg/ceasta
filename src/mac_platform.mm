// the macos parts of the gui that need cocoa: the system's open / save panels, and the menu bar
// glfw makes
#import <Cocoa/Cocoa.h>
#include <string>

std::string mac_open_file_dialog(const char* title)
{
    @autoreleasepool {
        NSOpenPanel* p = [NSOpenPanel openPanel];
        p.canChooseFiles = YES;
        p.canChooseDirectories = NO;
        p.allowsMultipleSelection = NO;
        // an .app is a folder: let people go inside it to the program (Contents/MacOS/...)
        p.treatsFilePackagesAsDirectories = YES;
        if (title)
            p.message = [NSString stringWithUTF8String:title];
        if ([p runModal] != NSModalResponseOK || !p.URL)
            return std::string();
        return std::string(p.URL.fileSystemRepresentation);
    }
}

std::string mac_save_file_dialog(const char* title, const std::string& suggested)
{
    @autoreleasepool {
        NSSavePanel* p = [NSSavePanel savePanel];
        if (title)
            p.message = [NSString stringWithUTF8String:title];
        NSString* s = [NSString stringWithUTF8String:suggested.c_str()];
        if (s.length) {
            NSString* dir = [s stringByDeletingLastPathComponent];
            if (dir.length)
                p.directoryURL = [NSURL fileURLWithPath:dir isDirectory:YES];
            p.nameFieldStringValue = [s lastPathComponent];
        }
        if ([p runModal] != NSModalResponseOK || !p.URL)
            return std::string();
        return std::string(p.URL.fileSystemRepresentation);
    }
}

// glfw's menu bar takes cmd+m for "minimize"; ceasta uses it (the bookmarks list)
void mac_fix_menu()
{
    @autoreleasepool {
        for (NSMenuItem* top in [[NSApp mainMenu] itemArray])
            for (NSMenuItem* item in [[top submenu] itemArray])
                if ([[item keyEquivalent] isEqualToString:@"m"] &&
                    ([item keyEquivalentModifierMask] & NSEventModifierFlagCommand))
                    [item setKeyEquivalent:@""];
    }
}
