#include <windows.h>

int WINAPI WinMain(
    HINSTANCE hInstance,
    HINSTANCE hPrevInstance,
    LPSTR lpCmdLine,
    int nCmdShow
) {
    MessageBoxW(NULL, L"Test executable running!", L"Success", MB_ICONINFORMATION);
    return 0;
}
