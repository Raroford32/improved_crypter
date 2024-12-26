#pragma once
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <objbase.h>
#include <string>
#include "crypter.hpp"
#include "resource.h"

class GUI {
private:
    HWND m_hwnd;
    HWND m_hwndInputPath;
    HWND m_hwndOutputPath;
    HWND m_hwndMetamorphic;
    HWND m_hwndAntiAnalysis;
    HWND m_hwndRandomSections;
    HWND m_hwndObfuscateImports;
    HWND m_hwndScrambleHeaders;
    HWND m_hwndInjectionType;
    HWND m_hwndTargetProcess;
    HWND m_hwndProgress;
    HWND m_hwndStatus;

    void createControls() {
            // Create input file controls
            CreateWindowW(L"STATIC", L"Input File:", WS_CHILD | WS_VISIBLE,
                10, 10, 70, 20, m_hwnd, nullptr, GetModuleHandleW(nullptr), nullptr);
            m_hwndInputPath = CreateWindowW(WC_EDITW, L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                90, 10, 300, 20, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_INPUT_PATH)), GetModuleHandleW(nullptr), nullptr);
            CreateWindowW(WC_BUTTONW, L"Browse...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                400, 10, 70, 20, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(ID_FILE_OPEN)), GetModuleHandleW(nullptr), nullptr);

            // Create output file controls
            CreateWindowW(L"STATIC", L"Output File:", WS_CHILD | WS_VISIBLE,
                10, 40, 70, 20, m_hwnd, nullptr, GetModuleHandleW(nullptr), nullptr);
            m_hwndOutputPath = CreateWindowW(WC_EDITW, L"", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                90, 40, 300, 20, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_OUTPUT_PATH)), GetModuleHandleW(nullptr), nullptr);
            CreateWindowW(WC_BUTTONW, L"Browse...", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                400, 40, 70, 20, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(ID_FILE_SAVE)), GetModuleHandleW(nullptr), nullptr);

            // Create options group
            CreateWindowW(WC_BUTTONW, L"Options", WS_CHILD | WS_VISIBLE | BS_GROUPBOX,
                10, 70, 460, 180, m_hwnd, nullptr, GetModuleHandleW(nullptr), nullptr);

            // Create checkboxes
            m_hwndMetamorphic = CreateWindowW(WC_BUTTONW, L"Use Metamorphic Engine", 
                WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                20, 90, 200, 20, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_METAMORPHIC)), GetModuleHandleW(nullptr), nullptr);
            SendMessageW(m_hwndMetamorphic, BM_SETCHECK, BST_CHECKED, 0);

            m_hwndAntiAnalysis = CreateWindowW(WC_BUTTONW, L"Use Anti-Analysis", 
                WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                20, 110, 200, 20, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_ANTI_ANALYSIS)), GetModuleHandleW(nullptr), nullptr);
            SendMessageW(m_hwndAntiAnalysis, BM_SETCHECK, BST_CHECKED, 0);

            m_hwndRandomSections = CreateWindowW(WC_BUTTONW, L"Add Random Sections", 
                WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                20, 130, 200, 20, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_RANDOM_SECTIONS)), GetModuleHandleW(nullptr), nullptr);
            SendMessageW(m_hwndRandomSections, BM_SETCHECK, BST_CHECKED, 0);

            m_hwndObfuscateImports = CreateWindowW(WC_BUTTONW, L"Obfuscate Imports", 
                WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                20, 150, 200, 20, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_OBFUSCATE_IMPORTS)), GetModuleHandleW(nullptr), nullptr);
            SendMessageW(m_hwndObfuscateImports, BM_SETCHECK, BST_CHECKED, 0);

            m_hwndScrambleHeaders = CreateWindowW(WC_BUTTONW, L"Scramble Headers", 
                WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                20, 170, 200, 20, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_SCRAMBLE_HEADERS)), GetModuleHandleW(nullptr), nullptr);
            SendMessageW(m_hwndScrambleHeaders, BM_SETCHECK, BST_CHECKED, 0);

            // Create injection type combo
            CreateWindowW(L"STATIC", L"Injection Method:", WS_CHILD | WS_VISIBLE,
                20, 200, 100, 20, m_hwnd, nullptr, GetModuleHandleW(nullptr), nullptr);
            m_hwndInjectionType = CreateWindowW(WC_COMBOBOXW, nullptr, 
                WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
                130, 200, 200, 200, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_INJECTION_TYPE)), GetModuleHandleW(nullptr), nullptr);

            // Add injection types
            SendMessageW(m_hwndInjectionType, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Process Hollowing"));
            SendMessageW(m_hwndInjectionType, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"APC Injection"));
            SendMessageW(m_hwndInjectionType, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Module Stomping"));
            SendMessageW(m_hwndInjectionType, CB_ADDSTRING, 0, reinterpret_cast<LPARAM>(L"Early Bird"));
            SendMessageW(m_hwndInjectionType, CB_SETCURSEL, 0, 0);

            // Create target process input
            CreateWindowW(L"STATIC", L"Target Process:", WS_CHILD | WS_VISIBLE,
                20, 230, 100, 20, m_hwnd, nullptr, GetModuleHandleW(nullptr), nullptr);
            m_hwndTargetProcess = CreateWindowW(WC_EDITW, L"svchost.exe", 
                WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                130, 230, 200, 20, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_TARGET_PROCESS)), GetModuleHandleW(nullptr), nullptr);

            // Create build button
            CreateWindowW(WC_BUTTONW, L"Build", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                200, 260, 80, 25, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(ID_BUILD)), GetModuleHandleW(nullptr), nullptr);

            // Create progress bar
            m_hwndProgress = CreateWindowW(PROGRESS_CLASSW, nullptr,
                WS_CHILD | WS_VISIBLE | PBS_SMOOTH,
                10, 295, 460, 20, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_PROGRESS)), GetModuleHandleW(nullptr), nullptr);
            SendMessageW(m_hwndProgress, PBM_SETRANGE, 0, MAKELPARAM(0, 100));

            // Create status bar
            m_hwndStatus = CreateWindowW(STATUSCLASSNAMEW, nullptr,
                WS_CHILD | WS_VISIBLE | SBARS_SIZEGRIP,
                0, 0, 0, 0, m_hwnd, reinterpret_cast<HMENU>(static_cast<UINT_PTR>(IDC_STATUS)), GetModuleHandleW(nullptr), nullptr);
            SendMessageW(m_hwndStatus, SB_SETTEXT, 0, reinterpret_cast<LPARAM>(L"Ready"));
    }

public:
    GUI(HWND hwnd) : m_hwnd(hwnd) {}

    bool initialize() {
        createControls();
        return true;
    }

    bool handleMessage(HWND /*hwnd*/, UINT msg, WPARAM wParam, LPARAM /*lParam*/, LRESULT* result) {
        switch(msg) {
            case WM_COMMAND:
                switch(LOWORD(wParam)) {
                    case ID_FILE_OPEN:
                        handleFileOpen();
                        *result = 0;
                        return true;

                    case ID_FILE_SAVE:
                        handleFileSave();
                        *result = 0;
                        return true;

                    case ID_BUILD:
                        handleBuild();
                        *result = 0;
                        return true;
                }
                break;
        }
        return false;
    }

private:
    void handleFileOpen() {
        wchar_t filename[MAX_PATH] = {0};
        OPENFILENAMEW ofn = {0};
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = m_hwnd;
        ofn.lpstrFilter = L"Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
        ofn.lpstrFile = filename;
        ofn.nMaxFile = MAX_PATH;
        ofn.Flags = OFN_EXPLORER | OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
        ofn.lpstrDefExt = L"exe";

        if(GetOpenFileNameW(&ofn)) {
            SetWindowTextW(m_hwndInputPath, filename);
            
            // Auto-generate output path
            std::wstring output = filename;
            size_t dot = output.find_last_of(L'.');
            if(dot != std::wstring::npos) {
                output = output.substr(0, dot);
            }
            output += L"_crypted.exe";
            SetWindowTextW(m_hwndOutputPath, output.c_str());
        }
    }

    void handleFileSave() {
        wchar_t filename[MAX_PATH] = {0};
        OPENFILENAMEW ofn = {0};
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = m_hwnd;
        ofn.lpstrFilter = L"Executable Files (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
        ofn.lpstrFile = filename;
        ofn.nMaxFile = MAX_PATH;
        ofn.Flags = OFN_EXPLORER | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY | OFN_OVERWRITEPROMPT;
        ofn.lpstrDefExt = L"exe";

        if(GetSaveFileNameW(&ofn)) {
            SetWindowTextW(m_hwndOutputPath, filename);
        }
    }

    void handleBuild() {
        // Get input/output paths
        wchar_t input[MAX_PATH], output[MAX_PATH];
        GetWindowTextW(m_hwndInputPath, input, MAX_PATH);
        GetWindowTextW(m_hwndOutputPath, output, MAX_PATH);

        if(!*input || !*output) {
            MessageBoxW(m_hwnd, L"Please select input and output files", L"Error", MB_ICONERROR);
            return;
        }

        // Get target process
        wchar_t targetProcess[MAX_PATH];
        GetWindowTextW(m_hwndTargetProcess, targetProcess, MAX_PATH);

        // Create config
        Crypter::CrypterConfig config;
        config.useMetamorphic = SendMessage(m_hwndMetamorphic, BM_GETCHECK, 0, 0) == BST_CHECKED;
        config.useAntiAnalysis = SendMessage(m_hwndAntiAnalysis, BM_GETCHECK, 0, 0) == BST_CHECKED;
        config.addRandomSections = SendMessage(m_hwndRandomSections, BM_GETCHECK, 0, 0) == BST_CHECKED;
        config.obfuscateImports = SendMessage(m_hwndObfuscateImports, BM_GETCHECK, 0, 0) == BST_CHECKED;
        config.scrambleHeaders = SendMessage(m_hwndScrambleHeaders, BM_GETCHECK, 0, 0) == BST_CHECKED;
        config.targetProcess = targetProcess;

        // Get injection type
        int injType = static_cast<int>(SendMessage(m_hwndInjectionType, CB_GETCURSEL, 0, 0));
        switch(injType) {
            case 0: config.injectionType = PEManipulator::InjectionType::ProcessHollowing; break;
            case 1: config.injectionType = PEManipulator::InjectionType::APCInjection; break;
            case 2: config.injectionType = PEManipulator::InjectionType::ModuleStomping; break;
            case 3: config.injectionType = PEManipulator::InjectionType::EarlyBird; break;
        }

        // Update UI
        EnableWindow(GetDlgItem(m_hwnd, ID_BUILD), FALSE);
        SendMessage(m_hwndProgress, PBM_SETPOS, 0, 0);
        SendMessageW(m_hwndStatus, SB_SETTEXT, 0, reinterpret_cast<LPARAM>(L"Building..."));

        // Convert paths to UTF-8
        int inputSize = WideCharToMultiByte(CP_UTF8, 0, input, -1, nullptr, 0, nullptr, nullptr);
        std::string inputUtf8(inputSize, 0);
        WideCharToMultiByte(CP_UTF8, 0, input, -1, &inputUtf8[0], inputSize, nullptr, nullptr);
        
        int outputSize = WideCharToMultiByte(CP_UTF8, 0, output, -1, nullptr, 0, nullptr, nullptr);
        std::string outputUtf8(outputSize, 0);
        WideCharToMultiByte(CP_UTF8, 0, output, -1, &outputUtf8[0], outputSize, nullptr, nullptr);

        // Build crypter
        bool success = Crypter::cryptFile(inputUtf8, outputUtf8, config);

        // Update UI
        EnableWindow(GetDlgItem(m_hwnd, ID_BUILD), TRUE);
        SendMessage(m_hwndProgress, PBM_SETPOS, 100, 0);
        SendMessageW(m_hwndStatus, SB_SETTEXT, 0, reinterpret_cast<LPARAM>(success ? L"Build completed successfully" : L"Build failed"));

        if(success) {
            MessageBoxW(m_hwnd, L"Build completed successfully!", L"Success", MB_ICONINFORMATION);
        } else {
            MessageBoxW(m_hwnd, L"Build failed!", L"Error", MB_ICONERROR);
        }
    }
};
