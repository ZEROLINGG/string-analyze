use crate::rules::lazy_rule;

// ==========================================
// 1. MSVC (Microsoft Visual C++)
// ==========================================
lazy_rule!(
    RE_COMPILER_MSVC_UCRT = r#"(?i)minkernel\\crts\\ucrt\\src\\"#,
    "发现 MSVC Universal CRT 源代码路径",
    30
);

lazy_rule!(
    RE_COMPILER_MSVC_VCRUNTIME = r#"(?i)[a-z]:\\[^:*?"<>|\r\n]*\\vcruntime\\src\\"#,
    "发现 MSVC VCRuntime 源代码路径",
    30
);

lazy_rule!(
    RE_COMPILER_MSVC_DLL = r#"(?i)\b(?:msvcr\d+|msvcp\d+|vcruntime\d+|ucrtbase)\.dll\b"#,
    "发现 MSVC 动态运行时库 (CRT DLL)",
    15
);

// ==========================================
// 2. GCC / Clang
// ==========================================
lazy_rule!(
    RE_COMPILER_GCC = r#"GCC:\s*\([^)]+\)\s*\d+\.\d+\.\d+"#,
    "发现完整的 GCC 编译器版本字符串",
    20
);

lazy_rule!(
    RE_COMPILER_CLANG = r#"(?i)\bclang\s+version\s+\d+\.\d+\.\d+"#,
    "发现 Clang 编译器版本字符串",
    20
);

// ==========================================
// 3. Rust
// ==========================================
lazy_rule!(
    RE_LANG_RUST_PATH = r#"/rustc/[0-9a-f]{40}/library/"#,
    "发现 Rust 标准库编译路径",
    30
);

lazy_rule!(
    RE_LANG_RUST_RUNTIME = r#"\b(?:RUST_BACKTRACE|panicked at|fatal runtime error)\b"#,
    "发现 Rust 运行时错误/调试字符串",
    30
);

// ==========================================
// 4. Go
// ==========================================
lazy_rule!(
    RE_LANG_GO_BUILDID = r#"\bGo build ID:\s*"[^"]+""#,
    "发现 Go Build ID",
    30
);

lazy_rule!(
    RE_LANG_GO_RUNTIME = r#"\b(?:runtime\.main|runtime\.gopanic|main\.main)\b"#,
    "发现 Go 运行时符号/函数名",
    30
);

// ==========================================
// 5. C# / .NET 框架
// ==========================================
lazy_rule!(
    RE_LANG_DOTNET_MSCOREE = r#"(?i)\bmscoree\.dll\b"#,
    "发现 .NET 核心运行时加载器 (mscoree.dll)",
    40
);

lazy_rule!(
    RE_LANG_DOTNET_CORMAIN = r#"\b_Cor(?:Exe|Dll)Main\b"#,
    "发现 .NET 可执行文件入口点符号 (_CorExeMain)",
    40
);

// ==========================================
// 6. Delphi / Free Pascal
// ==========================================
lazy_rule!(
    RE_COMPILER_DELPHI = r#"(?i)\b(?:Borland\\Delphi|System\.SysUtils|FastMM)\b"#,
    "发现 Delphi / Embarcadero 运行时特征",
    30
);

lazy_rule!(
    RE_COMPILER_FPC = r#"(?i)\bFree Pascal Compiler\b"#,
    "发现 Free Pascal 编译器特征",
    30
);

// ==========================================
// Python 打包工具
// ==========================================
lazy_rule!(
    RE_PACKER_PYINSTALLER = r#"(?i)\b(?:pyi-windows-manifest|Py_Initialize)\b"#,
    "发现 PyInstaller 打包特征",
    40
);

lazy_rule!(
    RE_PACKER_NUITKA = r#"(?i)\b__nuitka_module\b"#,
    "发现 Nuitka 打包/编译特征",
    40
);

// ==========================================
// UPX
// ==========================================
lazy_rule!(
    RE_PACKER_UPX_SECTION = r#"UPX[012]!"#,
    "发现 UPX 壳区段标识符",
    50
);

lazy_rule!(
    RE_PACKER_UPX_TEXT = r#"\$Info: This file is packed with the UPX executable packer\$"#,
    "发现 UPX 官方版权声明文本",
    50
);
