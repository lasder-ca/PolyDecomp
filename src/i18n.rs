#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UiLanguage {
    #[default]
    Japanese,
    English,
}

impl UiLanguage {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Japanese => "日本語",
            Self::English => "English",
        }
    }

    pub fn text(self, key: &str) -> &'static str {
        match (self, key) {
            (Self::Japanese, "subtitle") => {
                "外部バックエンド不要の自己完結型マルチ形式デコンパイラ"
            }
            (Self::English, "subtitle") => {
                "Self-contained multi-format decompiler with no external backends"
            }
            (Self::Japanese, "input") => "入力ファイル",
            (Self::English, "input") => "Input file",
            (Self::Japanese, "output") => "出力先",
            (Self::English, "output") => "Output",
            (Self::Japanese, "output_format") => "ネイティブ出力",
            (Self::English, "output_format") => "Native output",
            (Self::Japanese, "output_format_note") => "C / Rust / Python / ASM / JSON",
            (Self::English, "output_format_note") => "C / Rust / Python / ASM / JSON",
            (Self::Japanese, "browse") => "参照…",
            (Self::English, "browse") => "Browse…",
            (Self::Japanese, "engine") => "内蔵エンジン",
            (Self::English, "engine") => "Built-in engine",
            (Self::Japanese, "detect") => "形式を解析",
            (Self::English, "detect") => "Detect",
            (Self::Japanese, "decompile") => "デコンパイル",
            (Self::English, "decompile") => "Decompile",
            (Self::Japanese, "working") => "関数・制御フローを復元して解析中…",
            (Self::English, "working") => "Recovering functions and control flow…",
            (Self::Japanese, "kind") => "形式",
            (Self::English, "kind") => "Kind",
            (Self::Japanese, "language") => "推定言語",
            (Self::English, "language") => "Likely language",
            (Self::Japanese, "confidence") => "信頼度",
            (Self::English, "confidence") => "Confidence",
            (Self::Japanese, "capabilities") => "内蔵対応形式",
            (Self::English, "capabilities") => "Built-in capabilities",
            (Self::Japanese, "fidelity") => "復元度",
            (Self::English, "fidelity") => "Fidelity",
            (Self::Japanese, "preview") => "出力プレビュー",
            (Self::English, "preview") => "Output preview",
            (Self::Japanese, "log") => "ログ",
            (Self::English, "log") => "Log",
            (Self::Japanese, "open_output") => "出力を開く",
            (Self::English, "open_output") => "Open output",
            (Self::Japanese, "drop") => "ファイルをここへドロップできます",
            (Self::English, "drop") => "Drop a file here",
            (Self::Japanese, "auto_output") => "自動設定",
            (Self::English, "auto_output") => "Auto output",
            (Self::Japanese, "select_input") => "入力ファイルを選択してください",
            (Self::English, "select_input") => "Select an input file",
            (Self::Japanese, "done") => "完了",
            (Self::English, "done") => "Done",
            (Self::Japanese, "no_external") => {
                "Ghidra / CFR / JADX / pycdc / ILSpy 等は不要です"
            }
            (Self::English, "no_external") => {
                "No Ghidra, CFR, JADX, pycdc, ILSpy, or other decompiler executables required"
            }
            _ => "",
        }
    }
}
