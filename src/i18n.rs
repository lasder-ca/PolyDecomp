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
            (Self::Japanese, "subtitle") => "複数形式に対応したデコンパイラ・フロントエンド",
            (Self::English, "subtitle") => "Multi-format decompiler frontend",
            (Self::Japanese, "input") => "入力ファイル",
            (Self::English, "input") => "Input file",
            (Self::Japanese, "output") => "出力先",
            (Self::English, "output") => "Output",
            (Self::Japanese, "browse") => "参照…",
            (Self::English, "browse") => "Browse…",
            (Self::Japanese, "backend") => "バックエンド",
            (Self::English, "backend") => "Backend",
            (Self::Japanese, "timeout") => "タイムアウト（秒）",
            (Self::English, "timeout") => "Timeout (seconds)",
            (Self::Japanese, "detect") => "形式を解析",
            (Self::English, "detect") => "Detect",
            (Self::Japanese, "decompile") => "デコンパイル",
            (Self::English, "decompile") => "Decompile",
            (Self::Japanese, "working") => "解析中…",
            (Self::English, "working") => "Working…",
            (Self::Japanese, "kind") => "形式",
            (Self::English, "kind") => "Kind",
            (Self::Japanese, "language") => "推定言語",
            (Self::English, "language") => "Likely language",
            (Self::Japanese, "confidence") => "信頼度",
            (Self::English, "confidence") => "Confidence",
            (Self::Japanese, "engines") => "バックエンド状態",
            (Self::English, "engines") => "Backend status",
            (Self::Japanese, "available") => "利用可能",
            (Self::English, "available") => "Available",
            (Self::Japanese, "missing") => "未検出",
            (Self::English, "missing") => "Missing",
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
            _ => "",
        }
    }
}
