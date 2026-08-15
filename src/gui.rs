use crate::decompile::{backend_names, decompile, default_output};
use crate::detect::detect;
use crate::i18n::UiLanguage;
use crate::model::{DecompileOptions, DecompileResult, Detection};
use crate::tools::inventory;
use eframe::egui;
use rfd::FileDialog;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

struct WorkerResult(Result<DecompileResult, String>);

pub struct PolyDecompApp {
    language: UiLanguage,
    input: String,
    output: String,
    backend: String,
    timeout_secs: u64,
    detection: Option<Detection>,
    preview: String,
    log: String,
    worker: Option<Receiver<WorkerResult>>,
    busy: bool,
}

impl Default for PolyDecompApp {
    fn default() -> Self {
        Self {
            language: UiLanguage::Japanese,
            input: String::new(),
            output: String::new(),
            backend: "auto".to_owned(),
            timeout_secs: 900,
            detection: None,
            preview: String::new(),
            log: String::new(),
            worker: None,
            busy: false,
        }
    }
}

impl PolyDecompApp {
    fn t(&self, key: &str) -> &'static str {
        self.language.text(key)
    }

    fn set_input(&mut self, path: PathBuf) {
        self.input = path.display().to_string();
        self.apply_detection(&path);
    }

    fn apply_detection(&mut self, path: &Path) {
        match detect(path) {
            Ok(detection) => {
                self.output = default_output(path, detection.kind).display().to_string();
                self.log = format!("{}: {}", self.t("kind"), detection.kind.as_str());
                self.detection = Some(detection);
            }
            Err(error) => {
                self.log = error;
                self.detection = None;
            }
        }
    }

    fn detect_now(&mut self) {
        if self.input.trim().is_empty() {
            self.log = self.t("select_input").to_owned();
            return;
        }
        let path = PathBuf::from(self.input.trim());
        self.apply_detection(&path);
    }

    fn choose_input(&mut self) {
        if let Some(path) = FileDialog::new().pick_file() {
            self.set_input(path);
        }
    }

    fn choose_output(&mut self) {
        let directory = self
            .detection
            .as_ref()
            .is_some_and(|detection| detection.kind.output_is_directory());
        let selected = if directory {
            FileDialog::new().pick_folder()
        } else {
            FileDialog::new().save_file()
        };
        if let Some(path) = selected {
            self.output = path.display().to_string();
        }
    }

    fn reset_output(&mut self) {
        let Some(detection) = &self.detection else {
            return;
        };
        let input = PathBuf::from(self.input.trim());
        self.output = default_output(&input, detection.kind).display().to_string();
    }

    fn start_decompile(&mut self) {
        if self.busy || self.input.trim().is_empty() {
            if self.input.trim().is_empty() {
                self.log = self.t("select_input").to_owned();
            }
            return;
        }
        self.detect_now();
        let input = PathBuf::from(self.input.trim());
        let Some(detection) = self.detection.clone() else {
            return;
        };
        if self.output.trim().is_empty() {
            self.output = default_output(&input, detection.kind).display().to_string();
        }
        let output = PathBuf::from(self.output.trim());
        let options = DecompileOptions {
            backend: self.backend.clone(),
            timeout_secs: self.timeout_secs,
            force: true,
        };
        let (sender, receiver) = mpsc::channel();
        self.worker = Some(receiver);
        self.busy = true;
        self.preview.clear();
        self.log = self.t("working").to_owned();
        thread::spawn(move || {
            let result = decompile(&input, &output, &options).map_err(|error| error.to_string());
            let _ = sender.send(WorkerResult(result));
        });
    }

    fn poll_worker(&mut self) {
        let message = self.worker.as_ref().and_then(|receiver| receiver.try_recv().ok());
        let Some(WorkerResult(result)) = message else {
            return;
        };
        self.busy = false;
        self.worker = None;
        match result {
            Ok(result) => {
                self.log = format!(
                    "{}: {} → {} [{}]",
                    self.t("done"),
                    result.input.display(),
                    result.output.display(),
                    result.backend
                );
                self.preview = preview_output(&result.output);
            }
            Err(error) => self.log = error,
        }
    }

    fn try_open_output(&mut self) {
        if self.output.trim().is_empty() {
            return;
        }
        if let Err(error) = open_output(Path::new(self.output.trim())) {
            self.log = error;
        }
    }
}

impl eframe::App for PolyDecompApp {
    fn logic(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        self.poll_worker();
        if self.busy {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        if let Some(path) = ui
            .ctx()
            .input(|input| input.raw.dropped_files.clone())
            .into_iter()
            .find_map(|file| file.path)
        {
            self.set_input(path);
        }

        egui::CentralPanel::default().show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.vertical(|ui| {
                    ui.heading("PolyDecomp");
                    ui.label(self.t("subtitle"));
                });
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    egui::ComboBox::from_id_salt("language")
                        .selected_text(self.language.label())
                        .show_ui(ui, |ui| {
                            ui.selectable_value(&mut self.language, UiLanguage::Japanese, "日本語");
                            ui.selectable_value(&mut self.language, UiLanguage::English, "English");
                        });
                });
            });
            ui.separator();
            ui.weak(self.t("drop"));

            egui::Grid::new("paths").num_columns(4).spacing([10.0, 8.0]).show(ui, |ui| {
                ui.label(self.t("input"));
                ui.add_sized([ui.available_width() - 110.0, 24.0], egui::TextEdit::singleline(&mut self.input));
                if ui.button(self.t("browse")).clicked() {
                    self.choose_input();
                }
                ui.label("");
                ui.end_row();

                ui.label(self.t("output"));
                ui.add_sized([ui.available_width() - 190.0, 24.0], egui::TextEdit::singleline(&mut self.output));
                if ui.button(self.t("browse")).clicked() {
                    self.choose_output();
                }
                if ui.button(self.t("auto_output")).clicked() {
                    self.reset_output();
                }
                ui.end_row();
            });

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.label(self.t("backend"));
                egui::ComboBox::from_id_salt("backend")
                    .selected_text(&self.backend)
                    .show_ui(ui, |ui| {
                        for backend in backend_names() {
                            ui.selectable_value(&mut self.backend, (*backend).to_owned(), *backend);
                        }
                    });
                ui.separator();
                ui.label(self.t("timeout"));
                ui.add(egui::DragValue::new(&mut self.timeout_secs).range(1..=86_400));
                ui.separator();
                if ui.add_enabled(!self.busy, egui::Button::new(self.t("detect"))).clicked() {
                    self.detect_now();
                }
                if ui.add_enabled(!self.busy, egui::Button::new(self.t("decompile"))).clicked() {
                    self.start_decompile();
                }
                if self.busy {
                    ui.spinner();
                }
            });

            if let Some(detection) = &self.detection {
                ui.add_space(8.0);
                ui.group(|ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.strong(format!("{}:", self.t("kind")));
                        ui.label(detection.kind.as_str());
                        ui.separator();
                        ui.strong(format!("{}:", self.t("language")));
                        ui.label(&detection.language);
                        ui.separator();
                        ui.strong(format!("{}:", self.t("confidence")));
                        ui.label(format!("{:.0}%", detection.confidence * 100.0));
                        ui.separator();
                        ui.label(&detection.description);
                    });
                });
            }

            ui.add_space(8.0);
            ui.collapsing(self.t("engines"), |ui| {
                egui::Grid::new("tools").striped(true).show(ui, |ui| {
                    for tool in inventory() {
                        ui.monospace(&tool.name);
                        ui.label(if tool.path.is_some() { self.t("available") } else { self.t("missing") });
                        ui.label(tool.path.as_ref().map_or_else(|| tool.notes.clone(), |path| path.display().to_string()));
                        ui.end_row();
                    }
                });
            });

            ui.add_space(8.0);
            ui.horizontal(|ui| {
                ui.strong(self.t("log"));
                if ui.button(self.t("open_output")).clicked() {
                    self.try_open_output();
                }
            });
            ui.label(&self.log);
            ui.add_space(8.0);
            ui.strong(self.t("preview"));
            egui::ScrollArea::vertical().id_salt("preview-scroll").max_height(300.0).show(ui, |ui| {
                ui.add(
                    egui::TextEdit::multiline(&mut self.preview)
                        .font(egui::TextStyle::Monospace)
                        .desired_width(f32::INFINITY)
                        .desired_rows(15)
                        .interactive(false),
                );
            });
        });
    }
}

fn preview_output(path: &Path) -> String {
    if path.is_file() {
        return match fs::read(path) {
            Ok(bytes) => {
                let limit = bytes.len().min(512 * 1024);
                let mut text = String::from_utf8_lossy(&bytes[..limit]).into_owned();
                if bytes.len() > limit {
                    text.push_str("\n\n… preview truncated …");
                }
                text
            }
            Err(error) => format!("preview error: {error}"),
        };
    }
    if path.is_dir() {
        let mut entries = Vec::new();
        collect_entries(path, path, &mut entries, 200);
        return entries.join("\n");
    }
    String::new()
}

fn collect_entries(root: &Path, dir: &Path, entries: &mut Vec<String>, limit: usize) {
    if entries.len() >= limit {
        return;
    }
    let Ok(read_dir) = fs::read_dir(dir) else {
        return;
    };
    for entry in read_dir.flatten() {
        if entries.len() >= limit {
            entries.push("… truncated …".to_owned());
            return;
        }
        let path = entry.path();
        if path.is_dir() {
            collect_entries(root, &path, entries, limit);
        } else {
            entries.push(path.strip_prefix(root).unwrap_or(&path).display().to_string());
        }
    }
}

fn open_output(path: &Path) -> Result<(), String> {
    let target = if path.exists() && path.is_dir() {
        path.to_path_buf()
    } else {
        path.parent().unwrap_or(path).to_path_buf()
    };

    #[cfg(target_os = "windows")]
    let mut command = std::process::Command::new("explorer");
    #[cfg(target_os = "macos")]
    let mut command = std::process::Command::new("open");
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = std::process::Command::new("xdg-open");

    command
        .arg(&target)
        .spawn()
        .map(|_| ())
        .map_err(|error| format!("failed to open {}: {error}", target.display()))
}

fn install_japanese_font(ctx: &egui::Context) {
    #[cfg(target_os = "windows")]
    let candidates = [r"C:\Windows\Fonts\YuGothM.ttc", r"C:\Windows\Fonts\meiryo.ttc", r"C:\Windows\Fonts\msgothic.ttc"];
    #[cfg(target_os = "macos")]
    let candidates = ["/System/Library/Fonts/ヒラギノ角ゴシック W3.ttc", "/System/Library/Fonts/ヒラギノ丸ゴ ProN W4.ttc", "/System/Library/Fonts/AppleSDGothicNeo.ttc"];
    #[cfg(all(unix, not(target_os = "macos")))]
    let candidates = ["/usr/share/fonts/opentype/noto/NotoSansCJK-Regular.ttc", "/usr/share/fonts/opentype/noto/NotoSansCJKjp-Regular.otf", "/usr/share/fonts/truetype/noto/NotoSansCJK-Regular.ttc"];

    let Some(data) = candidates.iter().find_map(|path| fs::read(path).ok()) else {
        return;
    };
    let mut fonts = egui::FontDefinitions::default();
    fonts.font_data.insert("system-japanese".to_owned(), Arc::new(egui::FontData::from_owned(data)));
    if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Proportional) {
        family.insert(0, "system-japanese".to_owned());
    }
    if let Some(family) = fonts.families.get_mut(&egui::FontFamily::Monospace) {
        family.push("system-japanese".to_owned());
    }
    ctx.set_fonts(fonts);
}

pub fn run() -> eframe::Result {
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1080.0, 760.0])
            .with_min_inner_size([760.0, 520.0]),
        ..Default::default()
    };
    eframe::run_native(
        "PolyDecomp",
        options,
        Box::new(|cc| {
            install_japanese_font(&cc.egui_ctx);
            Ok(Box::<PolyDecompApp>::default())
        }),
    )
}
