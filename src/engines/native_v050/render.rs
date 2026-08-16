use super::{EnhancedFunction, EnhancedInstruction, EnhancedReport};
use crate::model::NativeOutputFormat;
use std::fmt::Write as _;

fn comment_prefix(format: NativeOutputFormat) -> &'static str {
    match format {
        NativeOutputFormat::Python => "#",
        NativeOutputFormat::Assembly => ";",
        _ => "//",
    }
}

fn render_header(out: &mut String, report: &EnhancedReport, format: NativeOutputFormat) {
    let comment = comment_prefix(format);
    let _ = writeln!(out, "{comment} PolyDecomp v0.5 readable native pseudocode");
    let _ = writeln!(out, "{comment} Format: {}", report.format);
    let _ = writeln!(out, "{comment} Architecture: {}", report.architecture);
    let _ = writeln!(out, "{comment} Entry point: 0x{:x}", report.entry);
    let _ = writeln!(
        out,
        "{comment} Readability: CFG + symbolic values + stack locals + recovered conditions + call names"
    );
    let _ = writeln!(
        out,
        "{comment} Reconstructed names/types are heuristics, not compiler-lost original source."
    );
    let _ = writeln!(out);

    if !report.imports.is_empty() {
        let _ = writeln!(out, "{comment} Resolved imports: {}", report.imports.len());
        for import in report.imports.iter().take(40) {
            let _ = writeln!(
                out,
                "{comment}   0x{:016x}  {}!{}",
                import.iat_address, import.dll, import.name
            );
        }
        if report.imports.len() > 40 {
            let _ = writeln!(
                out,
                "{comment}   ... {} more imports omitted from header ...",
                report.imports.len() - 40
            );
        }
        let _ = writeln!(out);
    }

    if !report.recovered_strings.is_empty() {
        let shown = report.recovered_strings.len().min(60);
        let _ = writeln!(out, "{comment} Recovered strings (first {shown})");
        for value in report.recovered_strings.iter().take(shown) {
            let _ = writeln!(out, "{comment}   {value:?}");
        }
        if report.recovered_strings.len() > shown {
            let _ = writeln!(
                out,
                "{comment}   ... {} more strings omitted from text header; JSON keeps the full list ...",
                report.recovered_strings.len() - shown
            );
        }
        let _ = writeln!(out);
    }
}

fn function_summary(out: &mut String, function: &EnhancedFunction, prefix: &str) {
    let _ = writeln!(
        out,
        "{prefix} 0x{:x}, {} bytes, recovered from {}, ABI: {}",
        function.address, function.size, function.origin, function.abi
    );
    if !function.arguments.is_empty() {
        let args = function
            .arguments
            .iter()
            .map(|argument| format!("{}={}", argument.name, argument.register))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(out, "{prefix} inferred arguments: {args}");
    }
    if !function.stack_locals.is_empty() {
        let _ = writeln!(
            out,
            "{prefix} inferred stack locals: {}",
            function.stack_locals.join(", ")
        );
    }
    if !function.calls.is_empty() {
        let _ = writeln!(out, "{prefix} calls: {}", function.calls.join(", "));
    }
    if !function.loop_headers.is_empty() {
        let loops = function
            .loop_headers
            .iter()
            .map(|address| format!("L_{address:x}"))
            .collect::<Vec<_>>()
            .join(", ");
        let _ = writeln!(out, "{prefix} loop headers: {loops}");
    }
}

fn c_signature(function: &EnhancedFunction) -> String {
    let return_type = if function.returns_value { "uintptr_t" } else { "void" };
    let args = if function.arguments.is_empty() {
        "void".to_owned()
    } else {
        function
            .arguments
            .iter()
            .map(|argument| format!("uintptr_t {}", argument.name))
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!("{return_type} {}({args})", function.name)
}

fn rust_signature(function: &EnhancedFunction) -> String {
    let args = function
        .arguments
        .iter()
        .map(|argument| format!("{}: usize", argument.name))
        .collect::<Vec<_>>()
        .join(", ");
    let return_type = if function.returns_value { " -> usize" } else { "" };
    format!("fn {}({args}){return_type}", function.name)
}

fn python_signature(function: &EnhancedFunction) -> String {
    let args = function
        .arguments
        .iter()
        .map(|argument| argument.name.as_str())
        .collect::<Vec<_>>()
        .join(", ");
    format!("def {}({args})", function.name)
}

fn conditional_parts(statement: &str) -> Option<(&str, &str)> {
    let rest = statement.strip_prefix("if (")?;
    let (condition, target) = rest.split_once(") goto L_")?;
    Some((condition, target.trim_end_matches(';')))
}

fn direct_goto_target(statement: &str) -> Option<&str> {
    statement
        .strip_prefix("goto L_")
        .map(|value| value.trim_end_matches(';'))
}

fn python_expression(value: &str) -> String {
    value
        .replace("(signed)", "")
        .replace(" /* unsigned */", "")
        .replace("!sign_flag", "not sign_flag")
        .replace("!overflow_flag", "not overflow_flag")
        .replace("!parity_flag", "not parity_flag")
}

fn rust_statement(statement: &str) -> String {
    if let Some(target) = direct_goto_target(statement) {
        return format!("goto_label(\"L_{target}\");");
    }
    statement.replace("(signed)", "")
}

fn python_statement(statement: &str) -> String {
    if let Some(target) = direct_goto_target(statement) {
        return format!("goto(\"L_{target}\")");
    }
    if statement.starts_with("/*") {
        return format!("# {}", statement.trim_matches(&['/', '*', ' '][..]));
    }
    python_expression(statement.trim_end_matches(';'))
}

fn annotation(instruction: &EnhancedInstruction, comment: &str) -> String {
    let symbol = instruction
        .symbol
        .as_deref()
        .map(|value| format!("; symbol={value}"))
        .unwrap_or_default();
    format!(
        "{comment} 0x{:016x}: {} [{}{}]",
        instruction.address, instruction.assembly, instruction.confidence, symbol
    )
}

fn render_c_function(out: &mut String, function: &EnhancedFunction) {
    function_summary(out, function, "//");
    let _ = writeln!(out, "{} {{", c_signature(function));
    for local in &function.stack_locals {
        let _ = writeln!(out, "    uintptr_t {local}; // inferred stack slot");
    }
    if !function.stack_locals.is_empty() {
        out.push('\n');
    }

    for block in &function.blocks {
        let role = if block.role == "loop-header" {
            " // loop header"
        } else if block.role == "branch" {
            " // branch block"
        } else {
            ""
        };
        let _ = writeln!(out, "L_{:x}:{role}", block.address);
        for instruction in &block.instructions {
            if instruction.hidden_in_readable_output {
                continue;
            }
            if let Some((condition, target)) = conditional_parts(&instruction.pseudocode) {
                let _ = writeln!(out, "    if ({condition}) {{");
                let _ = writeln!(out, "        goto L_{target};");
                let _ = writeln!(out, "    }} {}", annotation(instruction, "//"));
            } else {
                let _ = writeln!(
                    out,
                    "    {:<56} {}",
                    instruction.pseudocode,
                    annotation(instruction, "//")
                );
            }
        }
        out.push('\n');
    }
    out.push_str("}\n\n");
}

fn render_rust_function(out: &mut String, function: &EnhancedFunction) {
    function_summary(out, function, "//");
    let _ = writeln!(out, "{} {{", rust_signature(function));
    for local in &function.stack_locals {
        let _ = writeln!(out, "    let mut {local}: usize; // inferred stack slot");
    }
    if !function.stack_locals.is_empty() {
        out.push('\n');
    }

    for block in &function.blocks {
        let _ = writeln!(
            out,
            "    // L_{:x} [{}], successors: {:?}",
            block.address, block.role, block.successors
        );
        for instruction in &block.instructions {
            if instruction.hidden_in_readable_output {
                continue;
            }
            if let Some((condition, target)) = conditional_parts(&instruction.pseudocode) {
                let condition = condition.replace("(signed)", "");
                let _ = writeln!(out, "    if {condition} {{");
                let _ = writeln!(out, "        goto_label(\"L_{target}\");");
                let _ = writeln!(out, "    }} {}", annotation(instruction, "//"));
            } else {
                let statement = rust_statement(&instruction.pseudocode);
                let _ = writeln!(
                    out,
                    "    {:<56} {}",
                    statement,
                    annotation(instruction, "//")
                );
            }
        }
        out.push('\n');
    }
    out.push_str("}\n\n");
}

fn render_python_function(out: &mut String, function: &EnhancedFunction) {
    function_summary(out, function, "#");
    let _ = writeln!(out, "{}:", python_signature(function));
    if function.blocks.is_empty() {
        out.push_str("    pass\n\n");
        return;
    }

    for block in &function.blocks {
        let _ = writeln!(
            out,
            "    # L_{:x} [{}], successors: {:?}",
            block.address, block.role, block.successors
        );
        for instruction in &block.instructions {
            if instruction.hidden_in_readable_output {
                continue;
            }
            if let Some((condition, target)) = conditional_parts(&instruction.pseudocode) {
                let condition = python_expression(condition);
                let _ = writeln!(out, "    if {condition}:");
                let _ = writeln!(out, "        goto(\"L_{target}\")");
                let _ = writeln!(out, "        {}", annotation(instruction, "#"));
            } else {
                let statement = python_statement(&instruction.pseudocode);
                let _ = writeln!(out, "    {statement}");
                let _ = writeln!(out, "    {}", annotation(instruction, "#"));
            }
        }
        out.push('\n');
    }
    out.push('\n');
}

fn render_assembly_function(out: &mut String, function: &EnhancedFunction) {
    function_summary(out, function, ";");
    let _ = writeln!(out, "; function {}", function.name);
    for block in &function.blocks {
        let _ = writeln!(out, "L_{:x}: ; {}", block.address, block.role);
        for instruction in &block.instructions {
            let symbol = instruction
                .symbol
                .as_deref()
                .map(|value| format!(" ; resolved: {value}"))
                .unwrap_or_default();
            let _ = writeln!(
                out,
                "    0x{:016x}: {:<42} ; {}{}",
                instruction.address, instruction.assembly, instruction.pseudocode, symbol
            );
        }
    }
    out.push('\n');
}

pub(super) fn render(report: &EnhancedReport, format: NativeOutputFormat) -> String {
    let mut out = String::new();
    render_header(&mut out, report, format);

    if format == NativeOutputFormat::C {
        out.push_str("#include <stdint.h>\n\n");
    }

    for function in &report.functions {
        match format {
            NativeOutputFormat::C => render_c_function(&mut out, function),
            NativeOutputFormat::Rust => render_rust_function(&mut out, function),
            NativeOutputFormat::Python => render_python_function(&mut out, function),
            NativeOutputFormat::Assembly => render_assembly_function(&mut out, function),
            NativeOutputFormat::Json => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_conditional_goto() {
        assert_eq!(
            conditional_parts("if (arg0 == 0) goto L_1234;"),
            Some(("arg0 == 0", "1234"))
        );
    }

    #[test]
    fn python_goto_is_readable() {
        assert_eq!(python_statement("goto L_1234;"), "goto(\"L_1234\")");
    }
}
