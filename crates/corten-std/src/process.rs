//! `ExecCap`, `ProcessInvocation` and `process!` (spec 4.4, 4.5; CWE-77,
//! 78, 426 to 428).
//!
//! A program is named by an [`ExecCap`] from the capability manifest,
//! never by a string searched in `PATH`. Arguments are an argv vector, never
//! a shell string. Options are compile-time literals; runtime values are
//! operands, placed after `--` so a value beginning with `-` is not read as
//! an option by programs that follow the POSIX convention (CWE-88 stays C:
//! not every program honours `--`).
//!
//! Corten has no ambient spawn: an invocation is a value handed to the
//! process broker (Phase 3), which runs it under the declared limits.
//!
//! ```ignore
//! let tar: ExecCap = caps.take_exec("tar")?;
//! let job = corten_std::process!(tar, "-c", "-f"; archive, directory)?;
//! ```

use std::fmt;
use std::path::{Path, PathBuf};

/// The authority to run one program, granted by the manifest.
#[derive(Debug)]
pub struct ExecCap {
    name: String,
    path: PathBuf,
}

impl ExecCap {
    pub(crate) fn new(name: String, path: PathBuf) -> Self {
        Self { name, path }
    }

    /// The manifest name of the program.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Why an argument was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgError {
    /// Arguments are C strings to the operating system; a NUL would cut one
    /// short (CWE-626).
    Nul,
}

impl fmt::Display for ArgError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a process argument may not contain NUL")
    }
}

impl std::error::Error for ArgError {}

/// Literal options, written by the program's author: a label (spec 4.2), so
/// runtime operands cannot be passed where options belong.
#[derive(Debug, Clone, Copy)]
pub struct Options<'a>(pub &'a [&'static str]);

/// Runtime operands, placed after `--`: a label, as [`Options`].
#[derive(Debug, Clone, Copy)]
pub struct Operands<'a, 'b>(pub &'a [&'b str]);

/// A program and its argv, ready for the process broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInvocation {
    program: PathBuf,
    argv: Vec<String>,
}

impl ProcessInvocation {
    /// `exec` with literal `options`, then `--`, then runtime `operands`.
    /// Use the [`process!`](crate::process!) macro.
    ///
    /// # Errors
    ///
    /// [`ArgError::Nul`] if any argument contains NUL.
    pub fn new(
        exec: &ExecCap,
        Options(options): Options<'_>,
        Operands(operands): Operands<'_, '_>,
    ) -> Result<Self, ArgError> {
        let mut argv = Vec::with_capacity(
            options
                .len()
                .saturating_add(operands.len())
                .saturating_add(1),
        );
        for arg in options.iter().copied().chain(operands.iter().copied()) {
            if arg.contains('\0') {
                return Err(ArgError::Nul);
            }
        }
        argv.extend(options.iter().map(|s| (*s).to_owned()));
        if !operands.is_empty() {
            argv.push("--".to_owned());
            argv.extend(operands.iter().map(|s| (*s).to_owned()));
        }
        Ok(Self {
            program: exec.path.clone(),
            argv,
        })
    }

    /// The program the manifest granted.
    #[must_use]
    pub fn program(&self) -> &Path {
        &self.program
    }

    /// The arguments, without the program name.
    #[must_use]
    pub fn argv(&self) -> &[String] {
        &self.argv
    }
}

/// Builds a [`ProcessInvocation`]: `process!(exec, "-opt", ...; operand, ...)`.
#[macro_export]
macro_rules! process {
    ($exec:expr $(, $opt:literal)* ; $($operand:expr),* $(,)?) => {
        $crate::process::ProcessInvocation::new(
            &$exec,
            $crate::process::Options(&[$($opt),*]),
            $crate::process::Operands(&[$(::core::convert::AsRef::<str>::as_ref(&$operand)),*]),
        )
    };
    ($exec:expr $(, $opt:literal)* $(,)?) => {
        $crate::process::ProcessInvocation::new(
            &$exec,
            $crate::process::Options(&[$($opt),*]),
            $crate::process::Operands(&[]),
        )
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tar() -> ExecCap {
        ExecCap::new("tar".to_owned(), PathBuf::from("/usr/bin/tar"))
    }

    #[test]
    fn options_then_separator_then_operands() {
        let archive = String::from("--checkpoint-action=exec=sh");
        let job = crate::process!(tar(), "-c", "-f"; archive, "dir").unwrap();
        assert_eq!(job.program(), Path::new("/usr/bin/tar"));
        assert_eq!(
            job.argv(),
            ["-c", "-f", "--", "--checkpoint-action=exec=sh", "dir"]
        );
    }

    #[test]
    fn no_operands_means_no_separator() {
        let job = crate::process!(tar(), "--version").unwrap();
        assert_eq!(job.argv(), ["--version"]);
    }

    #[test]
    fn shell_metacharacters_stay_one_argument() {
        let job = crate::process!(tar(), "-f"; "a; rm -rf / #").unwrap();
        assert_eq!(job.argv(), ["-f", "--", "a; rm -rf / #"]);
    }

    #[test]
    fn nul_is_refused() {
        assert_eq!(crate::process!(tar(), "-f"; "a\0b"), Err(ArgError::Nul));
    }
}
