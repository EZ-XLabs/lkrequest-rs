use std::ffi::{c_char, c_void, CString};
use std::fs::OpenOptions;
use std::sync::OnceLock;

use tracing::field::{Field, Visit};
use tracing::{Event, Level, Subscriber};
use tracing_subscriber::filter::LevelFilter;
use tracing_subscriber::layer::{Context, Layer};
use tracing_subscriber::prelude::*;

use crate::abi::lk_status_t;
use crate::conv::read_c_string;
use crate::error::FfiError;
use crate::panic::{catch_status, null_error_out};
use crate::types::lk_log_callback_t;

fn parse_level(level: &str) -> Result<tracing::Level, FfiError> {
    match level.to_ascii_lowercase().as_str() {
        "trace" => Ok(tracing::Level::TRACE),
        "debug" => Ok(tracing::Level::DEBUG),
        "info" => Ok(tracing::Level::INFO),
        "warn" | "warning" => Ok(tracing::Level::WARN),
        "error" => Ok(tracing::Level::ERROR),
        _ => Err(FfiError::invalid_argument(format!(
            "invalid log level: {level}"
        ))),
    }
}

fn parse_callback_level(level: i32) -> Result<Level, FfiError> {
    match level {
        0 => Ok(Level::TRACE),
        1 => Ok(Level::DEBUG),
        2 => Ok(Level::INFO),
        3 => Ok(Level::WARN),
        4 => Ok(Level::ERROR),
        _ => Err(FfiError::invalid_argument(format!(
            "invalid callback log level: {level}"
        ))),
    }
}

fn sanitize_c_string(input: &str) -> CString {
    CString::new(input.replace('\0', " ")).expect("sanitized string contains no NUL")
}

fn level_to_i32(level: &Level) -> i32 {
    match *level {
        Level::TRACE => 0,
        Level::DEBUG => 1,
        Level::INFO => 2,
        Level::WARN => 3,
        Level::ERROR => 4,
    }
}

#[derive(Default)]
struct EventMessageVisitor {
    message: Option<String>,
    fields: Vec<String>,
}

impl EventMessageVisitor {
    fn finish(self) -> String {
        match (self.message, self.fields.is_empty()) {
            (Some(message), true) => message,
            (Some(message), false) => format!("{message} {}", self.fields.join(" ")),
            (None, _) => self.fields.join(" "),
        }
    }
}

impl Visit for EventMessageVisitor {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = Some(value.to_string());
        } else {
            self.fields.push(format!("{}={value}", field.name()));
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = Some(format!("{value:?}"));
        } else {
            self.fields.push(format!("{}={value:?}", field.name()));
        }
    }
}

struct CallbackLayer {
    callback: unsafe extern "C" fn(
        context: *mut c_void,
        level: i32,
        target: *const c_char,
        message: *const c_char,
    ),
    context: *mut c_void,
}

unsafe impl Send for CallbackLayer {}
unsafe impl Sync for CallbackLayer {}

impl<S> Layer<S> for CallbackLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &Event<'_>, _ctx: Context<'_, S>) {
        let mut visitor = EventMessageVisitor::default();
        event.record(&mut visitor);

        let target = sanitize_c_string(event.metadata().target());
        let message = sanitize_c_string(&visitor.finish());
        unsafe {
            (self.callback)(
                self.context,
                level_to_i32(event.metadata().level()),
                target.as_ptr(),
                message.as_ptr(),
            );
        }
    }
}

fn initialize_once(init: impl FnOnce() -> Result<(), FfiError>) -> Result<(), FfiError> {
    static INIT: OnceLock<()> = OnceLock::new();

    if INIT.get().is_some() {
        return Ok(());
    }

    init()?;
    let _ = INIT.set(());
    Ok(())
}

#[no_mangle]
pub extern "C" fn lk_log_init(
    level_ptr: *const std::ffi::c_char,
    file_path_ptr: *const std::ffi::c_char,
) -> lk_status_t {
    catch_status(null_error_out(), || unsafe {
        initialize_once(|| {
            let level = parse_level(&read_c_string(level_ptr, "level")?)?;
            let file_path = read_c_string(file_path_ptr, "file_path")?;
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&file_path)
                .map_err(|err| {
                    FfiError::invalid_config(format!("failed to open log file: {err}"))
                })?;
            let file_path = std::path::PathBuf::from(file_path);
            let make_writer =
                tracing_subscriber::fmt::writer::BoxMakeWriter::new(move || {
                    match file.try_clone().or_else(|_| {
                        OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(&file_path)
                    }) {
                        Ok(file) => Box::new(file) as Box<dyn std::io::Write + Send>,
                        Err(_) => Box::new(std::io::sink()) as Box<dyn std::io::Write + Send>,
                    }
                });

            let subscriber = tracing_subscriber::fmt()
                .with_ansi(false)
                .with_max_level(level)
                .with_writer(make_writer)
                .finish();

            tracing::subscriber::set_global_default(subscriber).map_err(|err| {
                FfiError::invalid_config(format!("failed to initialize global logger: {err}"))
            })
        })
    })
}

#[no_mangle]
pub extern "C" fn lk_log_init_callback(
    callback: lk_log_callback_t,
    context: *mut c_void,
    min_level: i32,
) -> lk_status_t {
    catch_status(null_error_out(), || {
        initialize_once(|| {
            let callback =
                callback.ok_or_else(|| FfiError::invalid_argument("log callback is null"))?;
            let level = parse_callback_level(min_level)?;
            let subscriber = tracing_subscriber::registry().with(
                CallbackLayer { callback, context }.with_filter(LevelFilter::from_level(level)),
            );
            tracing::subscriber::set_global_default(subscriber).map_err(|err| {
                FfiError::invalid_config(format!("failed to initialize global logger: {err}"))
            })
        })
    })
}
