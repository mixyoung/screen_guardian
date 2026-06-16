/// Format current local time as "YYYY-MM-DD HH:MM:SS.mmm"
pub fn format_now() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string()
}
