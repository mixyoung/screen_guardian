use anyhow::Context;

fn main() -> anyhow::Result<()> {
    let mut args = std::env::args().skip(1);
    let hwnd = args
        .next()
        .context("missing hwnd argument")?
        .parse::<isize>()
        .context("invalid hwnd")?;
    let affinity = args
        .next()
        .context("missing affinity argument")?
        .parse::<u32>()
        .context("invalid affinity")?;

    apply_affinity(hwnd, affinity)
}

#[cfg(windows)]
fn apply_affinity(hwnd: isize, affinity: u32) -> anyhow::Result<()> {
    use windows::Win32::{
        Foundation::HWND,
        UI::WindowsAndMessaging::{SetWindowDisplayAffinity, WINDOW_DISPLAY_AFFINITY},
    };

    unsafe {
        let result = SetWindowDisplayAffinity(HWND(hwnd as *mut _), WINDOW_DISPLAY_AFFINITY(affinity));
        if let Err(e) = result {
            anyhow::bail!("SetWindowDisplayAffinity failed: {}", e);
        }
    }
    Ok(())
}

#[cfg(not(windows))]
fn apply_affinity(_hwnd: isize, _affinity: u32) -> anyhow::Result<()> {
    Ok(())
}
