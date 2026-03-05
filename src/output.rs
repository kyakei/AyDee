use colored::*;

/// Print the AyDee banner
pub fn banner() {
    let banner = r#"
                  _            
   __ _ _   _  __| | ___  ___  
  / _` | | | |/ _` |/ _ \/ _ \ 
 | (_| | |_| | (_| |  __/  __/ 
  \__,_|\__, |\__,_|\___|\___| 
        |___/                  
    "#;
    println!("{}", banner.bright_red().bold());
    println!(
        "  {} {}\n",
        "AyDee - Active Directory Enumeration Tool".white().bold(),
        "v0.1.0".bright_black()
    );
}

/// Print a success message
pub fn success(msg: &str) {
    println!("  {} {}", "[+]".green().bold(), msg);
}

/// Print an info message
pub fn info(msg: &str) {
    println!("  {} {}", "[*]".blue().bold(), msg);
}

/// Print a warning message
pub fn warning(msg: &str) {
    println!("  {} {}", "[!]".yellow().bold(), msg);
}

/// Print a failure/negative result
pub fn fail(msg: &str) {
    println!("  {} {}", "[-]".red().bold(), msg);
}

/// Print a section header
pub fn section(title: &str) {
    println!("\n  {} {}", "━━━".bright_red(), title.white().bold());
    println!(
        "  {}",
        "─────────────────────────────────────────".bright_black()
    );
}

/// Print a key-value pair with formatting
pub fn kv(key: &str, value: &str) {
    println!(
        "    {} {} {}",
        "›".bright_black(),
        format!("{:<24}", key).bright_cyan(),
        value.white()
    );
}

/// Print a table row for port scan results
pub fn port_open(port: u16, service: &str) {
    println!(
        "    {} {:<8} {}",
        "●".green(),
        format!("{}/tcp", port).white().bold(),
        service.bright_green()
    );
}

pub fn port_closed(port: u16, service: &str) {
    println!(
        "    {} {:<8} {}",
        "○".bright_black(),
        format!("{}/tcp", port).bright_black(),
        service.bright_black()
    );
}

/// Print a summary line
pub fn summary(open: usize, closed: usize) {
    println!(
        "\n  {} {} open, {} closed",
        "⤷".bright_black(),
        format!("{}", open).green().bold(),
        format!("{}", closed).bright_black()
    );
}
