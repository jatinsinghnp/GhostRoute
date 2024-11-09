use std::fs::File;
use std::io::{self, BufRead, BufReader};
use reqwest::blocking::Client;
use colored::*;
use std::collections::HashSet;
use url::Url;

// Replaces any parameter value that starts with "http" with the specified payload
fn modify_url_parameters(target_url: &str, malicious_link: &str) -> String {
    if let Ok(mut parsed_url) = Url::parse(target_url) {
        let modified_query: Vec<(String, String)> = parsed_url
            .query_pairs()
            .map(|(key, value)| {
                if value.starts_with("http") {
                    (key.to_string(), malicious_link.to_string())
                } else {
                    (key.to_string(), value.to_string())
                }
            })
            .collect();
        parsed_url.query_pairs_mut().clear().extend_pairs(modified_query);
        return parsed_url.to_string();
    }
    target_url.to_string()
}

// Validates that the URL has an acceptable scheme (http or https)
fn is_supported_url(target_url: &str) -> bool {
    match Url::parse(target_url) {
        Ok(parsed_url) => parsed_url.scheme() == "http" || parsed_url.scheme() == "https",
        Err(_) => false,
    }
}

fn main() -> io::Result<()> {
    println!("{}","
  ________.__                    __ __________               __          
 /  _____/|  |__   ____  _______/  |_____   __|____  __ ___/  |_  ____  
/   \\  ___|  |  \\ /  _ \\/  ___/\\   __\\       _//  _ \\|  |  \\   __\\/ __ \\ 
\\    \\\\_\\  \\   Y  (  <_> )___ \\  |  | |    |   (  <_> )  |  /|  | \\  ___/ 
 \\______  /___|  /\\____/____  > |__| |____|_  /\\____/|____/ |__|  \\___  >
        \\/     \\/           \\/              \\/                        \\/ 

RedirReaper - Open Redirect Scanner
Version: 1.0
Developed by CyberGhost (Jatin Singh Tomar)".bright_red());

    // Get the file name from user input
    println!("Enter the filename containing the list of URLs:");
    let mut input_filename = String::new();
    io::stdin().read_line(&mut input_filename)?;
    let input_filename = input_filename.trim();

    // Open the file and read URLs
    let file = File::open(input_filename)?;
    let reader = BufReader::new(file);
    let url_list: Vec<String> = reader.lines().filter_map(|line| line.ok()).collect();

    let malicious_redirect = "http://malicious-site.com";
    let client = Client::new();
    let mut checked_urls = HashSet::new();

    // Loop through URLs and test for Open Redirect vulnerabilities
    for original_url in url_list {
        let altered_url = modify_url_parameters(&original_url, malicious_redirect);

        if checked_urls.contains(&altered_url) {
            continue;
        }

        if !is_supported_url(&altered_url) {
            println!("Skipping unsupported URL scheme for: {}", altered_url);
            continue;
        }

        // Send HTTP GET request to the modified URL
        match client.get(&altered_url).send() {
            Ok(response) => {
                let status_code = response.status();

                if status_code.is_redirection() {
                    if let Some(location) = response.headers().get("Location") {
                        let location_str = location.to_str().unwrap_or("");
                        if location_str == malicious_redirect {
                            println!("{} {}", "Potential Open Redirect Detected:".red(), altered_url);
                        } else {
                            println!("{} {}: {}", "Redirected to a different location for".yellow(), altered_url, location_str);
                        }
                    } else {
                        println!("{} {}", "Redirection status received but no Location header for".yellow(), altered_url);
                    }
                } else {
                    let body_content = response.text().unwrap_or_else(|_| String::from(""));
                    if body_content.contains("malicious redirect detected") {
                        println!("{} {}", "Open Redirect Detected in response body:".red(), altered_url);
                    } else {
                        println!("{} {}: Status {}", "No redirect for".green(), altered_url, status_code);
                    }
                }
            }
            Err(e) => eprintln!("Failed to send request to {}: {}", altered_url, e),
        }

        checked_urls.insert(altered_url);
    }

    Ok(())
}

