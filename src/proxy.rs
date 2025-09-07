use url::Url;

fn split_no_proxy(v: &str) -> Vec<String> {
    v.split(',')
        .map(|s| s.trim().to_lowercase())
        .filter(|s| !s.is_empty())
        .collect()
}

fn host_matches_no_proxy(host: &str, no_proxy_list: &[String]) -> bool {
    let host_l = host.to_lowercase();
    for pat in no_proxy_list {
        if pat == "*" {
            return true;
        }
        if host_l == *pat {
            return true;
        }
        if pat.starts_with('.') {
            if host_l.ends_with(pat) {
                return true;
            }
        }
    }
    false
}

pub fn choose_https_proxy(target_host: &str) -> Option<Url> {
    let no_proxy = std::env::var("NO_PROXY")
        .ok()
        .or_else(|| std::env::var("no_proxy").ok());
    if let Some(np) = no_proxy {
        let list = split_no_proxy(&np);
        if host_matches_no_proxy(target_host, &list) {
            return None;
        }
    }
    let cand = std::env::var("HTTPS_PROXY")
        .ok()
        .or_else(|| std::env::var("https_proxy").ok())
        .or_else(|| std::env::var("HTTP_PROXY").ok())
        .or_else(|| std::env::var("http_proxy").ok());
    cand.and_then(|s| Url::parse(&s).ok())
}
