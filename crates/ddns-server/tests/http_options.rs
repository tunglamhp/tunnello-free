mod common;

use axum::body::Body;
use axum::http::header::{AUTHORIZATION, HOST, WWW_AUTHENTICATE};
use axum::http::{Request, StatusCode};
use ddns_server::http_options::{apply, cidr_matches};
use ddns_server::tunnel::HttpOptions;
use std::net::{IpAddr, Ipv4Addr};

fn req(method: &str, uri: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .unwrap()
}
fn req_with(method: &str, uri: &str, headers: &[(&str, &str)]) -> Request<Body> {
    let mut b = Request::builder().method(method).uri(uri);
    for (k, v) in headers {
        b = b.header(*k, *v);
    }
    b.body(Body::empty()).unwrap()
}

#[test]
fn cidr_matching() {
    let ip: IpAddr = Ipv4Addr::new(10, 1, 2, 3).into();
    assert!(cidr_matches(ip, &["10.1.2.3".into()]));
    assert!(cidr_matches(ip, &["10.0.0.0/8".into()]));
    assert!(!cidr_matches(ip, &["10.2.0.0/16".into()]));
    assert!(!cidr_matches(ip, &["192.168.0.0/16".into()]));
    let v6: IpAddr = "2001:db8::1".parse().unwrap();
    assert!(cidr_matches(v6, &["2001:db8::/32".into()]));
}

#[test]
fn whitelist_blocks_and_allows() {
    let opts = HttpOptions {
        ip_whitelist: vec!["127.0.0.1".into()],
        ..Default::default()
    };
    let ip: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
    assert!(
        apply(&mut req("GET", "/"), ip, &opts).is_none(),
        "allowed ip passes"
    );
    let other: IpAddr = Ipv4Addr::new(8, 8, 8, 8).into();
    let resp = apply(&mut req("GET", "/"), other, &opts).unwrap();
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
}

#[test]
fn basic_auth_challenges_and_passes() {
    let opts = HttpOptions {
        basic_auth: Some(("u".into(), "p".into())),
        ..Default::default()
    };
    let ip: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
    let resp = apply(&mut req("GET", "/"), ip, &opts).unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(format!("{:?}", resp.headers().get(WWW_AUTHENTICATE)).contains("Basic"));
    let mut ok = req_with("GET", "/", &[(AUTHORIZATION.as_str(), "Basic dTpw")]); // base64("u:p")
    assert!(
        apply(&mut ok, ip, &opts).is_none(),
        "valid credentials pass"
    );
}

#[test]
fn key_auth_requires_bearer() {
    let opts = HttpOptions {
        key_auth: Some("sekret".into()),
        ..Default::default()
    };
    let ip: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
    assert_eq!(
        apply(&mut req("GET", "/"), ip, &opts).unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
    let mut good = req_with("GET", "/", &[(AUTHORIZATION.as_str(), "Bearer sekret")]);
    assert!(apply(&mut good, ip, &opts).is_none());
}

#[test]
fn preflight_bypasses_auth_only_when_enabled() {
    let ip: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
    let pre = || req_with("OPTIONS", "/", &[("Access-Control-Request-Method", "POST")]);
    let passthrough = HttpOptions {
        basic_auth: Some(("u".into(), "p".into())),
        pass_preflight: true,
        ..Default::default()
    };
    assert!(
        apply(&mut pre(), ip, &passthrough).is_none(),
        "preflight passes with pass_preflight"
    );
    let strict = HttpOptions {
        basic_auth: Some(("u".into(), "p".into())),
        pass_preflight: false,
        ..Default::default()
    };
    assert_eq!(
        apply(&mut pre(), ip, &strict).unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

#[test]
fn header_mutations() {
    let opts = HttpOptions {
        reverse_proxy_headers: true,
        host_rewrite: Some("internal.local".into()),
        add_headers: vec![("X-Foo".into(), "bar".into())],
        remove_headers: vec!["X-Bad".into()],
        ..Default::default()
    };
    let ip: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
    let mut r = req_with(
        "GET",
        "/",
        &[(HOST.as_str(), "orig.example.com"), ("X-Bad", "gone")],
    );
    assert!(apply(&mut r, ip, &opts).is_none());
    let h = r.headers();
    assert_eq!(h.get(HOST).unwrap(), "internal.local");
    assert_eq!(h.get("X-Foo").unwrap(), "bar");
    assert!(h.get("X-Bad").is_none(), "removed header must be gone");
    assert_eq!(h.get("X-Forwarded-For").unwrap(), "127.0.0.1");
    assert_eq!(h.get("X-Forwarded-Proto").unwrap(), "https");
    assert_eq!(h.get("X-Forwarded-Host").unwrap(), "orig.example.com");
    assert!(h.get("Forwarded").is_some());
}

#[test]
fn pin_auth_challenges_without_cookie() {
    let opts = HttpOptions {
        pin_auth: Some("1234".into()),
        ..Default::default()
    };
    let ip: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
    let resp = apply(&mut req("GET", "/"), ip, &opts).unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    // Body is HTML with a PIN form
    // (We can't easily read the body here, but status is enough.)
}

#[test]
fn pin_auth_passes_with_correct_query_pin() {
    let opts = HttpOptions {
        pin_auth: Some("1234".into()),
        ..Default::default()
    };
    let ip: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
    let resp = apply(&mut req("GET", "/?pin=1234"), ip, &opts).unwrap();
    // Redirect to / after successful PIN entry
    assert_eq!(resp.status(), StatusCode::SEE_OTHER);
    // Sets a tunnello_pin cookie
    let set_cookie = resp.headers().get("set-cookie").unwrap().to_str().unwrap();
    assert!(set_cookie.contains("tunnello_pin=1234"));
}

#[test]
fn pin_auth_rejects_wrong_query_pin() {
    let opts = HttpOptions {
        pin_auth: Some("1234".into()),
        ..Default::default()
    };
    let ip: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
    let resp = apply(&mut req("GET", "/?pin=9999"), ip, &opts).unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[test]
fn pin_auth_passes_with_valid_cookie() {
    let opts = HttpOptions {
        pin_auth: Some("1234".into()),
        ..Default::default()
    };
    let ip: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
    let mut ok = req_with("GET", "/", &[("Cookie", "tunnello_pin=1234")]);
    assert!(apply(&mut ok, ip, &opts).is_none(), "valid cookie passes");
}

#[test]
fn pin_auth_rejects_wrong_cookie() {
    let opts = HttpOptions {
        pin_auth: Some("1234".into()),
        ..Default::default()
    };
    let ip: IpAddr = Ipv4Addr::new(127, 0, 0, 1).into();
    let mut bad = req_with("GET", "/", &[("Cookie", "tunnello_pin=wrong")]);
    assert_eq!(
        apply(&mut bad, ip, &opts).unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}
