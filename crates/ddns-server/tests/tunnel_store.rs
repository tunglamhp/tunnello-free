mod common;

use ddns_server::account::AccountStore;
use ddns_server::domain::{DomainKind, DomainStore};
use ddns_server::token::TokenStore;
use ddns_server::tunnel::{HttpOptions, NewTunnel, TunnelStore};

async fn setup() -> (TokenStore, DomainStore, TunnelStore, String, String, String) {
    let ts = TokenStore::new();
    let (tid, _secret) = ts
        .create("store-test", ddns_proto::TokenLimits::default())
        .await
        .unwrap();
    let dom = DomainStore::open(&ts);
    let apex = dom
        .create("tunnel.example.com", DomainKind::Apex)
        .await
        .unwrap();
    let store = TunnelStore::open(&ts, &dom);
    // low-level insert path for a raw token record
    (ts, dom, store, tid, apex.id.clone(), apex.name)
}

#[tokio::test]
async fn create_constraints_and_lookup() {
    let (_ts, _dom, store, tid, did, _apex) = setup().await;
    let t = NewTunnel {
        name: "web".into(),
        token_id: tid.clone(),
        domain_id: did.clone(),
        subdomain: Some("my-fixed".into()),
        custom_hostname: None,
        options: HttpOptions::default(),
        ports: String::new(),
    };
    let rec = store.create(&t).await.unwrap();
    assert_eq!(rec.subdomain.as_deref(), Some("my-fixed"));
    assert!(
        rec.options.reverse_proxy_headers,
        "reverse-proxy headers default ON"
    );
    assert!(!rec.options.pass_preflight);

    // duplicate fixed subdomain rejected
    assert!(
        store.create(&t).await.is_err(),
        "duplicate subdomain must fail"
    );
    // slug shape rejected
    let bad = NewTunnel {
        name: "bad".into(),
        subdomain: Some("UPPER_slug!".into()),
        ports: String::new(),

        ..t.clone()
    };
    assert!(store.create(&bad).await.is_err(), "invalid slug must fail");
    // both subdomain and custom_hostname rejected
    let both = NewTunnel {
        subdomain: Some("a".into()),
        custom_hostname: Some("a.example.com".into()),
        ports: String::new(),

        ..t.clone()
    };
    assert!(
        store.create(&both).await.is_err(),
        "subdomain + custom_hostname are mutually exclusive"
    );
    // unknown token / domain rejected
    let badtok = NewTunnel {
        token_id: "t-nope".into(),
        ports: String::new(),

        ..t.clone()
    };
    assert!(store.create(&badtok).await.is_err());
    let baddom = NewTunnel {
        domain_id: "d-nope".into(),
        ports: String::new(),

        ..t.clone()
    };
    assert!(store.create(&baddom).await.is_err());

    // custom host lookup
    let c = NewTunnel {
        name: "cd".into(),
        token_id: tid.clone(),
        domain_id: did.clone(),
        subdomain: None,
        custom_hostname: Some("app.example.com".into()),
        options: HttpOptions::default(),
        ports: String::new(),
    };
    let crec = store.create(&c).await.unwrap();
    assert_eq!(
        store
            .custom_host("app.example.com")
            .await
            .unwrap()
            .unwrap()
            .id,
        crec.id
    );
    assert_eq!(
        store
            .custom_host("APP.example.com")
            .await
            .unwrap()
            .unwrap()
            .id,
        crec.id,
        "case-insensitive"
    );

    // resolve_for_token picks first enabled; hint prefers name match
    let by_default = store.resolve_for_token(&tid, None).await.unwrap().unwrap();
    assert_eq!(by_default.id, rec.id, "first created wins without hint");
    let by_hint = store
        .resolve_for_token(&tid, Some("cd"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(by_hint.id, crec.id, "hint prefers the named tunnel");
    assert!(
        store
            .resolve_for_token(&tid, Some("nope"))
            .await
            .unwrap()
            .is_some(),
        "unmatched hint falls back to first enabled"
    );

    // case-insensitive custom_hostname uniqueness
    let dup_case = NewTunnel {
        name: "dup-case".into(),
        token_id: tid.clone(),
        domain_id: did.clone(),
        subdomain: None,
        custom_hostname: Some("APP.example.com".into()),
        options: HttpOptions::default(),
        ports: String::new(),
    };
    assert!(
        store.create(&dup_case).await.is_err(),
        "case-insensitive duplicate custom_hostname must fail"
    );
}

#[tokio::test]
async fn update_toggle_delete() {
    let (_ts, _dom, store, tid, did, _apex) = setup().await;
    let t = NewTunnel {
        name: "x".into(),
        token_id: tid.clone(),
        domain_id: did.clone(),
        subdomain: None,
        custom_hostname: None,
        options: HttpOptions::default(),
        ports: String::new(),
    };
    let rec = store.create(&t).await.unwrap();
    assert!(!store.toggle(&rec.id).await.unwrap());
    assert!(store.toggle(&rec.id).await.unwrap());
    let upd = NewTunnel {
        name: "y".into(),
        subdomain: Some("new-slug".into()),
        ports: String::new(),

        ..t
    };
    store.update(&rec.id, &upd).await.unwrap();
    let got = store.list().await.unwrap().remove(0);
    assert_eq!(got.name, "y");
    assert_eq!(got.subdomain.as_deref(), Some("new-slug"));
    store.delete(&rec.id).await.unwrap();
    assert!(store.list().await.unwrap().is_empty());
}

#[tokio::test]
async fn options_json_round_trip() {
    let opts = HttpOptions {
        reverse_proxy_headers: true,
        basic_auth: Some(("admin".into(), "hunter2".into())),
        key_auth: Some("k-123".into()),
        pin_auth: Some("2468".into()),
        ip_whitelist: vec!["127.0.0.1".into(), "10.0.0.0/8".into()],
        https_only: true,
        host_rewrite: Some("internal.local".into()),
        add_headers: vec![("X-Foo".into(), "bar".into())],
        remove_headers: vec!["X-Bad".into()],
        pass_preflight: true,
        oidc_auth: true,
        email_otp: true,
    };
    let json = serde_json::to_string(&opts).unwrap();
    let back: HttpOptions = serde_json::from_str(&json).unwrap();
    assert_eq!(back, opts);
    let empty: HttpOptions = serde_json::from_str("{}").unwrap();
    assert!(
        empty.reverse_proxy_headers,
        "absent field must default to true"
    );
    assert!(empty.key_auth.is_none());
    assert!(empty.pin_auth.is_none());
    assert!(!empty.oidc_auth);
    assert!(!empty.email_otp);
}

#[tokio::test]
async fn create_sets_account_id_from_token_owner() {
    let ts = TokenStore::new();
    let accounts = AccountStore::open(&ts);
    let owner = accounts
        .create("owner@example.com", "h", "client")
        .await
        .unwrap();
    let (tid, _) = ts
        .create_owned("owned", ddns_proto::TokenLimits::default(), Some(owner.id))
        .await
        .unwrap();
    let dom = DomainStore::open(&ts);
    let apex = dom
        .create("tunnel.example.com", DomainKind::Apex)
        .await
        .unwrap();
    let store = TunnelStore::open(&ts, &dom);
    let rec = store
        .create(&NewTunnel {
            name: "web".into(),
            token_id: tid,
            domain_id: apex.id,
            subdomain: None,
            custom_hostname: None,
            options: HttpOptions::default(),
            ports: String::new(),
        })
        .await
        .unwrap();
    assert_eq!(rec.account_id, Some(owner.id));
    assert_eq!(rec.request_count, 0);
}

#[tokio::test]
async fn list_for_account_scopes_to_owner() {
    let ts = TokenStore::new();
    let accounts = AccountStore::open(&ts);
    let a1 = accounts
        .create("a1@example.com", "h", "client")
        .await
        .unwrap();
    let a2 = accounts
        .create("a2@example.com", "h", "client")
        .await
        .unwrap();
    let (t1, _) = ts
        .create_owned("t1", ddns_proto::TokenLimits::default(), Some(a1.id))
        .await
        .unwrap();
    let (t2, _) = ts
        .create_owned("t2", ddns_proto::TokenLimits::default(), Some(a2.id))
        .await
        .unwrap();
    let dom = DomainStore::open(&ts);
    let apex = dom
        .create("tunnel.example.com", DomainKind::Apex)
        .await
        .unwrap();
    let store = TunnelStore::open(&ts, &dom);
    let base = NewTunnel {
        name: String::new(),
        token_id: String::new(),
        domain_id: apex.id,
        subdomain: None,
        custom_hostname: None,
        options: HttpOptions::default(),
        ports: String::new(),
    };
    store
        .create(&NewTunnel {
            name: "a1-web".into(),
            token_id: t1,
            ports: String::new(),

            ..base.clone()
        })
        .await
        .unwrap();
    store
        .create(&NewTunnel {
            name: "a2-web".into(),
            token_id: t2,
            ports: String::new(),

            ..base.clone()
        })
        .await
        .unwrap();

    let for_a1 = store.list_for_account(a1.id).await.unwrap();
    assert_eq!(for_a1.len(), 1);
    assert_eq!(for_a1[0].name, "a1-web");
    let for_a2 = store.list_for_account(a2.id).await.unwrap();
    assert_eq!(for_a2.len(), 1);
    assert_eq!(for_a2[0].name, "a2-web");

    // An ownerless (operator/legacy) tunnel is not attributed to any tenant.
    let (t3, _) = ts
        .create("ownerless", ddns_proto::TokenLimits::default())
        .await
        .unwrap();
    store
        .create(&NewTunnel {
            name: "legacy".into(),
            token_id: t3,
            ports: String::new(),

            ..base
        })
        .await
        .unwrap();
    assert_eq!(store.list_for_account(a1.id).await.unwrap().len(), 1);
}

#[tokio::test]
async fn policy_upsert_list_delete_round_trip() {
    let (_ts, _dom, store, _tid, _did, _apex) = setup().await;

    // Create
    let id1 = store
        .save_policy("locked-down", r#"{"pin_auth":"1234"}"#)
        .await
        .unwrap();
    assert!(id1.starts_with("p-"));

    // Upsert by same name replaces options, keeps one row
    let id2 = store
        .save_policy("locked-down", r#"{"pin_auth":"9999"}"#)
        .await
        .unwrap();
    let list = store.list_policies().await.unwrap();
    assert_eq!(list.len(), 1, "upsert must not duplicate rows");
    assert_eq!(id2, id1, "same name must keep the same id");
    assert!(list[0].2.contains("9999"));

    // Second policy sorts by name
    store.save_policy("open", "{}").await.unwrap();
    let list = store.list_policies().await.unwrap();
    assert_eq!(list.len(), 2);
    assert_eq!(list[0].1, "locked-down");
    assert_eq!(list[1].1, "open");

    // Delete
    store.delete_policy(&id1).await.unwrap();
    let list = store.list_policies().await.unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].1, "open");
}
