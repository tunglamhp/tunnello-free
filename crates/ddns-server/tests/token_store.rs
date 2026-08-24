//! Plan 3 Task 1 acceptance: SQLite + argon2 token store tests.

mod common;

use ddns_proto::TokenLimits;
use ddns_server::TokenStore;

#[tokio::test]
async fn create_returns_show_once_secret() {
    let store = TokenStore::new();
    let (id, secret) = store
        .create("test-token", TokenLimits::default())
        .await
        .unwrap();

    assert!(secret.starts_with("tok_"), "secret must start with tok_");
    assert!(secret.len() > 20, "secret must be long enough");
    // The secret is NOT visible in list:
    let records = store.list().await;
    let found = records.iter().find(|r| r.id == id).unwrap();
    // The id matches but the secret is never returned by list:
    assert_eq!(found.name, "test-token");
    // Secret can't be recovered — validate only proves possession.
}

#[tokio::test]
async fn validate_roundtrip() {
    let store = TokenStore::new();
    let limits = TokenLimits {
        max_streams: 5,
        ..TokenLimits::default()
    };
    let (id, secret) = store.create("vtest", limits).await.unwrap();

    let record = store.validate(&secret).await.unwrap();
    assert_eq!(record.id, id);
    assert_eq!(record.limits.max_streams, 5);
    assert!(record.enabled);

    // Wrong secret -> None:
    assert!(store.validate("nope").await.is_none());
    assert!(store.validate(&format!("{}x", secret)).await.is_none());
}

#[tokio::test]
async fn disabled_token_rejected() {
    let store = TokenStore::new();
    let (id, secret) = store
        .create("toggle", TokenLimits::default())
        .await
        .unwrap();

    // Initially enabled:
    assert!(store.validate(&secret).await.is_some());

    // Disable it:
    store.set_enabled(&id, false).await.unwrap();
    assert!(
        store.validate(&secret).await.is_none(),
        "disabled must reject"
    );

    // Re-enable:
    store.set_enabled(&id, true).await.unwrap();
    assert!(
        store.validate(&secret).await.is_some(),
        "re-enabled must pass"
    );
}

#[tokio::test]
async fn delete_revokes() {
    let store = TokenStore::new();
    let (id, secret) = store.create("delme", TokenLimits::default()).await.unwrap();

    assert!(store.validate(&secret).await.is_some());

    store.delete(&id).await.unwrap();

    assert!(
        store.validate(&secret).await.is_none(),
        "deleted must not validate"
    );
    let ids: Vec<_> = store.list().await.into_iter().map(|r| r.id).collect();
    assert!(!ids.contains(&id), "list must not include deleted id");
}

#[tokio::test]
async fn insert_with_known_secret_works() {
    let store = TokenStore::new();
    let record = common::test_record("t-known", true);
    store.insert("tok_test".into(), record).await.unwrap();

    let validated = store.validate("tok_test").await.unwrap();
    assert_eq!(validated.id, "t-known");
    // Wrong secret still fails:
    assert!(store.validate("other").await.is_none());
}

#[tokio::test]
async fn persists_across_reopen() {
    let path = std::env::temp_dir().join(format!("ddns-test-persist-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path); // clean up from prior run

    let (id, secret, s1) = {
        let store = TokenStore::open(&path).unwrap();
        let (id, secret) = store
            .create("persistent", TokenLimits::default())
            .await
            .unwrap();
        // Verify server_secret is generated and cached:
        let s1 = store.server_secret().await.unwrap();
        assert_eq!(s1.len(), 32);
        let _pw = store.set_admin_password("hash123".into()).await;
        (id, secret, s1)
    };

    // Re-open:
    let store2 = TokenStore::open(&path).unwrap();

    // Token still validates:
    let record = store2.validate(&secret).await.unwrap();
    assert_eq!(record.id, id);
    assert_eq!(record.name, "persistent");

    // server_secret stable across reopen:
    let s2 = store2.server_secret().await.unwrap();
    assert_eq!(s1, s2, "server_secret must be stable across reopen");

    // admin_password roundtrip:
    let pw = store2.admin_password().await;
    assert_eq!(pw.as_deref(), Some("hash123"));

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn hash_format_is_argon2id() {
    // Peek the stored hash directly: it must be an argon2id PHC string.
    let path = std::env::temp_dir().join(format!("ddns-test-argon2-{}.db", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let store = TokenStore::open(&path).unwrap();
    let (id, secret) = store
        .create("hashcheck", TokenLimits::default())
        .await
        .unwrap();

    let conn = rusqlite::Connection::open(&path).unwrap();
    let hash: String = conn
        .query_row("SELECT secret_hash FROM tokens WHERE id=?1", [&id], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(
        hash.starts_with("$argon2id$"),
        "stored hash must be argon2id, got: {hash}"
    );

    // And the stored hash actually verifies the secret:
    assert!(store.validate(&secret).await.is_some());

    // insert() with a known secret produces the same format:
    let store2 = TokenStore::open(&path).unwrap();
    store2
        .insert("plain".into(), common::test_record("t-plain", true))
        .await
        .unwrap();
    let hash2: String = conn
        .query_row(
            "SELECT secret_hash FROM tokens WHERE id=?1",
            ["t-plain"],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        hash2.starts_with("$argon2id$"),
        "inserted hash must be argon2id, got: {hash2}"
    );
    assert!(store2.validate("plain").await.is_some());

    let _ = std::fs::remove_file(&path);
}

#[tokio::test]
async fn concurrent_creates() {
    let store = TokenStore::new();

    let handles: Vec<_> = (0..8)
        .map(|i| {
            let s = store.clone();
            tokio::spawn(async move {
                s.create(&format!("c{i}"), TokenLimits::default())
                    .await
                    .unwrap()
            })
        })
        .collect();

    let mut results = Vec::new();
    for h in handles {
        results.push(h.await.unwrap());
    }

    // All secrets validate:
    for (id, secret) in &results {
        let record = store.validate(secret).await.unwrap();
        assert_eq!(record.id, *id);
    }

    // All ids distinct:
    let mut ids: Vec<_> = results.iter().map(|(id, _)| id.clone()).collect();
    ids.sort();
    ids.dedup();
    assert_eq!(ids.len(), 8);

    // List has all 8:
    assert_eq!(store.list().await.len(), 8);
}

#[test]
fn schema_creates_domains_and_tunnels_tables() {
    let store = ddns_server::token::TokenStore::new();
    let conn = store.db_conn().lock().unwrap_or_else(|p| p.into_inner());
    let count: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name IN ('domains','tunnels')",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 2, "domains and tunnels tables must exist after init");
}
