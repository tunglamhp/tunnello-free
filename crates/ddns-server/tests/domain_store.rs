mod common;

use ddns_server::domain::{CertStatus, DomainKind, DomainStore, ValidationStatus};

fn store() -> DomainStore {
    DomainStore::open(&ddns_server::token::TokenStore::new())
}

#[tokio::test]
async fn create_list_update_activate_delete() {
    let s = store();
    let d = s.create("ops.example.com", DomainKind::Apex).await.unwrap();
    assert_eq!(d.kind, DomainKind::Apex);
    assert_eq!(d.validation_status, ValidationStatus::Pending);
    assert_eq!(d.cert_status, CertStatus::Absent);
    assert!(!d.active, "new apex starts inactive");
    assert_eq!(
        s.apex_names().await.unwrap(),
        vec!["ops.example.com".to_string()]
    );

    let c = s
        .create("app.ops.example.com", DomainKind::Custom)
        .await
        .unwrap();
    assert!(s.get(&c.id).await.unwrap().is_some());

    // activating one apex clears the previous one
    let d2 = s
        .create("third.example.com", DomainKind::Apex)
        .await
        .unwrap();
    s.activate(&d.id).await.unwrap();
    s.activate(&d2.id).await.unwrap();
    assert_eq!(s.active_apex().await.unwrap().unwrap().id, d2.id);

    s.update(&d.id, "ops2.example.com", DomainKind::Apex)
        .await
        .unwrap();
    assert_eq!(
        s.get(&d.id).await.unwrap().unwrap().name,
        "ops2.example.com"
    );

    s.delete(&c.id).await.unwrap();
    s.delete(&d.id).await.unwrap();
    s.delete(&d2.id).await.unwrap();
    assert!(s.active_apex().await.unwrap().is_none());
}

#[tokio::test]
async fn duplicate_name_rejected() {
    let s = store();
    s.create("dup.example.com", DomainKind::Apex).await.unwrap();
    assert!(s.create("dup.example.com", DomainKind::Apex).await.is_err());
}

#[tokio::test]
async fn seed_from_config_is_idempotent_and_activates() {
    let s = store();
    s.seed_from_config("tunnel.example.com");
    s.seed_from_config("tunnel.example.com");
    assert_eq!(
        s.apex_names().await.unwrap(),
        vec!["tunnel.example.com".to_string()]
    );
    assert_eq!(
        s.active_apex().await.unwrap().unwrap().name,
        "tunnel.example.com"
    );
    // manual apex already exists → seed does not duplicate
    s.create("other.example.com", DomainKind::Apex)
        .await
        .unwrap();
    s.seed_from_config("tunnel.example.com");
    assert_eq!(s.apex_names().await.unwrap().len(), 2);
}
