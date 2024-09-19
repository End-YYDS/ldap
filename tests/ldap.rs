use dotenv::dotenv;
use ldap::{self, Groups, Ldap, User};
use ldap3::{LdapError, Scope};
use serial_test::serial;

fn config() -> (String, String, String, String) {
    dotenv().ok();
    let bind_dn = std::env::var("BIND_DN").expect("BIND_DN is not set in .env file");
    let bind_pw = std::env::var("BIND_PW").expect("BIND_PW is not set in .env file");
    let bind_ip = std::env::var("BIND_IP").expect("BIND_IP is not set in .env file");
    let base_dn = std::env::var("BASE_DN").expect("BASE_DN is not set in .env file");
    (bind_dn, bind_pw, bind_ip, base_dn)
}
fn bind() -> (Ldap, Result<(), LdapError>) {
    let (bind_dn, bind_pw, bind_ip, base_dn) = config();
    let mut ldap = Ldap::new(&bind_ip, &base_dn).unwrap();
    let ret = ldap.bind(&bind_dn, &bind_pw);
    (ldap, ret)
}

#[test]
#[serial]
fn read_env_file() {
    let ret = dotenv();
    assert!(ret.is_ok());
}

#[test]
#[serial]
fn test_ldap_bind() {
    let (_ldap, ret) = bind();
    assert!(ret.is_ok());
}

#[test]
#[serial]
fn test_ldap_add_user() {
    let (mut ldap, _) = bind();
    let new_user = User::new(
        "test",
        "test12345678",
        "Test User",
        "User",
        "/home/test",
        "/bin/bash",
        "Test",
        "Test User",
        "10001",
        "5000",
        "Test User",
        Groups::People,
    );
    let ret = ldap.add_user(&new_user);
    assert!(ret.is_ok());
}

#[test]
#[serial]
fn test_ldap_search_user() {
    let (mut ldap, _) = bind();
    let ret = ldap.search_entry(
        Scope::Subtree,
        "(uid=test)",
        vec![
            "dn",
            "cn",
            "sn",
            "uid",
            "uidNumber",
            "gidNumber",
            "homeDirectory",
            "loginShell",
            "userPassword",
        ],
    );
    assert!(ret.is_ok());
}

#[test]
#[serial]
fn test_ldap_change_password() {
    let (mut ldap, _) = bind();
    let ret = ldap.change_password("test", "12345678");
    assert!(ret.is_ok());
    let ret = ldap.check_login("test", "12345678");
    assert!(ret.is_ok());
}

#[test]
#[serial]
fn test_ldap_del_user() {
    let (mut ldap, _) = bind();
    let ret = ldap.del_user("test");
    assert!(ret.is_ok());
}
