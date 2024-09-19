use std::collections::HashSet;
use std::fmt;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use ldap3::result::Result;
use ldap3::{LdapConn, LdapConnSettings, Mod, Scope, SearchEntry};
use rand::Rng;
use sha1::{Digest, Sha1};

pub struct Ldap {
    conn: LdapConn,
    base_dn: String,
}

#[allow(dead_code)]
pub struct User<'a> {
    uid: &'a str,
    user_password: &'a str,
    cn: &'a str,
    sn: &'a str,
    home_directory: &'a str,
    login_shell: &'a str,
    given_name: &'a str,
    display_name: &'a str,
    uid_number: &'a str,
    gid_number: &'a str,
    gecos: &'a str,
    ou: Groups,
}
#[allow(dead_code)]
pub enum Groups {
    People,
    Group,
    Other,
}
impl fmt::Display for Groups {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ou_str = match self {
            Groups::People => "People",
            Groups::Group => "Group",
            Groups::Other => "Other",
        };
        write!(f, "{}", ou_str)
    }
}
fn generate_ssha(password: &str) -> String {
    let mut sha = Sha1::new();
    let mut rng = rand::thread_rng();
    let salt: [u8; 4] = rng.gen();
    sha.update(password.as_bytes());
    sha.update(salt);
    let hashed_password = sha.finalize();
    let mut ssha = Vec::new();
    ssha.extend_from_slice(&hashed_password);
    ssha.extend_from_slice(&salt);
    format!("{{SSHA}}{}", STANDARD.encode(ssha))
}
#[allow(dead_code)]
impl Ldap {
    pub fn new(url: &str, base_dn: &str) -> Result<Self> {
        let conn = LdapConn::with_settings(
            LdapConnSettings::new()
                .set_no_tls_verify(true)
                .set_starttls(true)
                .set_conn_timeout(Duration::new(5, 0)),
            url,
        )?;
        Ok(Self {
            conn,
            base_dn: base_dn.to_string(),
        })
    }

    pub fn bind(&mut self, admin_dn: &str, admin_password: &str) -> Result<()> {
        self.conn.simple_bind(admin_dn, admin_password)?.success()?;
        Ok(())
    }

    fn add_entry(&mut self, dn: &str, attrs: Vec<(&str, Vec<&str>)>) -> Result<()> {
        let attrs: Vec<(&str, HashSet<&str>)> = attrs
            .into_iter()
            .map(|(k, v)| (k, v.into_iter().collect()))
            .collect();
        self.conn.add(dn, attrs)?;
        println!("Entry added successfully: {}", dn);
        Ok(())
    }

    fn modify_entry(&mut self, dn: &str, mods: Vec<Mod<&str>>) -> Result<()> {
        self.conn.modify(dn, mods)?.success()?;
        Ok(())
    }

    pub fn search_entry(
        &mut self,
        scope: Scope,
        filter: &str,
        attrs: Vec<&str>,
    ) -> Result<Vec<SearchEntry>> {
        let (rs, _res) = self
            .conn
            .search(&self.base_dn, scope, filter, attrs)?
            .success()?;
        let entries: Vec<SearchEntry> = rs.into_iter().map(SearchEntry::construct).collect();
        Ok(entries)
    }
    pub fn change_password(&mut self, dn: &str, new_password: &str) -> Result<()> {
        let mut password_set = HashSet::new();
        let hashed_password = generate_ssha(new_password);
        password_set.insert(hashed_password.as_str());
        let user_dn = user_dn(dn, &self.base_dn);
        let mods = vec![Mod::Replace("userPassword", password_set)];
        self.modify_entry(&user_dn, mods)?;
        println!("Password modification successful for DN: {}", user_dn);
        match self.verify_password(&user_dn, new_password) {
            Ok(_) => {
                println!("Password verification successful: Password changed and works.");
                Ok(())
            }
            Err(e) => {
                println!("Password verification failed: {}", e);
                Err(e)
            }
        }
    }

    pub fn verify_password(&mut self, dn: &str, password: &str) -> Result<()> {
        self.conn.simple_bind(dn, password)?.success()?;
        Ok(())
    }
    fn delete_entry(&mut self, dn: &str) -> Result<()> {
        self.conn.delete(dn)?.success()?;
        println!("Entry deleted successfully: {}", dn);
        Ok(())
    }
    pub fn add_user(&mut self, user: &User) -> Result<()> {
        let user_dn = user.get_dn(&self.base_dn);
        let hashed_password = generate_ssha(user.user_password);
        println!("Hashed password: {}", hashed_password);
        let attrs = vec![
            (
                "objectClass",
                vec!["inetOrgPerson", "posixAccount", "shadowAccount"],
            ),
            ("cn", vec![user.cn]),
            ("sn", vec![user.sn]),
            ("uid", vec![user.uid]),
            ("userPassword", vec![&hashed_password]),
            ("homeDirectory", vec![user.home_directory]),
            ("loginShell", vec![user.login_shell]),
            ("gecos", vec![user.gecos]),
            ("givenName", vec![user.given_name]),
            ("displayName", vec![user.display_name]),
            ("uidNumber", vec![&user.uid_number]),
            ("gidNumber", vec![&user.gid_number]),
        ];
        let attrs: Vec<(&str, HashSet<&str>)> = attrs
            .into_iter()
            .map(|(attr, values)| (attr, values.into_iter().collect()))
            .collect();
        self.conn.add(&user_dn, attrs)?;
        println!("User added successfully: {}", user_dn);
        Ok(())
    }
    pub fn del_user(&mut self, uid: &str) -> Result<()> {
        let user_dn = format!("uid={},ou={},{}", uid, Groups::People, self.base_dn);
        self.conn.delete(&user_dn)?.success()?;
        println!("User {} deleted successfully from DN: {}", uid, user_dn);
        Ok(())
    }
    pub fn check_login(&mut self, uid: &str, password: &str) -> Result<()> {
        let user_dn = format!("uid={},ou={},{}", uid, Groups::People, self.base_dn);
        match self.conn.simple_bind(&user_dn, password)?.success() {
            Ok(_) => {
                println!("Login successful!!");
                Ok(())
            }
            Err(e) => {
                println!("Login failed!!");
                Err(e)
            }
        }
        // println!("User {} logged in successfully.", uid);
        // Ok(())
    }
}

#[allow(dead_code)]
#[allow(clippy::too_many_arguments)]
impl<'a> User<'a> {
    pub fn new(
        uid: &'a str,
        user_password: &'a str,
        cn: &'a str,
        sn: &'a str,
        home_directory: &'a str,
        login_shell: &'a str,
        given_name: &'a str,
        display_name: &'a str,
        uid_number: &'a str,
        gid_number: &'a str,
        gecos: &'a str,
        ou: Groups,
    ) -> Self {
        Self {
            uid,
            user_password,
            cn,
            sn,
            home_directory,
            login_shell,
            given_name,
            display_name,
            uid_number,
            gid_number,
            gecos,
            ou,
        }
    }
    pub fn get_dn(&self, base_dn: &str) -> String {
        format!("uid={},ou={},{}", self.uid, self.ou, base_dn)
    }
}
fn user_dn(uid: &str, base_dn: &str) -> String {
    format!("uid={},ou=People,{}", uid, base_dn)
}
