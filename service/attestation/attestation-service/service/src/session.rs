use actix_web::cookie::{time::{Duration, OffsetDateTime}, Cookie};
use scc::HashMap;
use uuid::Uuid;

pub struct Session {
    pub id: String,
    pub challenge: String,
    timeout: OffsetDateTime,
}

impl Session {
    pub fn new(challenge: String, timeout_m: i64) -> Self {
        let id = Uuid::new_v4().as_simple().to_string();
        let timeout = OffsetDateTime::now_utc() + Duration::minutes(timeout_m);
        Session {
            id,
            challenge,
            timeout,
        }
    }
    pub fn is_expired(&self) -> bool {
        return self.timeout < OffsetDateTime::now_utc();
    }
    pub fn cookie(&self) -> Cookie {
        Cookie::build("oeas-session-id", self.id.clone())
        .expires(self.timeout.clone())
        .finish()
    }
}

pub struct SessionMap {
    pub session_map: HashMap<String, Session>,
}

impl SessionMap {
    pub fn new() -> Self {
        SessionMap {
            session_map: HashMap::new(),
        }
    }
    pub fn insert(&self, session: Session) {
        let _ = self.session_map.insert(session.id.clone(), session);
    }
    pub fn delete(&self, session: Session) {
       let _ = self.session_map.remove(&session.id);
    }
}