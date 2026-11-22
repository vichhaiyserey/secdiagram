pub trait Entity {
    fn id(&self) -> i64;
}

pub struct User {
    pub id: i64,
    pub username: String,
}

impl Entity for User {
    fn id(&self) -> i64 {
        self.id
    }
}

pub struct UserStore;

impl UserStore {
    pub fn new() -> Self {
        UserStore
    }

    pub fn query_raw(&self, query: &str) -> String {
        query.to_string()
    }
}
