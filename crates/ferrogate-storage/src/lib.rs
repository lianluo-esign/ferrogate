//! Repository boundaries for tenant, key, usage, and request-log storage.

pub trait Repository<T> {
    fn get(&self, id: &str) -> Option<T>;
}

#[derive(Debug, Default)]
pub struct InMemoryRepository<T> {
    _marker: std::marker::PhantomData<T>,
}
