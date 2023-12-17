//! LRU with an associated map that maps in reverse

use lru::LruCache;
use serde::{Serialize, Deserialize};
use std::borrow::Borrow;
use std::collections::HashMap;
use std::hash::Hash;
use std::num::NonZeroUsize;
use std::option::Option;

#[derive(Debug)]
pub struct BijectiveLRU<L: Hash + Eq, R: Eq + Hash> {
    pub ca: LruCache<L, R>,
    pub map: HashMap<R, L>,
}

impl<L: Hash + Eq + Clone, R: Hash + Eq + Clone> BijectiveLRU<L, R> {
    pub fn new(cap: NonZeroUsize) -> Self {
        Self {
            ca: LruCache::new(cap),
            map: Default::default(),
        }
    }
    pub fn from_map(cap: NonZeroUsize, map: HashMap<R, L>) -> Self {
        let mut ca = LruCache::new(cap);
        for (r, l ) in map.iter() {
            ca.push(l.clone(), r.clone());
        }
        Self { ca, map }
    }
    pub fn lget<Q: ?Sized + Hash + Eq>(&mut self, key: &Q) -> Option<&R>
    where
        L: Borrow<Q>,
    {
        self.ca.get(key)
    }
    pub fn rget<Q: ?Sized + Hash + Eq>(&mut self, value: &Q) -> Option<&L>
    where
        R: Borrow<Q>,
    {
        let k = self.map.get(value);
        k.map(|k| {
            self.ca.promote(k);
            k
        })
    }
    pub fn rcontains<Q: ?Sized + Hash + Eq>(&mut self, value: &Q) -> bool
    where
        R: Borrow<Q>,
    {
        self.map.contains_key(value)
    }
    /// [from ca, from map]
    pub fn push(&mut self, k1: L, v1: R) -> [Option<(L, R)>; 2] {
        let mut popped: [Option<(L, R)>; 2] = [None, None];
        if let Some(k2) = self.map.insert(v1.clone(), k1.clone()) {
            popped[0] = self.ca.pop_entry(&k2);
        }
        if let Some((_pk, pv)) = self.ca.push(k1, v1.clone()) {
            if pv != v1 {
                popped[1] = self.map.remove_entry(&pv).map(|(v, k)| (k, v));
            }
        }
        popped
    }
}

#[cfg(test)]
mod tests {
    use super::BijectiveLRU;

    #[test]
    fn test1() {
        let mut lr = BijectiveLRU::new(2.try_into().unwrap());
        lr.push(1, 'a');
        lr.push(2, 'b');
        dbg!(lr.push(3, 'c'));
        dbg!(lr.push(1, 'b'), &lr);
        dbg!(lr.push(5, 'a'), &lr);
    }
}
