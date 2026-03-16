use std::{fmt::Display, str::FromStr};

use itertools::Itertools;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone, Serialize, Deserialize, Hash)]
pub struct ChainIndex(Vec<u32>);

#[derive(thiserror::Error, Debug)]
pub enum ChainIndexError {
    #[error("No root found")]
    NoRootFound,
    #[error("Failed to parse segment into a number")]
    ParseIntError(#[from] std::num::ParseIntError),
}

impl FromStr for ChainIndex {
    type Err = ChainIndexError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if !s.starts_with('/') {
            return Err(ChainIndexError::NoRootFound);
        }

        if s == "/" {
            return Ok(ChainIndex(vec![]));
        }

        let uprooted_substring = s.strip_prefix("/").unwrap();

        let splitted_chain: Vec<&str> = uprooted_substring.split("/").collect();
        let mut res = vec![];

        for split_ch in splitted_chain {
            let cci = split_ch.parse()?;
            res.push(cci);
        }

        Ok(Self(res))
    }
}

impl Display for ChainIndex {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "/")?;
        for cci in &self.0[..(self.0.len().saturating_sub(1))] {
            write!(f, "{cci}/")?;
        }
        if let Some(last) = self.0.last() {
            write!(f, "{}", last)?;
        }
        Ok(())
    }
}

impl Default for ChainIndex {
    fn default() -> Self {
        ChainIndex::from_str("/").expect("Root parsing failure")
    }
}

impl ChainIndex {
    pub fn root() -> Self {
        ChainIndex::default()
    }

    pub fn chain(&self) -> &[u32] {
        &self.0
    }

    pub fn index(&self) -> Option<u32> {
        self.chain().last().copied()
    }

    pub fn next_in_line(&self) -> ChainIndex {
        let mut chain = self.0.clone();
        // ToDo: Add overflow check
        if let Some(last_p) = chain.last_mut() {
            *last_p += 1
        }

        ChainIndex(chain)
    }

    pub fn previous_in_line(&self) -> Option<ChainIndex> {
        let mut chain = self.0.clone();
        if let Some(last_p) = chain.last_mut() {
            *last_p = last_p.checked_sub(1)?;
        }

        Some(ChainIndex(chain))
    }

    pub fn parent(&self) -> Option<ChainIndex> {
        if self.0.is_empty() {
            None
        } else {
            Some(ChainIndex(self.0[..(self.0.len() - 1)].to_vec()))
        }
    }

    pub fn nth_child(&self, child_id: u32) -> ChainIndex {
        let mut chain = self.0.clone();
        chain.push(child_id);

        ChainIndex(chain)
    }

    pub fn depth(&self) -> u32 {
        self.0.iter().map(|cci| cci + 1).sum()
    }

    fn collapse_back(&self) -> Option<Self> {
        let mut res = self.parent()?;

        let last_mut = res.0.last_mut()?;
        *last_mut += *(self.0.last()?) + 1;

        Some(res)
    }

    fn shuffle_iter(&self) -> impl Iterator<Item = ChainIndex> {
        self.0
            .iter()
            .permutations(self.0.len())
            .unique()
            .map(|item| ChainIndex(item.into_iter().cloned().collect()))
    }

    pub fn chain_ids_at_depth(depth: usize) -> impl Iterator<Item = ChainIndex> {
        let mut stack = vec![ChainIndex(vec![0; depth])];
        let mut cumulative_stack = vec![ChainIndex(vec![0; depth])];

        while let Some(id) = stack.pop() {
            if let Some(collapsed_id) = id.collapse_back() {
                for id in collapsed_id.shuffle_iter() {
                    stack.push(id.clone());
                    cumulative_stack.push(id);
                }
            }
        }

        cumulative_stack.into_iter().unique()
    }

    pub fn chain_ids_at_depth_rev(depth: usize) -> impl Iterator<Item = ChainIndex> {
        let mut stack = vec![ChainIndex(vec![0; depth])];
        let mut cumulative_stack = vec![ChainIndex(vec![0; depth])];

        while let Some(id) = stack.pop() {
            if let Some(collapsed_id) = id.collapse_back() {
                for id in collapsed_id.shuffle_iter() {
                    stack.push(id.clone());
                    cumulative_stack.push(id);
                }
            }
        }

        cumulative_stack.into_iter().rev().unique()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_id_root_correct() {
        let chain_id = ChainIndex::root();
        let chain_id_2 = ChainIndex::from_str("/").unwrap();

        assert_eq!(chain_id, chain_id_2);
    }

    #[test]
    fn test_chain_id_deser_correct() {
        let chain_id = ChainIndex::from_str("/257").unwrap();

        assert_eq!(chain_id.chain(), &[257]);
    }

    #[test]
    fn test_chain_id_deser_failure_no_root() {
        let chain_index_error = ChainIndex::from_str("257").err().unwrap();

        assert!(matches!(chain_index_error, ChainIndexError::NoRootFound));
    }

    #[test]
    fn test_chain_id_deser_failure_int_parsing_failure() {
        let chain_index_error = ChainIndex::from_str("/hello").err().unwrap();

        assert!(matches!(
            chain_index_error,
            ChainIndexError::ParseIntError(_)
        ));
    }

    #[test]
    fn test_chain_id_next_in_line_correct() {
        let chain_id = ChainIndex::from_str("/257").unwrap();
        let next_in_line = chain_id.next_in_line();

        assert_eq!(next_in_line, ChainIndex::from_str("/258").unwrap());
    }

    #[test]
    fn test_chain_id_child_correct() {
        let chain_id = ChainIndex::from_str("/257").unwrap();
        let child = chain_id.nth_child(3);

        assert_eq!(child, ChainIndex::from_str("/257/3").unwrap());
    }

    #[test]
    fn test_correct_display() {
        let chainid = ChainIndex(vec![5, 7, 8]);

        let string_index = format!("{chainid}");

        assert_eq!(string_index, "/5/7/8".to_string());
    }

    #[test]
    fn test_prev_in_line() {
        let chain_id = ChainIndex(vec![1, 7, 3]);

        let prev_chain_id = chain_id.previous_in_line().unwrap();

        assert_eq!(prev_chain_id, ChainIndex(vec![1, 7, 2]))
    }

    #[test]
    fn test_prev_in_line_no_prev() {
        let chain_id = ChainIndex(vec![1, 7, 0]);

        let prev_chain_id = chain_id.previous_in_line();

        assert_eq!(prev_chain_id, None)
    }

    #[test]
    fn test_parent() {
        let chain_id = ChainIndex(vec![1, 7, 3]);

        let parent_chain_id = chain_id.parent().unwrap();

        assert_eq!(parent_chain_id, ChainIndex(vec![1, 7]))
    }

    #[test]
    fn test_parent_no_parent() {
        let chain_id = ChainIndex(vec![]);

        let parent_chain_id = chain_id.parent();

        assert_eq!(parent_chain_id, None)
    }

    #[test]
    fn test_parent_root() {
        let chain_id = ChainIndex(vec![1]);

        let parent_chain_id = chain_id.parent().unwrap();

        assert_eq!(parent_chain_id, ChainIndex::root())
    }

    #[test]
    fn test_collapse_back() {
        let chain_id = ChainIndex(vec![1, 1]);

        let collapsed = chain_id.collapse_back().unwrap();

        assert_eq!(collapsed, ChainIndex(vec![3]))
    }

    #[test]
    fn test_collapse_back_one() {
        let chain_id = ChainIndex(vec![1]);

        let collapsed = chain_id.collapse_back();

        assert_eq!(collapsed, None)
    }

    #[test]
    fn test_collapse_back_root() {
        let chain_id = ChainIndex(vec![]);

        let collapsed = chain_id.collapse_back();

        assert_eq!(collapsed, None)
    }

    #[test]
    fn test_shuffle() {
        for id in ChainIndex::chain_ids_at_depth(5) {
            println!("{id}");
        }
    }
}
