/// Trait, that reperesents a Node in hierarchical key tree.
pub trait KeyNode {
    /// Tree root node.
    fn root(seed: [u8; 64]) -> Self;

    /// `cci`'s child of node.
    #[must_use]
    fn nth_child(&self, cci: u32) -> Self;

    fn chain_code(&self) -> &[u8; 32];

    fn child_index(&self) -> Option<u32>;

    fn account_id(&self) -> nssa::AccountId;
}
