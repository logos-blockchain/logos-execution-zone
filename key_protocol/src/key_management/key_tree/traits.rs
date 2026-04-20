pub trait KeyTreeNode: Sized {
    #[must_use]
    fn from_seed(seed: [u8; 64]) -> Self;
    #[must_use]
    fn derive_child(&self, cci: u32) -> Self;
    #[must_use]
    fn account_ids(&self) -> Vec<nssa::AccountId>;
}
