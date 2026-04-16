pub trait KeyTreeNode: Sized {
    fn from_seed(seed: [u8; 64]) -> Self;
    fn derive_child(&self, cci: u32) -> Self;
    fn account_ids(&self) -> Vec<nssa::AccountId>;
}
