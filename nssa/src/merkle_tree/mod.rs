#![expect(clippy::arithmetic_side_effects, reason = "TODO: fix later")]

use borsh::{BorshDeserialize, BorshSerialize};
use sha2::{Digest as _, Sha256};

mod default_values;

type Value = [u8; 32];
type Node = [u8; 32];

#[cfg_attr(test, derive(Debug, PartialEq, Eq))]
#[derive(Clone, BorshSerialize, BorshDeserialize)]
pub struct MerkleTree {
    nodes: Vec<Node>,
    capacity: usize,
    length: usize,
}

impl MerkleTree {
    pub fn root(&self) -> Node {
        let root_index = self.root_index();
        *self.get_node(root_index)
    }

    fn root_index(&self) -> usize {
        let tree_depth = self.depth();
        let capacity_depth =
            usize::try_from(self.capacity.trailing_zeros()).expect("u32 fits in usize");

        if tree_depth == capacity_depth {
            0
        } else {
            // 2^(capacity_depth - tree_depth) - 1
            (1 << (capacity_depth - tree_depth)) - 1
        }
    }

    /// Number of levels required to hold all nodes.
    fn depth(&self) -> usize {
        usize::try_from(self.length.next_power_of_two().trailing_zeros())
            .expect("u32 fits in usize")
    }

    fn get_node(&self, index: usize) -> &Node {
        &self.nodes[index]
    }

    fn set_node(&mut self, index: usize, node: Node) {
        self.nodes[index] = node;
    }

    pub fn with_capacity(capacity: usize) -> Self {
        // Adjust capacity to ensure power of two
        let capacity = capacity.next_power_of_two();
        let total_depth = usize::try_from(capacity.trailing_zeros()).expect("u32 fits in usize");

        let nodes = default_values::DEFAULT_VALUES[..=total_depth]
            .iter()
            .rev()
            .enumerate()
            .flat_map(|(level, default_value)| std::iter::repeat_n(default_value, 1 << level))
            .copied()
            .collect();

        Self {
            nodes,
            capacity,
            length: 0,
        }
    }

    /// Reallocates storage of Merkle tree for double capacity.
    /// The current tree is embedded into the new tree as a subtree.
    fn reallocate_to_double_capacity(&mut self) {
        let old_capacity = self.capacity;
        let new_capacity = old_capacity << 1;

        let mut this = Self::with_capacity(new_capacity);

        for (index, value) in self.nodes.iter().enumerate() {
            let offset = prev_power_of_two(index + 1);
            let new_index = index + offset;
            this.set_node(new_index, *value);
        }

        this.length = self.length;

        *self = this;
    }

    pub fn insert(&mut self, value: Value) -> usize {
        if self.length == self.capacity {
            self.reallocate_to_double_capacity();
        }

        let new_index = self.length;

        let mut node_index = new_index + self.capacity - 1;
        let mut node_hash = hash_value(&value);

        // Insert the new node at the bottom layer
        self.set_node(node_index, node_hash);
        self.length += 1;

        // Update upper levels for the newly inserted node
        for _ in 0..self.depth() {
            let parent_index = (node_index - 1) >> 1;
            let left_child = self.get_node((parent_index << 1) + 1);
            let right_child = self.get_node((parent_index << 1) + 2);
            node_hash = hash_two(left_child, right_child);
            self.set_node(parent_index, node_hash);
            node_index = parent_index;
        }

        new_index
    }

    pub fn get_authentication_path_for(&self, index: usize) -> Option<Vec<Node>> {
        if index >= self.length {
            return None;
        }

        let mut path = Vec::with_capacity(self.depth());

        let mut node_index = self.capacity + index - 1;
        let root_index = self.root_index();

        while node_index != root_index {
            let parent_index = (node_index - 1) >> 1;
            // Left children have odd indices, and right children have even indices
            let is_left_child = node_index & 1 == 1;
            let sibling_index = if is_left_child {
                node_index + 1
            } else {
                node_index - 1
            };
            path.push(*self.get_node(sibling_index));
            node_index = parent_index;
        }

        Some(path)
    }
}

/// Compute parent as the hash of two child nodes.
fn hash_two(left: &Node, right: &Node) -> Node {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn hash_value(value: &Value) -> Node {
    let mut hasher = Sha256::new();
    hasher.update(value);
    hasher.finalize().into()
}

const fn prev_power_of_two(x: usize) -> usize {
    if x == 0 {
        return 0;
    }
    1 << (usize::BITS - x.leading_zeros() - 1)
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;

    use super::*;

    impl MerkleTree {
        pub fn new(values: &[Value]) -> Self {
            let mut this = Self::with_capacity(values.len());
            for value in values.iter().copied() {
                this.insert(value);
            }
            this
        }
    }

    #[test]
    fn empty_merkle_tree() {
        let tree = MerkleTree::with_capacity(4);
        let expected_root =
            hex!("0000000000000000000000000000000000000000000000000000000000000000");
        assert_eq!(tree.root(), expected_root);
        assert_eq!(tree.capacity, 4);
        assert_eq!(tree.length, 0);
    }

    #[test]
    fn merkle_tree_0() {
        let values = [[0; 32]];
        let tree = MerkleTree::new(&values);
        assert_eq!(tree.root(), hash_value(&[0; 32]));
        assert_eq!(tree.capacity, 1);
        assert_eq!(tree.length, 1);
    }

    #[test]
    fn merkle_tree_1() {
        let values = [[1; 32], [2; 32], [3; 32], [4; 32]];
        let tree = MerkleTree::new(&values);
        let expected_root =
            hex!("48c73f7821a58a8d2a703e5b39c571c0aa20cf14abcd0af8f2b955bc202998de");
        assert_eq!(tree.root(), expected_root);
        assert_eq!(tree.capacity, 4);
        assert_eq!(tree.length, 4);
    }

    #[test]
    fn merkle_tree_2() {
        let values = [[1; 32], [2; 32], [3; 32], [0; 32]];
        let tree = MerkleTree::new(&values);
        let expected_root =
            hex!("c9bbb83096df85157a146e7d770455a98412dee0633187ee86fee6c8a45b831a");
        assert_eq!(tree.root(), expected_root);
        assert_eq!(tree.capacity, 4);
        assert_eq!(tree.length, 4);
    }

    #[test]
    fn merkle_tree_3() {
        let values = [[1; 32], [2; 32], [3; 32]];
        let tree = MerkleTree::new(&values);
        let expected_root =
            hex!("c8d3d8d2b13f27ceeccdc699119871f9f32ea7ed86ff45d0ad11f77b28cd7568");
        assert_eq!(tree.root(), expected_root);
        assert_eq!(tree.capacity, 4);
        assert_eq!(tree.length, 3);
    }

    #[test]
    fn merkle_tree_4() {
        let values = [[11; 32], [12; 32], [13; 32], [14; 32], [15; 32]];
        let tree = MerkleTree::new(&values);
        let expected_root =
            hex!("ef418aed5aa20702d4d94c92da79a4012f2e36f1008bfdb3cd1e38749dca2499");

        assert_eq!(tree.root(), expected_root);
        assert_eq!(tree.capacity, 8);
        assert_eq!(tree.length, 5);
    }

    #[test]
    fn merkle_tree_5() {
        let values = [
            [11; 32], [12; 32], [12; 32], [13; 32], [14; 32], [15; 32], [15; 32], [13; 32],
            [13; 32], [15; 32], [11; 32],
        ];
        let tree = MerkleTree::new(&values);
        let expected_root =
            hex!("3f72d2ff55921a86c48e5988ec3e19ee9d0d5aa3e23197842970a903508ed767");
        assert_eq!(tree.root(), expected_root);
        assert_eq!(tree.capacity, 16);
        assert_eq!(tree.length, 11);
    }

    #[test]
    fn merkle_tree_6() {
        let values = [[1; 32], [2; 32], [3; 32], [4; 32], [5; 32]];
        let tree = MerkleTree::new(&values);
        let expected_root =
            hex!("069cb8259a06fe6edb3fa7ff7933a6dd7dca6fca299314379794a688926c3792");
        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn with_capacity_4() {
        let tree = MerkleTree::with_capacity(4);

        assert_eq!(tree.length, 0);
        assert_eq!(tree.nodes.len(), 7);
        for i in 3..7 {
            assert_eq!(*tree.get_node(i), default_values::DEFAULT_VALUES[0], "{i}");
        }
        for i in 1..3 {
            assert_eq!(*tree.get_node(i), default_values::DEFAULT_VALUES[1], "{i}");
        }
        assert_eq!(*tree.get_node(0), default_values::DEFAULT_VALUES[2]);
    }

    #[test]
    fn with_capacity_5() {
        let tree = MerkleTree::with_capacity(5);

        assert_eq!(tree.length, 0);
        assert_eq!(tree.nodes.len(), 15);
        for i in 7..15 {
            assert_eq!(*tree.get_node(i), default_values::DEFAULT_VALUES[0]);
        }
        for i in 3..7 {
            assert_eq!(*tree.get_node(i), default_values::DEFAULT_VALUES[1]);
        }
        for i in 1..3 {
            assert_eq!(*tree.get_node(i), default_values::DEFAULT_VALUES[2]);
        }
        assert_eq!(*tree.get_node(0), default_values::DEFAULT_VALUES[3]);
    }

    #[test]
    fn with_capacity_6() {
        let mut tree = MerkleTree::with_capacity(100);

        let values = [[1; 32], [2; 32], [3; 32], [4; 32]];

        let expected_root =
            hex!("48c73f7821a58a8d2a703e5b39c571c0aa20cf14abcd0af8f2b955bc202998de");

        assert_eq!(0, tree.insert(values[0]));
        assert_eq!(1, tree.insert(values[1]));
        assert_eq!(2, tree.insert(values[2]));
        assert_eq!(3, tree.insert(values[3]));

        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn with_capacity_7() {
        let mut tree = MerkleTree::with_capacity(599);

        let values = [[1; 32], [2; 32], [3; 32]];

        let expected_root =
            hex!("c8d3d8d2b13f27ceeccdc699119871f9f32ea7ed86ff45d0ad11f77b28cd7568");

        assert_eq!(0, tree.insert(values[0]));
        assert_eq!(1, tree.insert(values[1]));
        assert_eq!(2, tree.insert(values[2]));

        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn with_capacity_8() {
        let mut tree = MerkleTree::with_capacity(1);

        let values = [[1; 32], [2; 32], [3; 32]];

        let expected_root =
            hex!("c8d3d8d2b13f27ceeccdc699119871f9f32ea7ed86ff45d0ad11f77b28cd7568");

        assert_eq!(0, tree.insert(values[0]));
        assert_eq!(1, tree.insert(values[1]));
        assert_eq!(2, tree.insert(values[2]));

        assert_eq!(tree.root(), expected_root);
    }

    #[test]
    fn insert_value_1() {
        let mut tree = MerkleTree::with_capacity(1);

        let values = [[1; 32], [2; 32], [3; 32]];
        let expected_tree = MerkleTree::new(&values);

        assert_eq!(0, tree.insert(values[0]));
        assert_eq!(1, tree.insert(values[1]));
        assert_eq!(2, tree.insert(values[2]));

        assert_eq!(expected_tree, tree);
    }

    #[test]
    fn insert_value_2() {
        let mut tree = MerkleTree::with_capacity(1);

        let values = [[1; 32], [2; 32], [3; 32], [4; 32]];
        let expected_tree = MerkleTree::new(&values);

        assert_eq!(0, tree.insert(values[0]));
        assert_eq!(1, tree.insert(values[1]));
        assert_eq!(2, tree.insert(values[2]));
        assert_eq!(3, tree.insert(values[3]));

        assert_eq!(expected_tree, tree);
    }

    #[test]
    fn insert_value_3() {
        let mut tree = MerkleTree::with_capacity(1);

        let values = [[11; 32], [12; 32], [13; 32], [14; 32], [15; 32]];
        let expected_tree = MerkleTree::new(&values);

        tree.insert(values[0]);
        tree.insert(values[1]);
        tree.insert(values[2]);
        tree.insert(values[3]);
        tree.insert(values[4]);

        assert_eq!(expected_tree, tree);
    }

    // Reference implementation
    fn verify_authentication_path(value: &Value, index: usize, path: &[Node], root: &Node) -> bool {
        let mut result = hash_value(value);
        let mut level_index = index;
        for node in path {
            let is_left_child = level_index & 1 == 0;
            if is_left_child {
                result = hash_two(&result, node);
            } else {
                result = hash_two(node, &result);
            }
            level_index >>= 1;
        }
        &result == root
    }

    #[test]
    fn authentication_path_1() {
        let values = [[1; 32], [2; 32], [3; 32], [4; 32]];
        let tree = MerkleTree::new(&values);
        let expected_authentication_path = vec![
            hex!("9f4fb68f3e1dac82202f9aa581ce0bbf1f765df0e9ac3c8c57e20f685abab8ed"),
            hex!("50a27d4746f357cb700cbe9d4883b77fb64f0128828a3489dc6a6f21ddbf2414"),
        ];

        let authentication_path = tree.get_authentication_path_for(2).unwrap();
        assert_eq!(authentication_path, expected_authentication_path);
    }

    #[test]
    fn authentication_path_2() {
        let values = [[1; 32], [2; 32], [3; 32]];
        let tree = MerkleTree::new(&values);
        let expected_authentication_path = vec![
            hex!("75877bb41d393b5fb8455ce60ecd8dda001d06316496b14dfa7f895656eeca4a"),
            hex!("a41b855d2db4de9052cd7be5ec67d6586629cb9f6e3246a4afa5ba313f07a9c5"),
        ];

        let authentication_path = tree.get_authentication_path_for(0).unwrap();
        assert_eq!(authentication_path, expected_authentication_path);
    }

    #[test]
    fn authentication_path_3() {
        let values = [[1; 32], [2; 32], [3; 32], [4; 32], [5; 32]];
        let tree = MerkleTree::new(&values);
        let expected_authentication_path = vec![
            hex!("0000000000000000000000000000000000000000000000000000000000000000"),
            hex!("f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b"),
            hex!("48c73f7821a58a8d2a703e5b39c571c0aa20cf14abcd0af8f2b955bc202998de"),
        ];

        let authentication_path = tree.get_authentication_path_for(4).unwrap();
        assert_eq!(authentication_path, expected_authentication_path);
    }

    #[test]
    fn authentication_path_4() {
        let values = [[1; 32], [2; 32], [3; 32], [4; 32], [5; 32]];
        let tree = MerkleTree::new(&values);
        assert!(tree.get_authentication_path_for(5).is_none());
    }

    #[test]
    fn authentication_path_5() {
        let values = [[1; 32], [2; 32], [3; 32], [4; 32], [5; 32]];
        let tree = MerkleTree::new(&values);
        let index = 4;
        let value = values[index];
        let path = tree.get_authentication_path_for(index).unwrap();
        assert!(verify_authentication_path(
            &value,
            index,
            &path,
            &tree.root()
        ));
    }

    #[test]
    fn tree_with_63_insertions() {
        let values = [
            hex!("cd00acab0f45736e6c6311f1953becc0b69a062e7c2a7310875d28bdf9ef9c5b"),
            hex!("0df5a6afbcc7bf126caf7084acfc593593ab512e6ca433c61c1a922be40a04ea"),
            hex!("23c1258620266c7bedb6d1ee32f6da9413e4010ace975239dccb34e727e07c40"),
            hex!("f33ccc3a11476b0ef62326ca5ec292056759b05e6a28023d2d1ce66165611353"),
            hex!("77f914ab016b8049f6bea7704000e413a393865918a3824f9285c3db0aacff23"),
            hex!("910a1c23188e54d57fd167ddb0f8bf68c6b70ed9ec76ef56c4b7f2632f82ca7f"),
            hex!("047ee85526197d1e7403a559cf6d2f22c1926c8ad59481a2e2f1b697af45e40b"),
            hex!("9d355cf89fb382ae34bf80566b28489278d10f2cebb5b0ea42fab1bac5adae0c"),
            hex!("604018b95232596b2685a9bc737b6cccb53b10e483d2d9a2f4a755410b02a188"),
            hex!("a16708ef7b6bf1796063addaf57d6a566b6f87b0bbe42af43a4590d05f1684cb"),
            hex!("820f2dfa271cd2fd41e1452406d5dad552c85c1223c45d45dbd7446759fdc6b8"),
            hex!("680b6912d7e219f8805d4d28adb4428dd78fea0dc1b8cdb2412645c4b1962c88"),
            hex!("14d5471ce6c45506753982b17cac5790ac7bc29e6f388f31052d7dfd62b294e5"),
            hex!("8b364200172b777d4aa16d2098b5eb98ac3dd4a1b9597e5c2bf6f6930031f230"),
            hex!("9bb45b910711874339dda8a21a9aad73822286f5e52d7d3de0ed78dfbba329a5"),
            hex!("d6806d5df5cb25ce5d531042f09b3cb34fb9e47c61182b63cccd9d44392f6027"),
            hex!("b8cfa90ebc8fd09c04682d93a08fddd3e8e57715174dcc92451edd191264a58b"),
            hex!("3463c7f81d00f809b3dfa83195447c927fb4045b3913dac6f45bee6c4010d7ed"),
            hex!("1d6ad7f7d677905feb506c58f4b404a79370ebc567296abea3a368b61d5a8239"),
            hex!("a58085ecf00963cb22da23c901b9b3ddc56462bb96ff03c923d67708e10dd29c"),
            hex!("c3319f4a65fb5bbb8447137b0972c03cbd84ebf7d9da194e0fcbd68c2d4d5bdb"),
            hex!("4aa31e90e0090faf3648d05e5d5499df2c78ebed4d6e6c23d8147de5d67dae73"),
            hex!("9f33b1d2c8bc7bd265336de1033ede6344bc41260313bdcb43f1108b83b9be92"),
            hex!("6500d4ad93d41c16ec81eaa5e70f173194aabe5c1072ac263b5727296f5b7cac"),
            hex!("3584f5d260003669fad98786e13171376b0f19410cb232ce65606cbff79e6768"),
            hex!("c8410946ebf56f13141c894a34ced85a5230088af70dcea581e44f52847830ac"),
            hex!("71dd90281cdebb70422f2d04ae446d5d2d5ea64b803c16128d37e3fcd5d1a4cc"),
            hex!("c05acf8d77ab4d659a538bd35af590864a7ad9c055ff5d6cda9d5aecfccecba3"),
            hex!("f1df98822ea084cce9021aa9cc81b1746cd1e84a75690da63e10fd877633ed77"),
            hex!("2ca822bc8f67bceb0a71a0d06fea7349036ef3e5ec21795a851e4182bd35ce01"),
            hex!("7fd2179abc3bcf89b4d8092988ba8c23952b3bbd3d7caea6b5ea0c13cf19f68b"),
            hex!("91b6ad516e017f6aa5a2e95776538bd3a3e933c1b1d32bb5e0f00a9db63c9c24"),
            hex!("cd31a8b5eef5ca0be5ef1cb261d0bf0a74d774a3152bb99739cfd296a1d0b85e"),
            hex!("3fb16f48b2bf93f3815979e6638f975d7f935088ec37db0be0f07965fbc78339"),
            hex!("c60c61b99bf486af5f4bf780a69860dafcd35c1474306a8575666fb5449bcec0"),
            hex!("8048d0d7e14091251f3f6c6b10bf6b5880a014b513f9f8c2395501dbffa6192a"),
            hex!("778b5af10b9dbe80b60a8e4f0bb91caf4476bcb812801099760754ae623fbd84"),
            hex!("d3ac25467920a4e08998b7a3226b8b54bfe66ac58cfedc71f15b2402fee0054a"),
            hex!("029aa94598fae2961a0d43937b8a9a3138bcfeae99a7cb15f77fac7c506f8432"),
            hex!("2eee5ef52fe669cb6882a68c893abdc1262dcf4424e4ba7a479da7cf1c10171d"),
            hex!("de3fb3d070e3a90f0eed8b5e65088a8dc0e4e3c342b9c0bf33bab714eae5dfec"),
            hex!("14d40177e833ab45bbfdc5f2b11fba7efaebb3f69facc554f24b549a2efe8538"),
            hex!("5734355069702448774fb2df95f1d562e1b9fe1514aeb6b922554ee9d2d01068"),
            hex!("8a273d49ac110343cec2cf3359d16eb2906b446bd9ec9833e2a640cebc8d5155"),
            hex!("e3fa984dd3cbeb9a7e827ed32d3d4e6a6ba643a55d82be97d9ddb06ee809fa3e"),
            hex!("90b1d5a364e17c8b7965396b06ec6e13749b5fc16500731518ad8fc30ae33e77"),
            hex!("7517376541b2e8ec83cbab04522b54a26610908a9872feb663451385aea58eb1"),
            hex!("5cba2e4cf7448e526d161133c4b2ea7c919ac4813a7308612595f46f11dea6cd"),
            hex!("c721911b300bec0691c8a2dfaabfef1d66b7b6258918914d3c3ad690729f05b7"),
            hex!("d0d0a70d8ae0d27806fa0b711c507290c260a89cbca0436d339d1dccdd087d62"),
            hex!("2a625c28ea763c5e82dd0a93ecfca7ec371ccbb363cd42be359c2c875f58009d"),
            hex!("174ef0119932ed890397d9f3837dd85f9100558b6fc9085d4af947ae8cf74bbc"),
            hex!("b497bc267151e8efa3c6daa461e6804b01a3f05f44f1f4d5b41d5f0d3f5219b1"),
            hex!("e987e91f5734630ddd7e6b58733b4fcdbc316ee9e8cac0e94c36c91cf58e59cc"),
            hex!("55019ad8bbe656c51eb042190c1c8da53f42baf43fd2350ebea38fc7cca2fae3"),
            hex!("c45a638edd18a6d9f5ad20b870c81b8626459bcb22dae7d58add7a6b6c6a84a8"),
            hex!("d42d3a5fb2ad50b2027fe5a36d59dd71e49a63e4b1b299073c96bbf7ba5d68a1"),
            hex!("9599e561054bcd3f647eb018ab0b069d3176497d42be9c4466551cbb959be47c"),
            hex!("42f33b23775327ff71aea6569548255f3cc9929da73373cc9bb1743d417f7cda"),
            hex!("ab24294f44fc6fdbeb96e0f6e93c4f6d97d035b73b9a337c353e18c6d0603bdd"),
            hex!("33954ec63520334f99b640a2982ac966b68c363fed383d621a1ab573934f1d33"),
            hex!("5e2a1f7df963d1fd8f50a285387cfbb5df581426619b325563e20bf7886c62b7"),
            hex!("13ffde471d4e27c473254e766fd1328ad80c42cab4d4955cffeae43d866f86e5"),
        ];

        let expected_root =
            hex!("1cf9b214217d7823f9de51b8f6cb34d0a99436a3a1bb762f90b815672a6afcc0");

        let mut tree_less_capacity = MerkleTree::with_capacity(1);
        let mut tree_exact_capacity = MerkleTree::with_capacity(64);
        let mut tree_more_capacity = MerkleTree::with_capacity(128);

        for value in &values {
            tree_less_capacity.insert(*value);
            tree_exact_capacity.insert(*value);
            tree_more_capacity.insert(*value);
        }

        assert_eq!(tree_more_capacity.root(), expected_root);
        assert_eq!(tree_less_capacity.root(), expected_root);
        assert_eq!(tree_exact_capacity.root(), expected_root);
    }
}

//
