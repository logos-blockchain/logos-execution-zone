
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_max_length_allowed() {
        let max_vec = vec![
            0_u8;
            usize::try_from(DATA_MAX_LENGTH.as_u64())
                .expect("DATA_MAX_LENGTH fits in usize")
        ];
        let result = ShardData::try_from(max_vec);
        assert!(result.is_ok());
    }

    #[test]
    fn data_too_big_error() {
        let big_vec = vec![
            0_u8;
            usize::try_from(DATA_MAX_LENGTH.as_u64())
                .expect("DATA_MAX_LENGTH fits in usize")
                + 1
        ];
        let result = ShardData::try_from(big_vec);
        assert!(matches!(result, Err(DataTooBigError)));
    }

    #[test]
    fn borsh_deserialize_exceeding_limit_error() {
        let too_big_data = vec![
            0_u8;
            usize::try_from(DATA_MAX_LENGTH.as_u64())
                .expect("DATA_MAX_LENGTH fits in usize")
                + 1
        ];
        let mut serialized = Vec::new();
        <_ as BorshSerialize>::serialize(&too_big_data, &mut serialized).unwrap();

        let result = <ShardData as BorshDeserialize>::deserialize(&mut serialized.as_ref());
        assert!(result.is_err());
    }

    #[test]
    fn json_deserialize_exceeding_limit_error() {
        let data = vec![
            0_u8;
            usize::try_from(DATA_MAX_LENGTH.as_u64())
                .expect("DATA_MAX_LENGTH fits in usize")
                + 1
        ];
        let json = serde_json::to_string(&data).unwrap();

        let result: Result<ShardData, _> = serde_json::from_str(&json);
        assert!(result.is_err());
    }
}
