use crate::{PrivateKey, PublicKey, Signature};

pub struct TestVector {
    pub seckey: Option<PrivateKey>,
    pub pubkey: PublicKey,
    pub aux_rand: Option<[u8; 32]>,
    pub message: Option<Vec<u8>>,
    pub signature: Signature,
    pub verification_result: bool,
}

/// Test vectors from
/// <https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv>.
//
pub fn test_vectors() -> Vec<TestVector> {
    vec![
        TestVector {
            seckey: Some(PrivateKey::try_new(hex_to_bytes(
                "0000000000000000000000000000000000000000000000000000000000000003",
            )).unwrap()),
            pubkey: PublicKey::try_new(hex_to_bytes(
                "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
            )).unwrap(),
            aux_rand: Some(hex_to_bytes::<32>(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )),
            message: Some(
                hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
                    .unwrap(),
            ),
            signature: Signature {
                value: hex_to_bytes(
                    "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0",
                ),
            },
            verification_result: true,
        },
        TestVector {
            seckey: Some(PrivateKey::try_new(hex_to_bytes(
                "B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF",
            )).unwrap()),
            pubkey: PublicKey::try_new(hex_to_bytes(
                "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            )).unwrap(),
            aux_rand: Some(hex_to_bytes::<32>(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )),
            message: Some(
                hex::decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
                    .unwrap(),
            ),
            signature: Signature {
                value: hex_to_bytes(
                    "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A",
                ),
            },
            verification_result: true,
        },
        TestVector {
            seckey: Some(PrivateKey::try_new(hex_to_bytes(
                "C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9",
            )).unwrap()),
            pubkey: PublicKey::try_new(hex_to_bytes(
                "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
            )).unwrap(),
            aux_rand: Some(hex_to_bytes::<32>(
                "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906",
            )),
            message: Some(
                hex::decode("7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C")
                    .unwrap(),
            ),
            signature: Signature {
                value: hex_to_bytes(
                    "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7",
                ),
            },
            verification_result: true,
        },
        TestVector {
            seckey: Some(PrivateKey::try_new(hex_to_bytes(
                "0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710",
            )).unwrap()),
            pubkey: PublicKey::try_new(hex_to_bytes(
                "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
            )).unwrap(),
            aux_rand: Some(hex_to_bytes::<32>(
                "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
            )),
            message: Some(
                hex::decode("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF")
                    .unwrap(),
            ),
            signature: Signature {
                value: hex_to_bytes(
                    "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3",
                ),
            },
            verification_result: true,
        },
        TestVector {
            seckey: None,
            pubkey: PublicKey::try_new(hex_to_bytes(
                "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
            )).unwrap(),
            aux_rand: None,
            message: Some(
                hex::decode("4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703")
                    .unwrap(),
            ),
            signature: Signature {
                value: hex_to_bytes(
                    "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C6376AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4",
                ),
            },
            verification_result: true,
        },
        // Test with invalid public key
        // TestVector {
        //     seckey: None,
        //     pubkey: PublicKey::new(hex_to_bytes(
        //                     "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
        //                 )).unwrap(),
        //     aux_rand: None,
        //     message: Some(
        //                     hex::decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89").unwrap(),
        //                 ),
        //     signature: Signature {
        //                     value: hex_to_bytes(
        //                         "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
        //                     ),
        //                 },
        //     verification_result: false,
        // },
        TestVector {
            seckey: None,
            pubkey: PublicKey::try_new(hex_to_bytes(
                "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            )).unwrap(),
            aux_rand: None,
            message: Some(
                hex::decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
                    .unwrap(),
            ),
            signature: Signature {
                value: hex_to_bytes(
                    "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A14602975563CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2",
                ),
            },
            verification_result: false,
        },
        TestVector {
            seckey: None,
            pubkey: PublicKey::try_new(hex_to_bytes(
                "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            )).unwrap(),
            aux_rand: None,
            message: Some(
                hex::decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
                    .unwrap(),
            ),
            signature: Signature {
                value: hex_to_bytes(
                    "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD",
                ),
            },
            verification_result: false,
        },
        TestVector {
            seckey: None,
            pubkey: PublicKey::try_new(hex_to_bytes(
                "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            )).unwrap(),
            aux_rand: None,
            message: Some(
                hex::decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
                    .unwrap(),
            ),
            signature: Signature {
                value: hex_to_bytes(
                    "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6",
                ),
            },
            verification_result: false,
        },
        TestVector {
            seckey: None,
            pubkey: PublicKey::try_new(hex_to_bytes(
                "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            )).unwrap(),
            aux_rand: None,
            message: Some(
                hex::decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
                    .unwrap(),
            ),
            signature: Signature {
                value: hex_to_bytes(
                    "0000000000000000000000000000000000000000000000000000000000000000123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051",
                ),
            },
            verification_result: false,
        },
        TestVector {
            seckey: None,
            pubkey: PublicKey::try_new(hex_to_bytes(
                "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            )).unwrap(),
            aux_rand: None,
            message: Some(
                hex::decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
                    .unwrap(),
            ),
            signature: Signature {
                value: hex_to_bytes(
                    "00000000000000000000000000000000000000000000000000000000000000017615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197",
                ),
            },
            verification_result: false,
        },
        TestVector {
            seckey: None,
            pubkey: PublicKey::try_new(hex_to_bytes(
                "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            )).unwrap(),
            aux_rand: None,
            message: Some(
                hex::decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
                    .unwrap(),
            ),
            signature: Signature {
                value: hex_to_bytes(
                    "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
                ),
            },
            verification_result: false,
        },
        TestVector {
            seckey: None,
            pubkey: PublicKey::try_new(hex_to_bytes(
                "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            )).unwrap(),
            aux_rand: None,
            message: Some(
                hex::decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
                    .unwrap(),
            ),
            signature: Signature {
                value: hex_to_bytes(
                    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
                ),
            },
            verification_result: false,
        },
        TestVector {
            seckey: None,
            pubkey: PublicKey::try_new(hex_to_bytes(
                "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
            )).unwrap(),
            aux_rand: None,
            message: Some(
                hex::decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89")
                    .unwrap(),
            ),
            signature: Signature {
                value: hex_to_bytes(
                    "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141",
                ),
            },
            verification_result: false,
        },
        // Test with invalid public key
        // TestVector {
        //     seckey: None,
        //     pubkey: PublicKey::new(hex_to_bytes(
        //                     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
        //                 )).unwrap(),
        //     aux_rand: None,
        //     message: Some(
        //                     hex::decode("243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89").unwrap(),
        //                 ),
        //     signature: Signature {
        //                     value: hex_to_bytes(
        //                         "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E17776969E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B",
        //                     ),
        //                 },
        //     verification_result: false,
        // },
        TestVector {
            seckey: Some(PrivateKey::try_new(hex_to_bytes(
                "0340034003400340034003400340034003400340034003400340034003400340",
            )).unwrap()),
            pubkey: PublicKey::try_new(hex_to_bytes(
                "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
            )).unwrap(),
            aux_rand: Some(hex_to_bytes::<32>(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )),
            message: None,
            signature: Signature {
                value: hex_to_bytes(
                    "71535DB165ECD9FBBC046E5FFAEA61186BB6AD436732FCCC25291A55895464CF6069CE26BF03466228F19A3A62DB8A649F2D560FAC652827D1AF0574E427AB63",
                ),
            },
            verification_result: true,
        },
        TestVector {
            seckey: Some(PrivateKey::try_new(hex_to_bytes(
                "0340034003400340034003400340034003400340034003400340034003400340",
            )).unwrap()),
            pubkey: PublicKey::try_new(hex_to_bytes(
                "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
            )).unwrap(),
            aux_rand: Some(hex_to_bytes::<32>(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )),
            message: Some(hex::decode("11").unwrap()),
            signature: Signature {
                value: hex_to_bytes(
                    "08A20A0AFEF64124649232E0693C583AB1B9934AE63B4C3511F3AE1134C6A303EA3173BFEA6683BD101FA5AA5DBC1996FE7CACFC5A577D33EC14564CEC2BACBF",
                ),
            },
            verification_result: true,
        },
        TestVector {
            seckey: Some(PrivateKey::try_new(hex_to_bytes(
                "0340034003400340034003400340034003400340034003400340034003400340",
            )).unwrap()),
            pubkey: PublicKey::try_new(hex_to_bytes(
                "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
            )).unwrap(),
            aux_rand: Some(hex_to_bytes::<32>(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )),
            message: Some(hex::decode("0102030405060708090A0B0C0D0E0F1011").unwrap()),
            signature: Signature {
                value: hex_to_bytes(
                    "5130F39A4059B43BC7CAC09A19ECE52B5D8699D1A71E3C52DA9AFDB6B50AC370C4A482B77BF960F8681540E25B6771ECE1E5A37FD80E5A51897C5566A97EA5A5",
                ),
            },
            verification_result: true,
        },
        TestVector {
            seckey: Some(PrivateKey::try_new(hex_to_bytes(
                "0340034003400340034003400340034003400340034003400340034003400340",
            )).unwrap()),
            pubkey: PublicKey::try_new(hex_to_bytes(
                "778CAA53B4393AC467774D09497A87224BF9FAB6F6E68B23086497324D6FD117",
            )).unwrap(),
            aux_rand: Some(hex_to_bytes::<32>(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )),
            message: Some(
                hex::decode("99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999").unwrap(),
            ),
            signature: Signature {
                value: hex_to_bytes(
                    "403B12B0D8555A344175EA7EC746566303321E5DBFA8BE6F091635163ECA79A8585ED3E3170807E7C03B720FC54C7B23897FCBA0E9D0B4A06894CFD249F22367",
                ),
            },
            verification_result: true,
        },
    ]
}

fn hex_to_bytes<const N: usize>(hex: &str) -> [u8; N] {
    hex::decode(hex).unwrap().try_into().unwrap()
}
