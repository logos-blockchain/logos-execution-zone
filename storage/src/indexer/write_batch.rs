use super::*;

impl RocksDBIO {
    // Accounts meta

    pub(crate) fn update_acc_meta_batch(
        &self,
        acc_id: [u8; 32],
        num_tx: u64,
        write_batch: &mut WriteBatch,
    ) -> DbResult<()> {
        let cf_ameta = self.account_meta_column();

        write_batch.put_cf(
            &cf_ameta,
            borsh::to_vec(&acc_id).map_err(|err| {
                DbError::borsh_cast_message(err, Some("Failed to serialize account id".to_string()))
            })?,
            borsh::to_vec(&num_tx).map_err(|err| {
                DbError::borsh_cast_message(
                    err,
                    Some("Failed to serialize acc metadata".to_string()),
                )
            })?,
        );

        Ok(())
    }

    // Account

    pub fn put_account_transactions(
        &self,
        acc_id: [u8; 32],
        tx_hashes: Vec<[u8; 32]>,
    ) -> DbResult<()> {
        let acc_num_tx = self.get_acc_meta_num_tx(acc_id)?.unwrap_or(0);
        let cf_att = self.account_id_to_tx_hash_column();
        let mut write_batch = WriteBatch::new();

        for (tx_id, tx_hash) in tx_hashes.iter().enumerate() {
            let put_id = acc_num_tx + tx_id as u64;

            let mut prefix = borsh::to_vec(&acc_id).map_err(|berr| {
                DbError::borsh_cast_message(
                    berr,
                    Some("Failed to serialize account id".to_string()),
                )
            })?;
            let suffix = borsh::to_vec(&put_id).map_err(|berr| {
                DbError::borsh_cast_message(berr, Some("Failed to serialize tx id".to_string()))
            })?;

            prefix.extend_from_slice(&suffix);

            write_batch.put_cf(
                &cf_att,
                prefix,
                borsh::to_vec(tx_hash).map_err(|berr| {
                    DbError::borsh_cast_message(
                        berr,
                        Some("Failed to serialize tx hash".to_string()),
                    )
                })?,
            );
        }

        self.update_acc_meta_batch(
            acc_id,
            acc_num_tx + (tx_hashes.len() as u64),
            &mut write_batch,
        )?;

        self.db.write(write_batch).map_err(|rerr| {
            DbError::rocksdb_cast_message(rerr, Some("Failed to write batch".to_string()))
        })
    }
}