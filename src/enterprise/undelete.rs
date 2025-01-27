use serde::{Deserialize, Serialize}; // 引入serde库用于序列化和反序列化
use store::{
    write::{
        key::{DeserializeBigEndian, KeySerializer}, // 引入用于序列化键的模块
        now, BatchBuilder, BlobOp, ValueClass, // 引入用于批量操作和Blob操作的模块
    },
    IterateParams, ValueKey, U32_LEN, U64_LEN, // 引入用于迭代参数和键值的模块
};
use trc::AddContext; // 引入trc库用于添加上下文
use utils::{BlobHash, BLOB_HASH_LEN}; // 引入utils库用于Blob哈希操作

use crate::Core; // 引入当前crate的Core模块

// 定义DeletedBlob结构体，用于表示已删除的Blob
#[derive(Debug, Serialize, Deserialize)]
pub struct DeletedBlob<H, T, C> {
    pub hash: H, // Blob的哈希值
    pub size: usize, // Blob的大小
    #[serde(rename = "deletedAt")]
    pub deleted_at: T, // 删除时间
    #[serde(rename = "expiresAt")]
    pub expires_at: T, // 过期时间
    pub collection: C, // 集合
}

// 为Core结构体实现方法
impl Core {
    // 定义hold_undelete方法，用于保留删除操作
    pub fn hold_undelete(
        &self,
        batch: &mut BatchBuilder, // 批量构建器
        collection: u8, // 集合ID
        blob_hash: &BlobHash, // Blob哈希值
        blob_size: usize, // Blob大小
    ) {
        // 检查是否存在undelete配置
        if let Some(undelete) = self.enterprise.as_ref().and_then(|e| e.undelete.as_ref()) {
            let now = now(); // 获取当前时间

            // 设置保留操作
            batch.set(
                BlobOp::Reserve {
                    hash: blob_hash.clone(), // 克隆Blob哈希值
                    until: now + undelete.retention.as_secs(), // 设置保留时间
                },
                KeySerializer::new(U64_LEN + U64_LEN)
                    .write(blob_size as u32) // 写入Blob大小
                    .write(now) // 写入当前时间
                    .write(collection) // 写入集合ID
                    .finalize(), // 完成序列化
            );
        }
    }

    // 定义list_deleted方法，用于列出已删除的Blob
    pub async fn list_deleted(
        &self,
        account_id: u32, // 账户ID
    ) -> trc::Result<Vec<DeletedBlob<BlobHash, u64, u8>>> {
        let from_key = ValueKey {
            account_id, // 设置起始键的账户ID
            collection: 0,
            document_id: 0,
            class: ValueClass::Blob(BlobOp::Reserve {
                hash: BlobHash::default(), // 设置默认哈希值
                until: 0,
            }),
        };
        let to_key = ValueKey {
            account_id: account_id + 1, // 设置结束键的账户ID
            collection: 0,
            document_id: 0,
            class: ValueClass::Blob(BlobOp::Reserve {
                hash: BlobHash::default(), // 设置默认哈希值
                until: 0,
            }),
        };

        let now = now(); // 获取当前时间
        let mut results = Vec::new(); // 初始化结果向量

        // 迭代存储数据
        self.storage
            .data
            .iterate(
                IterateParams::new(from_key, to_key).ascending(), // 设置迭代参数
                |key, value| {
                    let expires_at = key.deserialize_be_u64(key.len() - U64_LEN)?; // 反序列化过期时间
                    if value.len() == U32_LEN + U64_LEN + 1 && expires_at > now {
                        results.push(DeletedBlob {
                            hash: BlobHash::try_from_hash_slice(
                                key.get(U32_LEN..U32_LEN + BLOB_HASH_LEN).ok_or_else(|| {
                                    trc::Error::corrupted_key(key, value.into(), trc::location!())
                                })?,
                            )
                            .unwrap(), // 获取Blob哈希值
                            size: value.deserialize_be_u32(0)? as usize, // 获取Blob大小
                            deleted_at: value.deserialize_be_u64(U32_LEN)?, // 获取删除时间
                            expires_at, // 获取过期时间
                            collection: *value.last().unwrap(), // 获取集合ID
                        });
                    }
                    Ok(true)
                },
            )
            .await
            .caused_by(trc::location!())?;

        Ok(results) // 返回结果
    }
}
