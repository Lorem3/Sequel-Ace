//
//  SPLogFieldDecrypt.h
//  Sequel Ace
//
//  Provides AES-ECB decryption for designated log fields.
//  Configuration is read from ~/.SequelAce/cfg.json:
//    {
//      "KEY":   "<hex-encoded AES key, 32 or 64 hex chars>",
//      "field": "<column name to target, default: log>"
//    }
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/**
 * 读取 ~/.SequelAce/cfg.json，提供 log 字段自动 AES-ECB 解密能力。
 * 线程安全：内部每次调用重新读配置文件（预览场景频率极低，无需缓存）。
 */
@interface SPLogFieldDecrypt : NSObject

/**
 * 从 cfg.json 读取目标列名（field 字段），默认返回 @"log"。
 * 若文件不存在、JSON 无效或 field 为空，均返回 @"log"。
 */
+ (NSString *)targetFieldName;

/**
 * 快速判断字符串中是否含有加密行（格式：换行 + "i." + Base64内容）。
 * 不执行解密，仅用于列表视图的背景色判断。
 */
+ (BOOL)containsEncryptedContent:(NSString *)text;

/**
 * 从 cfg.json 读取 encColor 字段（格式 #RRGGBBAA，如 #FFE0E0FF）。
 * 若字段缺失或格式非法，返回默认淡红色。
 * 颜色在 cfg 从磁盘重新加载后会按 encColor 重新计算。
 */
+ (NSColor *)encryptedCellColor;

/**
 * 从磁盘重新读取 ~/.SequelAce/cfg.json，并刷新内存缓存与 encColor。
 */
+ (void)reloadCfgFromDisk;

/**
 * 对 logText 尝试执行解密展示替换：
 *   - 查找格式为 "i.<Base64密文>" 的行（兼容 \n 和 \r\n 换行）
 *     例：...\ni.ABC123==\n...
 *   - 提取 "i." 之后到行尾的 Base64 内容
 *   - Base64 → AES-ECB/PKCS7 解密 → Gzip 解压 → UTF-8 校验
 *   - 若成功，替换 "i.<Base64>" 为：
 *       [decrypt]
 *       --------------- begin----------------------------------
 *       <plaintext>
 *       ---------------------------------------end ----------------------
 *   - 支持同一 logText 中存在多个加密行，逐一替换
 *   - 任何步骤失败均静默保留原行，不影响其他行
 *
 * @param logText 原始字段内容字符串
 * @return 替换后的展示字符串，或原始字符串（解密失败/无标记时）
 */
+ (NSString *)displayStringForLogText:(NSString *)logText;

@end

NS_ASSUME_NONNULL_END
