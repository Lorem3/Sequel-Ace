//
//  SPLogFieldDecrypt.m
//  Sequel Ace
//

#import "SPLogFieldDecrypt.h"
#import "SPDataAdditions.h"
#import <CommonCrypto/CommonCrypto.h>
#import <AppKit/AppKit.h>
#include <zlib.h>

// cfg.json 中的 key 名称
static NSString * const kCfgKeyHex   = @"KEY";
static NSString * const kCfgKeyField = @"field";
static NSString * const kDefaultFieldName = @"log";

// 密文行前缀：日志中每个需要解密的行格式为 "i.<Base64密文>"
// 完整行示例：\ni.ABC123==\n
static NSString * const kLinePrefixLF   = @"\ni.";
static NSString * const kLinePrefixCRLF = @"\r\ni.";

@implementation SPLogFieldDecrypt

#pragma mark - 配置读取

+ (nullable NSDictionary *)_loadCfg {
    static NSDictionary *cachedCfg = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        NSString *cfgPath = [@"~/.SequelAce/cfg.json" stringByExpandingTildeInPath];
        NSData *data = [NSData dataWithContentsOfFile:cfgPath];
        if (!data) return;
        NSError *err = nil;
        id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:&err];
        if (err || ![obj isKindOfClass:[NSDictionary class]]) return;
        cachedCfg = (NSDictionary *)obj;
    });
    return cachedCfg;
}

+ (NSString *)targetFieldName {
    NSDictionary *cfg = [self _loadCfg];
    NSString *field = cfg[kCfgKeyField];
    if ([field isKindOfClass:[NSString class]] && field.length > 0) {
        return field;
    }
    return kDefaultFieldName;
}

+ (NSColor *)encryptedCellColor {
    static NSColor *cachedColor = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        // 默认淡红色
        NSColor *defaultColor = [NSColor colorWithCalibratedRed:1.0 green:0.88 blue:0.88 alpha:1.0];
        NSDictionary *cfg = [self _loadCfg];
        NSString *hex = cfg[@"encColor"];
        if (![hex isKindOfClass:[NSString class]]) { cachedColor = defaultColor; return; }

        // 去掉前缀 #，期望格式 RRGGBBAA（8位十六进制）
        NSString *h = [hex hasPrefix:@"#"] ? [hex substringFromIndex:1] : hex;
        if (h.length != 8) { cachedColor = defaultColor; return; }

        unsigned int rgba = 0;
        NSScanner *scanner = [NSScanner scannerWithString:h];
        if (![scanner scanHexInt:&rgba]) { cachedColor = defaultColor; return; }

        CGFloat r = ((rgba >> 24) & 0xFF) / 255.0;
        CGFloat g = ((rgba >> 16) & 0xFF) / 255.0;
        CGFloat b = ((rgba >>  8) & 0xFF) / 255.0;
        CGFloat a = ( rgba        & 0xFF) / 255.0;
        cachedColor = [NSColor colorWithCalibratedRed:r green:g blue:b alpha:a];
    });
    return cachedColor;
}

+ (BOOL)containsEncryptedContent:(NSString *)text {
    if (text.length == 0) return NO;
    return ([text rangeOfString:kLinePrefixLF].location != NSNotFound
            || [text rangeOfString:kLinePrefixCRLF].location != NSNotFound);
}

+ (nullable NSData *)_aesKeyFromCfg:(NSDictionary *)cfg {
    id keyVal = cfg[kCfgKeyHex];
    if (![keyVal isKindOfClass:[NSString class]]) return nil;

    NSData *keyData = [NSData dataWithHexString:(NSString *)keyVal];
    if (!keyData) return nil;

    NSUInteger len = keyData.length;
    // AES-128 = 16字节，AES-256 = 32字节
    if (len != kCCKeySizeAES128 && len != kCCKeySizeAES256) return nil;

    return keyData;
}

#pragma mark - Gzip 解压（inflateInit2 +16 支持 gzip header）

+ (nullable NSData *)_gunzip:(NSData *)data {
    if (data.length == 0) return nil;

    NSUInteger fullLen  = data.length;
    NSUInteger halfLen  = MAX(fullLen, (NSUInteger)1024) * 2;
    NSMutableData *out  = [NSMutableData dataWithLength:halfLen];

    z_stream strm;
    memset(&strm, 0, sizeof(strm));
    strm.next_in  = (Bytef *)data.bytes;
    strm.avail_in = (uInt)data.length;

    // +16 让 zlib 识别 gzip 头
    if (inflateInit2(&strm, 15 + 16) != Z_OK) return nil;

    int status;
    BOOL done = NO;
    do {
        if (strm.total_out >= out.length) {
            [out increaseLengthBy:halfLen];
        }
        strm.next_out  = (Bytef *)out.mutableBytes + strm.total_out;
        strm.avail_out = (uInt)(out.length - strm.total_out);

        status = inflate(&strm, Z_SYNC_FLUSH);
        if (status == Z_STREAM_END) { done = YES; break; }
        if (status != Z_OK) break;
    } while (strm.avail_out == 0);

    inflateEnd(&strm);
    if (!done) return nil;

    [out setLength:strm.total_out];
    return [NSData dataWithData:out];
}

#pragma mark - AES-ECB 解密

+ (nullable NSData *)_aesECBDecrypt:(NSData *)cipherData key:(NSData *)keyData {
    if (cipherData.length == 0) return nil;

    size_t keyLen = keyData.length; // 16 or 32
    size_t bufLen = cipherData.length + kCCBlockSizeAES128;
    void  *buf    = malloc(bufLen);
    if (!buf) return nil;

    size_t moved = 0;
    CCCryptorStatus status = CCCrypt(
        kCCDecrypt,
        kCCAlgorithmAES,
        kCCOptionECBMode | kCCOptionPKCS7Padding,
        keyData.bytes, keyLen,
        NULL,                   // ECB 无 IV
        cipherData.bytes, cipherData.length,
        buf, bufLen,
        &moved
    );

    if (status != kCCSuccess) {
        free(buf);
        return nil;
    }
    return [NSData dataWithBytesNoCopy:buf length:moved freeWhenDone:YES];
}

#pragma mark - 密文行提取

/**
 * 在 text 中查找前缀为 linePrefix（如 "\ni."）的行，
 * 提取 "i." 之后到行尾的 Base64 内容。
 *
 * 返回的 outLineRange 是 "i.<base64>" 在原字符串中的范围（不含前导换行），
 * 用于后续替换。若未找到返回 NSNotFound。
 *
 * 支持一次调用只处理第一个匹配行；日志中有多个加密行时可循环调用。
 */
+ (NSRange)_encryptedLineRangeInText:(NSString *)text
                           linePrefix:(NSString *)linePrefix
                          base64String:(NSString * __autoreleasing *)outBase64 {
    NSRange prefixRange = [text rangeOfString:linePrefix];
    if (prefixRange.location == NSNotFound) {
        return NSMakeRange(NSNotFound, 0);
    }

    // Base64 内容从 "i." 后面开始（跳过前导 \n 或 \r\n，但 "i." 本身保留在替换范围内）
    // linePrefix = "\ni." → Base64起点 = prefixRange.location + prefixRange.length
    // 替换范围起点 = prefixRange.location + 1（跳过 \n，从 "i." 开始）
    NSUInteger newlineLen  = [linePrefix hasPrefix:@"\r\n"] ? 2 : 1; // \r\n 或 \n
    NSUInteger lineStart   = prefixRange.location + newlineLen;       // "i." 的位置
    NSUInteger base64Start = NSMaxRange(prefixRange);                  // "i." 之后

    NSUInteger textLen = text.length;
    if (base64Start >= textLen) return NSMakeRange(NSNotFound, 0);

    // 取到行尾（\n 或 \r\n 之前），不包含换行符本身
    NSCharacterSet *newlines = [NSCharacterSet newlineCharacterSet];
    NSRange nlRange = [text rangeOfCharacterFromSet:newlines
                                            options:0
                                              range:NSMakeRange(base64Start, textLen - base64Start)];
    NSUInteger base64End = (nlRange.location != NSNotFound) ? nlRange.location : textLen;

    if (base64End <= base64Start) return NSMakeRange(NSNotFound, 0);

    NSString *b64 = [text substringWithRange:NSMakeRange(base64Start, base64End - base64Start)];
    b64 = [b64 stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    if (b64.length == 0) return NSMakeRange(NSNotFound, 0);

    if (outBase64) *outBase64 = b64;
    // 替换范围：从 "i." 开始到 Base64 内容末尾（不含换行）
    return NSMakeRange(lineStart, base64End - lineStart);
}

#pragma mark - 单行解密

+ (nullable NSString *)_decryptBase64Line:(NSString *)base64 key:(NSData *)keyData {
    NSData *cipherData = [[NSData alloc] initWithBase64EncodedString:base64
                                                             options:NSDataBase64DecodingIgnoreUnknownCharacters];
    if (!cipherData || cipherData.length == 0) return nil;

    NSData *decrypted = nil;
    @try {
        decrypted = [self _aesECBDecrypt:cipherData key:keyData];
    } @catch (NSException *e) {
        return nil;
    }
    if (!decrypted) return nil;

    NSData *unzipped = [self _gunzip:decrypted];
    if (!unzipped) return nil;

    NSString *plainText = [[NSString alloc] initWithData:unzipped encoding:NSUTF8StringEncoding];
    if (!plainText) return nil;

    // 字节一致性校验，防止替换字符（U+FFFD）悄悄混入
    NSData *reEncoded = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    if (!reEncoded || reEncoded.length != unzipped.length) return nil;

    return plainText;
}

#pragma mark - 主入口

+ (NSString *)displayStringForLogText:(NSString *)logText {
    if (logText.length == 0) return logText;

    NSDictionary *cfg = [self _loadCfg];
    if (!cfg) return logText;

    NSData *keyData = [self _aesKeyFromCfg:cfg];
    if (!keyData) return logText;

    // 确定行前缀风格（LF 或 CRLF），优先 LF
    NSString *linePrefix = nil;
    if ([logText rangeOfString:kLinePrefixLF].location != NSNotFound) {
        linePrefix = kLinePrefixLF;
    } else if ([logText rangeOfString:kLinePrefixCRLF].location != NSNotFound) {
        linePrefix = kLinePrefixCRLF;
    }
    if (!linePrefix) return logText;

    // 支持日志中有多行需要解密：从后往前替换，避免 range 偏移
    NSMutableString *result = [logText mutableCopy];
    NSMutableArray<NSValue *> *ranges   = [NSMutableArray array];
    NSMutableArray<NSString *> *b64List = [NSMutableArray array];

    // 收集所有加密行的位置（在原字符串中查找）
    NSUInteger searchFrom = 0;
    while (searchFrom < logText.length) {
        NSString *remaining = [logText substringFromIndex:searchFrom];
        NSString *b64 = nil;
        NSRange   rel = [self _encryptedLineRangeInText:remaining
                                             linePrefix:linePrefix
                                            base64String:&b64];
        if (rel.location == NSNotFound) break;

        // 转换为原字符串中的绝对 range
        NSRange absRange = NSMakeRange(searchFrom + rel.location, rel.length);
        [ranges addObject:[NSValue valueWithRange:absRange]];
        [b64List addObject:b64];
        searchFrom = absRange.location + absRange.length;
    }

    if (ranges.count == 0) return logText;

    // 从后往前替换，保持前面行的 range 有效
    BOOL anyReplaced = NO;
    for (NSInteger i = (NSInteger)ranges.count - 1; i >= 0; i--) {
        NSRange range    = [ranges[(NSUInteger)i] rangeValue];
        NSString *b64    = b64List[(NSUInteger)i];
        NSString *plain  = [self _decryptBase64Line:b64 key:keyData];
        if (!plain) continue; // 解密失败：保留原文

        NSString *replacement = [NSString stringWithFormat:
            @"\n\n------------------------------ [DECRYPT TXT BEGIN] ------------------------------\n\n%@\n\n------------------------------ [DECRYPT TXT END]  ------------------------------\n\n",
            plain];
        [result replaceCharactersInRange:range withString:replacement];
        anyReplaced = YES;
    }

    return anyReplaced ? [result copy] : logText;
}

@end
