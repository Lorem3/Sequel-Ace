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
static NSString * const kCfgKeyHex    = @"KEY";
static NSString * const kCfgKeyHexOld = @"KEY_OLD";
static NSString * const kCfgKeyField  = @"field";
static NSString * const kDefaultFieldName = @"log";

// 密文行前缀（完整行示例：\ni.ABC123==\n）
static NSString * const kLinePrefixILF   = @"\ni.";
static NSString * const kLinePrefixICRLF = @"\r\ni.";
static NSString * const kLinePrefixALF   = @"\na.";
static NSString * const kLinePrefixACRLF = @"\r\na.";
static NSString * const kLinePrefixOLF   = @"\no.";
static NSString * const kLinePrefixOCRLF = @"\r\no.";

typedef NS_ENUM(NSUInteger, SPLogEncryptFormat) {
    SPLogEncryptFormatI, // KEY:     Base64 → AES → Gzip → UTF-8
    SPLogEncryptFormatA, // KEY_OLD: Base64 → AES → Base64 → Gzip → UTF-8
    SPLogEncryptFormatO, // KEY_OLD: Base64 → AES → UTF-8
};

// 与 encColor 缓存联动：仅在 _loadCfg 真正从磁盘读入后自增
static NSUInteger s_cfgDiskReadSerial = 0;

// 为 YES 时下一次 _loadCfg 读磁盘；reloadCfgFromDisk 置为 YES。首次启动为 YES。
static BOOL s_cfgDiskReadRequired = YES;

@implementation SPLogFieldDecrypt

#pragma mark - 配置读取

+ (nullable NSDictionary *)_loadCfg {
    static NSDictionary *cachedCfg = nil;
    if (!s_cfgDiskReadRequired && cachedCfg != nil) {
        return cachedCfg;
    }
    s_cfgDiskReadRequired = NO;

    NSString *cfgPath = [@"~/.SequelAce/cfg.json" stringByExpandingTildeInPath];
    NSData *data = [NSData dataWithContentsOfFile:cfgPath];
    if (!data) {
        s_cfgDiskReadSerial++;
        cachedCfg = nil;
        return nil;
    }
    NSError *err = nil;
    id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:&err];
    if (err || ![obj isKindOfClass:[NSDictionary class]]) {
        s_cfgDiskReadSerial++;
        cachedCfg = nil;
        return nil;
    }
    cachedCfg = (NSDictionary *)obj;
    s_cfgDiskReadSerial++;
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
    static NSUInteger encColorBuiltCfgSerial = 0;

    NSDictionary *cfg = [self _loadCfg];
    if (encColorBuiltCfgSerial != s_cfgDiskReadSerial) {
        encColorBuiltCfgSerial = s_cfgDiskReadSerial;
        // 默认淡红色
        NSColor *defaultColor = [NSColor colorWithCalibratedRed:1.0 green:0.88 blue:0.88 alpha:1.0];
        NSString *hex = cfg[@"encColor"];
        if (![hex isKindOfClass:[NSString class]]) {
            cachedColor = defaultColor;
            return cachedColor;
        }

        // 去掉前缀 #，期望格式 RRGGBBAA（8位十六进制）
        NSString *h = [hex hasPrefix:@"#"] ? [hex substringFromIndex:1] : hex;
        if (h.length != 8) {
            cachedColor = defaultColor;
            return cachedColor;
        }

        unsigned int rgba = 0;
        NSScanner *scanner = [NSScanner scannerWithString:h];
        if (![scanner scanHexInt:&rgba]) {
            cachedColor = defaultColor;
            return cachedColor;
        }

        CGFloat r = ((rgba >> 24) & 0xFF) / 255.0;
        CGFloat g = ((rgba >> 16) & 0xFF) / 255.0;
        CGFloat b = ((rgba >>  8) & 0xFF) / 255.0;
        CGFloat a = ( rgba        & 0xFF) / 255.0;
        cachedColor = [NSColor colorWithCalibratedRed:r green:g blue:b alpha:a];
    }
    return cachedColor;
}

+ (void)reloadCfgFromDisk {
    s_cfgDiskReadRequired = YES;
    (void)[self _loadCfg];
}

+ (BOOL)_text:(NSString *)text containsAnyPrefix:(NSArray<NSString *> *)prefixes {
    for (NSString *prefix in prefixes) {
        if ([text rangeOfString:prefix].location != NSNotFound) {
            return YES;
        }
    }
    return NO;
}

+ (BOOL)containsEncryptedContent:(NSString *)text {
    if (text.length == 0) return NO;
    return [self _text:text containsAnyPrefix:@[
        kLinePrefixILF, kLinePrefixICRLF,
        kLinePrefixALF, kLinePrefixACRLF,
        kLinePrefixOLF, kLinePrefixOCRLF,
    ]];
}

+ (nullable NSData *)_aesKeyFromCfg:(NSDictionary *)cfg keyName:(NSString *)keyName {
    id keyVal = cfg[keyName];
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
 * 提取标记（"i." / "a." / "o."）之后到行尾的 Base64 内容。
 *
 * 返回的 range 是 "x.<base64>" 在 text 参数中的范围（不含前导换行），用于后续替换。
 * 支持一次调用只处理第一个匹配行；循环调用可收集多行。
 */
+ (NSRange)_encryptedLineRangeInText:(NSString *)text
                           linePrefix:(NSString *)linePrefix
                          base64String:(NSString * __autoreleasing *)outBase64 {
    NSRange prefixRange = [text rangeOfString:linePrefix];
    if (prefixRange.location == NSNotFound) {
        return NSMakeRange(NSNotFound, 0);
    }

    NSUInteger newlineLen  = [linePrefix hasPrefix:@"\r\n"] ? 2 : 1;
    NSUInteger lineStart   = prefixRange.location + newlineLen;
    NSUInteger base64Start = NSMaxRange(prefixRange);

    NSUInteger textLen = text.length;
    if (base64Start >= textLen) return NSMakeRange(NSNotFound, 0);

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
    return NSMakeRange(lineStart, base64End - lineStart);
}

+ (void)_collectEncryptedLinesInText:(NSString *)fullText
                          linePrefix:(NSString *)linePrefix
                              format:(SPLogEncryptFormat)format
                          intoRanges:(NSMutableArray<NSValue *> *)ranges
                             base64s:(NSMutableArray<NSString *> *)b64List
                             formats:(NSMutableArray<NSNumber *> *)formatList {
    NSUInteger searchFrom = 0;
    while (searchFrom < fullText.length) {
        NSString *remaining = [fullText substringFromIndex:searchFrom];
        NSString *b64 = nil;
        NSRange rel = [self _encryptedLineRangeInText:remaining
                                           linePrefix:linePrefix
                                         base64String:&b64];
        if (rel.location == NSNotFound) break;

        NSRange absRange = NSMakeRange(searchFrom + rel.location, rel.length);
        [ranges addObject:[NSValue valueWithRange:absRange]];
        [b64List addObject:b64];
        [formatList addObject:@(format)];
        searchFrom = NSMaxRange(absRange);
    }
}

#pragma mark - 单行解密

+ (nullable NSData *)_cipherDataFromBase64:(NSString *)base64 {
    NSData *cipherData = [[NSData alloc] initWithBase64EncodedString:base64
                                                             options:NSDataBase64DecodingIgnoreUnknownCharacters];
    if (!cipherData || cipherData.length == 0) return nil;
    return cipherData;
}

+ (nullable NSData *)_aesDecryptBase64:(NSString *)base64 key:(NSData *)keyData {
    NSData *cipherData = [self _cipherDataFromBase64:base64];
    if (!cipherData) return nil;

    NSData *decrypted = nil;
    @try {
        decrypted = [self _aesECBDecrypt:cipherData key:keyData];
    } @catch (NSException *e) {
        return nil;
    }
    return decrypted;
}

+ (nullable NSString *)_utf8PlainTextValidatingBytes:(NSData *)data {
    if (!data || data.length == 0) return nil;

    NSString *plainText = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    if (!plainText) return nil;

    NSData *reEncoded = [plainText dataUsingEncoding:NSUTF8StringEncoding];
    if (!reEncoded || reEncoded.length != data.length) return nil;

    return plainText;
}

+ (nullable NSString *)_decryptBase64LineFormatI:(NSString *)base64 key:(NSData *)keyData {
    NSData *decrypted = [self _aesDecryptBase64:base64 key:keyData];
    if (!decrypted) return nil;

    NSData *unzipped = [self _gunzip:decrypted];
    if (!unzipped) return nil;

    return [self _utf8PlainTextValidatingBytes:unzipped];
}

+ (nullable NSString *)_decryptBase64LineFormatA:(NSString *)base64 key:(NSData *)keyData {
    NSData *decrypted = [self _aesDecryptBase64:base64 key:keyData];
    if (!decrypted) return nil;

    NSString *innerB64 = [[NSString alloc] initWithData:decrypted encoding:NSUTF8StringEncoding];
    if (!innerB64) return nil;
    innerB64 = [innerB64 stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (innerB64.length == 0) return nil;

    NSData *innerData = [[NSData alloc] initWithBase64EncodedString:innerB64
                                                            options:NSDataBase64DecodingIgnoreUnknownCharacters];
    if (!innerData || innerData.length == 0) return nil;

    NSData *unzipped = [self _gunzip:innerData];
    if (!unzipped) return nil;

    return [self _utf8PlainTextValidatingBytes:unzipped];
}

+ (nullable NSString *)_decryptBase64LineFormatO:(NSString *)base64 key:(NSData *)keyData {
    NSData *decrypted = [self _aesDecryptBase64:base64 key:keyData];
    if (!decrypted) return nil;

    return [self _utf8PlainTextValidatingBytes:decrypted];
}

+ (nullable NSString *)_decryptLine:(NSString *)base64
                             format:(SPLogEncryptFormat)format
                                key:(NSData *)keyData {
    switch (format) {
        case SPLogEncryptFormatI:
            return [self _decryptBase64LineFormatI:base64 key:keyData];
        case SPLogEncryptFormatA:
            return [self _decryptBase64LineFormatA:base64 key:keyData];
        case SPLogEncryptFormatO:
            return [self _decryptBase64LineFormatO:base64 key:keyData];
    }
}

#pragma mark - 主入口

+ (NSString *)displayStringForLogText:(NSString *)logText {
    if (logText.length == 0) return logText;
    if (![self containsEncryptedContent:logText]) return logText;

    NSDictionary *cfg = [self _loadCfg];
    if (!cfg) return logText;

    NSData *keyData    = [self _aesKeyFromCfg:cfg keyName:kCfgKeyHex];
    NSData *keyOldData = [self _aesKeyFromCfg:cfg keyName:kCfgKeyHexOld];

    NSMutableArray<NSValue *> *ranges    = [NSMutableArray array];
    NSMutableArray<NSString *> *b64List = [NSMutableArray array];
    NSMutableArray<NSNumber *> *formatList = [NSMutableArray array];

    [self _collectEncryptedLinesInText:logText linePrefix:kLinePrefixILF   format:SPLogEncryptFormatI intoRanges:ranges base64s:b64List formats:formatList];
    [self _collectEncryptedLinesInText:logText linePrefix:kLinePrefixICRLF format:SPLogEncryptFormatI intoRanges:ranges base64s:b64List formats:formatList];
    [self _collectEncryptedLinesInText:logText linePrefix:kLinePrefixALF   format:SPLogEncryptFormatA intoRanges:ranges base64s:b64List formats:formatList];
    [self _collectEncryptedLinesInText:logText linePrefix:kLinePrefixACRLF format:SPLogEncryptFormatA intoRanges:ranges base64s:b64List formats:formatList];
    [self _collectEncryptedLinesInText:logText linePrefix:kLinePrefixOLF   format:SPLogEncryptFormatO intoRanges:ranges base64s:b64List formats:formatList];
    [self _collectEncryptedLinesInText:logText linePrefix:kLinePrefixOCRLF format:SPLogEncryptFormatO intoRanges:ranges base64s:b64List formats:formatList];

    if (ranges.count == 0) return logText;

    // 按起始位置从大到小排序，从后往前替换
    NSMutableArray<NSNumber *> *indices = [NSMutableArray arrayWithCapacity:ranges.count];
    for (NSUInteger i = 0; i < ranges.count; i++) {
        [indices addObject:@(i)];
    }
    [indices sortUsingComparator:^NSComparisonResult(NSNumber *a, NSNumber *b) {
        NSRange ra = [ranges[a.unsignedIntegerValue] rangeValue];
        NSRange rb = [ranges[b.unsignedIntegerValue] rangeValue];
        if (ra.location > rb.location) return NSOrderedAscending;
        if (ra.location < rb.location) return NSOrderedDescending;
        return NSOrderedSame;
    }];

    NSMutableString *result = [logText mutableCopy];
    BOOL anyReplaced = NO;

    for (NSNumber *idxNum in indices) {
        NSUInteger i = idxNum.unsignedIntegerValue;
        NSRange range = [ranges[i] rangeValue];
        NSString *b64 = b64List[i];
        SPLogEncryptFormat format = (SPLogEncryptFormat)formatList[i].unsignedIntegerValue;

        NSData *key = nil;
        if (format == SPLogEncryptFormatI) {
            key = keyData;
        } else {
            key = keyOldData;
        }
        if (!key) continue;

        NSString *plain = [self _decryptLine:b64 format:format key:key];
        if (!plain) continue;

        NSString *replacement = [NSString stringWithFormat:
            (@"\n------------------BEGIN DECRYPTION------------------\n\n"
             @"%@"
             @"\n\n------------------END DECRYPTION------------------\n"),
            plain];
        [result replaceCharactersInRange:range withString:replacement];
        anyReplaced = YES;
    }

    return anyReplaced ? [result copy] : logText;
}

@end
