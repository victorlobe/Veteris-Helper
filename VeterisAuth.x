#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <objc/runtime.h>
#include <mach-o/dyld.h>
#include <mach/mach_time.h>
#include <math.h>
#include <pthread.h>
#include "Auth/BBHTTPInterface.h"
#include "vauth.h"
#include "vauth_attest.h"
#include "vauth_build_config.h"

static const char VAOwnRequest;
static NSLock *VALock;
static NSDictionary *VAHeaders;
static NSDictionary *VACredentials;
static NSString *VASession;
static double VAOffset, VAExpires;
static BOOL VANeedSession, VANeedRegister;
static uint8_t VAHash[32];
static NSString *VAString(unsigned index) {
    char buffer[128]; vauth_build_string(index, buffer);
    NSString *value = [NSString stringWithUTF8String:buffer];
    vauth_wipe(buffer, sizeof(buffer)); return value;
}

static double VAClock(void) {
    mach_timebase_info_data_t info;
    mach_timebase_info(&info);
    return (double)mach_absolute_time() * info.numer / info.denom / 1e9;
}
static int VARandom(void *ctx, unsigned char *out, size_t size) {
    (void)ctx;
    return SecRandomCopyBytes(kSecRandomDefault, size, out) == errSecSuccess ? 0 : -1;
}
static NSString *VAHeader(NSDictionary *headers, NSString *name) {
    for (id key in headers) {
        if ([key isKindOfClass:[NSString class]] && [key caseInsensitiveCompare:name] == NSOrderedSame) {
            id value = [headers objectForKey:key];
            return [value isKindOfClass:[NSString class]] ? value : nil;
        }
    }
    return nil;
}
static BOOL VATarget(BBHTTPRequest *request) {
    const char *url = [[[request url] absoluteString] UTF8String];
    vauth_url_parts parts;
    return url && vauth_split_url(url, &parts) == VAUTH_OK && vauth_is_signed_host(parts.host, parts.host_len);
}
static void VAClearAuth(BBHTTPRequest *request) {
    NSMutableDictionary *headers = [[request headers] mutableCopy];
    for (NSString *key in [[headers allKeys] copy]) {
        if ([[key lowercaseString] hasPrefix:@"x-veteris-auth-"] ||
            [key caseInsensitiveCompare:@"X-Veteris-Helper-Version"] == NSOrderedSame)
            [headers removeObjectForKey:key];
    }
    [request setHeaders:headers];
}
static NSDictionary *VAKeychainQuery(void) {
    return [NSDictionary dictionaryWithObjectsAndKeys:
        (__bridge id)kSecClassGenericPassword, (__bridge id)kSecClass,
        VAString(VAS_SERVICE), (__bridge id)kSecAttrService,
        @"installation", (__bridge id)kSecAttrAccount, nil];
}
static BOOL VAValidCredentials(id value) {
    if (![value isKindOfClass:[NSDictionary class]]) return NO;
    id keyID = [value objectForKey:@"key_id"], key = [value objectForKey:@"install_key"];
    id offset = [value objectForKey:@"offset"];
    return [keyID isKindOfClass:[NSString class]] && vauth_valid_key_id([keyID UTF8String]) &&
        [key isKindOfClass:[NSData class]] && [key length] == 32 &&
        [offset isKindOfClass:[NSNumber class]] && isfinite([offset doubleValue]);
}
static NSDictionary *VALoad(void) {
    NSMutableDictionary *query = [VAKeychainQuery() mutableCopy];
    [query setObject:(__bridge id)kCFBooleanTrue forKey:(__bridge id)kSecReturnData];
    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
    NSData *data = CFBridgingRelease(result);
    if (status != errSecSuccess || ![data isKindOfClass:[NSData class]]) return nil;
    id value = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:NULL];
    return VAValidCredentials(value) ? value : nil;
}
static void VASave(NSDictionary *credentials, double offset) {
    if (!credentials) return;
    NSMutableDictionary *value = [credentials mutableCopy];
    [value setObject:[NSNumber numberWithDouble:offset] forKey:@"offset"];
    NSData *data = [NSPropertyListSerialization dataWithPropertyList:value format:NSPropertyListBinaryFormat_v1_0 options:0 error:NULL];
    if (!data) return;
    NSDictionary *attributes = [NSDictionary dictionaryWithObjectsAndKeys:data, (__bridge id)kSecValueData,
        (__bridge id)kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, (__bridge id)kSecAttrAccessible, nil];
    OSStatus status = SecItemUpdate((__bridge CFDictionaryRef)VAKeychainQuery(), (__bridge CFDictionaryRef)attributes);
    if (status == errSecItemNotFound) {
        NSMutableDictionary *query = [VAKeychainQuery() mutableCopy];
        [query addEntriesFromDictionary:attributes];
        status = SecItemAdd((__bridge CFDictionaryRef)query, NULL);
    }
    if (status != errSecSuccess) NSLog(@"Veteris Auth: keychain save failed (%ld), using memory for this run.", (long)status);
}

static BOOL VASign(BBHTTPRequest *request, NSDictionary *credentials, NSString *session, double offset) {
    if (!VAValidCredentials(credentials) || !session) return NO;
    NSString *version = VAHeader([request headers], @"X-Veteris-Version");
    NSString *absolute = [[request url] absoluteString];
    const char *url = [absolute UTF8String];
    vauth_url_parts parts;
    char nonce[33], signature[65];
    double timestamp = [[NSDate date] timeIntervalSince1970] + offset;
    if (!version || !isfinite(timestamp) || timestamp < 0 || timestamp > 1e12 ||
        vauth_split_url(url, &parts) != VAUTH_OK || !vauth_is_signed_host(parts.host, parts.host_len) ||
        vauth_new_nonce(VARandom, NULL, nonce) != VAUTH_OK) return NO;
    NSData *body = [request uploadData];
    vauth_request input = {0};
    input.method = [[request verb] UTF8String];
    input.path = parts.path; input.path_len = parts.path_len;
    input.query = parts.query; input.query_len = parts.query_len;
    input.body = [body bytes]; input.body_len = [body length];
    input.timestamp = (int64_t)timestamp; input.nonce_hex = nonce;
    input.key_id = [[credentials objectForKey:@"key_id"] UTF8String];
    input.session = [session UTF8String]; input.veteris_version = [version UTF8String];
    input.helper_version = VAUTH_HELPER_VERSION;
    if (vauth_sign_request([[credentials objectForKey:@"install_key"] bytes], &input, signature) != VAUTH_OK) return NO;
    NSDictionary *added = [NSDictionary dictionaryWithObjectsAndKeys:
        @"1", VAString(VAS_VERSION), [credentials objectForKey:@"key_id"], VAString(VAS_KEY_ID),
        [NSString stringWithFormat:@"%lld", (long long)input.timestamp], VAString(VAS_TIMESTAMP),
        [NSString stringWithUTF8String:nonce], VAString(VAS_NONCE),
        session, VAString(VAS_SESSION), [NSString stringWithUTF8String:signature], VAString(VAS_SIGNATURE),
        @VAUTH_HELPER_VERSION, VAString(VAS_HELPER), nil];
    // curl keeps custom headers on redirects
    [request setMaxRedirects:0];
    for (NSString *key in added) {
        if (![request setValue:[added objectForKey:key] forHeader:key]) { VAClearAuth(request); return NO; }
    }
    vauth_wipe(signature, sizeof(signature));
    return YES;
}

static NSString *VAFormEscape(NSString *text) {
    NSMutableString *result = [NSMutableString string];
    NSData *data = [text dataUsingEncoding:NSUTF8StringEncoding];
    const unsigned char *bytes = [data bytes];
    for (NSUInteger i = 0; i < [data length]; i++) {
        unsigned char c = bytes[i];
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || strchr("-._~", c))
            [result appendFormat:@"%c", c];
        else [result appendFormat:@"%%%02X", c];
    }
    return result;
}
static NSDictionary *VASend(NSString *route, NSDictionary *form, NSDictionary *headers,
                             NSDictionary *credentials, double offset) {
    BBHTTPRequest *request = [[NSClassFromString(@"BBHTTPRequest") alloc]
        initWithTarget:[VAString(VAS_ENDPOINT) stringByAppendingString:route]
        andVerb:form ? @"POST" : @"GET"];
    if (!request) return nil;
    objc_setAssociatedObject(request, &VAOwnRequest, @YES, OBJC_ASSOCIATION_RETAIN_NONATOMIC);
    for (NSString *key in headers) [request setValue:[headers objectForKey:key] forHeader:key];
    [request setMaxRedirects:0]; [request setConnectionTimeout:15];
    if (form) {
        NSMutableArray *parts = [NSMutableArray array];
        for (NSString *key in [[form allKeys] sortedArrayUsingSelector:@selector(compare:)])
            [parts addObject:[NSString stringWithFormat:@"%@=%@", VAFormEscape(key), VAFormEscape([form objectForKey:key])]];
        NSData *body = [[parts componentsJoinedByString:@"&"] dataUsingEncoding:NSUTF8StringEncoding];
        if (![request setUploadData:body withContentType:@"application/x-www-form-urlencoded"]) return nil;
    }
    if (credentials && !VASign(request, credentials, @"", offset)) return nil;
    [request downloadContentAsData];
    // no NSObject subclasses, iOS 5 can't load the dylib then
    NSCondition *condition = [NSCondition new];
    __block NSDictionary *replyValue = nil;
    __block BOOL replyDone = NO;
    [request setFinishBlock:^(BBHTTPRequest *finished) {
        NSDictionary *value = nil;
        @try {
            id data = [[finished response] content];
            if (![finished error] && [[finished response] code] == 200 &&
                [data isKindOfClass:[NSData class]] && [data length] <= 16384) {
                id plist = [NSPropertyListSerialization propertyListWithData:data options:NSPropertyListImmutable format:NULL error:NULL];
                if ([plist isKindOfClass:[NSDictionary class]]) value = plist;
            }
        } @catch (NSException *exception) { value = nil; }
        [condition lock]; replyValue = value; replyDone = YES; [condition signal]; [condition unlock];
    }];
    if (![(BBHTTPExecutor *)[NSClassFromString(@"BBHTTPExecutor") sharedExecutor] executeRequest:request]) return nil;
    double deadline = VAClock() + 25;
    [condition lock];
    while (!replyDone && VAClock() < deadline)
        [condition waitUntilDate:[NSDate dateWithTimeIntervalSinceNow:1]];
    NSDictionary *value = replyValue;
    BOOL done = replyDone;
    [condition unlock];
    if (!done) [request cancel];
    return value;
}
static BOOL VATime(id value, double *offset) {
    if (![value isKindOfClass:[NSNumber class]]) return NO;
    double time = [value doubleValue];
    if (!isfinite(time) || time <= 0 || time > 1e12) return NO;
    *offset = time - [[NSDate date] timeIntervalSince1970];
    return YES;
}
static NSMutableDictionary *VAAttestation(NSDictionary *challenge, NSString *subject, NSDictionary *headers) {
    NSString *nonce = [challenge objectForKey:@"nonce"];
    NSString *version = VAHeader(headers, @"X-Veteris-Version");
    if (![nonce isKindOfClass:[NSString class]] || !version || !subject) return nil;
    vauth_attest_input input = {[nonce UTF8String], [subject UTF8String], [version UTF8String], VAUTH_HELPER_VERSION, VAHash};
    char proof[65], hash[65];
    if (vauth_attest(&input, proof) != VAUTH_OK) return nil;
    vauth_hex_encode(VAHash, 32, hash);
    return [NSMutableDictionary dictionaryWithObjectsAndKeys:
        [NSString stringWithUTF8String:vauth_attest_kind()], @"kind", nonce, @"challenge",
        [NSString stringWithUTF8String:hash], @"code_hash", [NSString stringWithUTF8String:proof], @"proof",
        version, @"veteris_version", @VAUTH_HELPER_VERSION, @"helper_version", nil];
}
static NSDictionary *VARegister(NSDictionary *headers, double *offset) {
    for (NSUInteger index = 0; index < sizeof(vauth_server_keys)/sizeof(vauth_server_keys[0]); index++) {
        NSDictionary *challenge = VASend(@"challenge", nil, headers, nil, 0);
        if (!VATime([challenge objectForKey:@"server_time"], offset)) return nil;
        uint8_t secret[32] = {0}, publicKey[32], server[32], wrapped[60], key[32] = {0};
        NSDictionary *credentials = nil;
        @try {
            if (vauth_x25519_keypair(VARandom, NULL, secret, publicKey) != VAUTH_OK ||
                vauth_hex_decode(vauth_server_keys[index], server, 32) != VAUTH_OK) return nil;
            char publicHex[65], fingerprint[17];
            vauth_hex_encode(publicKey, 32, publicHex); vauth_key_fingerprint(server, fingerprint);
            NSString *publicString = [NSString stringWithUTF8String:publicHex];
            NSString *fp = [NSString stringWithUTF8String:fingerprint];
            NSMutableDictionary *form = VAAttestation(challenge, publicString, headers);
            if (!form) return nil;
            [form setObject:publicString forKey:@"client_public"]; [form setObject:fp forKey:@"server_key"];
            NSString *device = VAHeader(headers, @"X-Veteris-Device");
            if (device) [form setObject:device forKey:@"device"];
            NSDictionary *response = VASend(@"register", form, headers, nil, *offset);
            id keyID = [response objectForKey:@"key_id"], transport = [response objectForKey:@"install_key"];
            if ([keyID isKindOfClass:[NSString class]] && vauth_valid_key_id([keyID UTF8String]) &&
                [transport isKindOfClass:[NSString class]] && [[response objectForKey:@"server_key"] isEqual:fp] &&
                [[response objectForKey:@"key_version"] isKindOfClass:[NSNumber class]] &&
                vauth_hex_decode([transport UTF8String], wrapped, 60) == VAUTH_OK &&
                vauth_unwrap_install_key(secret, server, [keyID UTF8String], wrapped, key) == VAUTH_OK &&
                VATime([response objectForKey:@"server_time"], offset)) {
                credentials = [NSDictionary dictionaryWithObjectsAndKeys:keyID, @"key_id",
                    [NSData dataWithBytes:key length:32], @"install_key", fp, @"server_key",
                    [response objectForKey:@"key_version"], @"key_version",
                    [NSNumber numberWithDouble:*offset], @"offset", nil];
            }
        } @finally { vauth_wipe(secret, 32); vauth_wipe(key, 32); vauth_wipe(wrapped, 60); }
        if (credentials) return credentials;
    }
    return nil;
}

static void VAWorkerRun(void) {
    @autoreleasepool {
        @try {
            if (vauth_macho_text_hash(_dyld_get_image_header(0), _dyld_get_image_vmaddr_slide(0), VAHash) != VAUTH_OK) return;
            NSDictionary *saved = VALoad();
            [VALock lock]; VACredentials = saved; VAOffset = [[saved objectForKey:@"offset"] doubleValue]; [VALock unlock];
            double nextAttempt = 0, lastRegisterDirective = -3600, lastSave = 0;
            for (;;) {
                @autoreleasepool {
                    [NSThread sleepForTimeInterval:1];
                    [VALock lock];
                    NSDictionary *headers = VAHeaders, *credentials = VACredentials;
                    double offset = VAOffset;
                    BOOL replace = VANeedRegister && VAClock() - lastRegisterDirective >= 3600;
                    BOOL renew = VANeedSession || !VASession || VAExpires <= [[NSDate date] timeIntervalSince1970] + offset + 60;
                    [VALock unlock];
                    if (!headers) continue;
                    if (replace) {
                        lastRegisterDirective = VAClock();
                        SecItemDelete((__bridge CFDictionaryRef)VAKeychainQuery());
                        [VALock lock]; VACredentials = nil; VASession = nil; VANeedRegister = NO; [VALock unlock];
                        credentials = nil; renew = YES;
                        nextAttempt = 0;
                    }
                    if (VAClock() < nextAttempt) continue;
                    if (!renew && credentials) {
                        if (VAClock() - lastSave > 60) { VASave(credentials, offset); lastSave = VAClock(); }
                        continue;
                    }
                    nextAttempt = VAClock() + 60;
                    @try {
                        if (!credentials) {
                            credentials = VARegister(headers, &offset);
                            if (!credentials) continue;
                            VASave(credentials, offset);
                            [VALock lock]; VACredentials = credentials; VAOffset = offset; [VALock unlock];
                        }
                        NSDictionary *challenge = VASend(@"challenge", nil, headers, nil, 0);
                        if (!VATime([challenge objectForKey:@"server_time"], &offset)) continue;
                        NSMutableDictionary *form = VAAttestation(challenge, [credentials objectForKey:@"key_id"], headers);
                        if (!form) continue;
                        NSDictionary *response = VASend(@"session", form, headers, credentials, offset);
                        id session = [response objectForKey:@"session"], expires = [response objectForKey:@"expires"];
                        if (![session isKindOfClass:[NSString class]] || ![session length] || !vauth_valid_session([session UTF8String]) ||
                            ![expires isKindOfClass:[NSNumber class]] || !VATime([response objectForKey:@"server_time"], &offset) ||
                            !isfinite([expires doubleValue]) || [expires doubleValue] <= [[NSDate date] timeIntervalSince1970] + offset) continue;
                        [VALock lock]; VASession = session; VAExpires = [expires doubleValue]; VAOffset = offset;
                        VANeedSession = NO; [VALock unlock];
                        VASave(credentials, offset); lastSave = VAClock();
                        NSLog(@"Veteris Auth: session ready.");
                    } @catch (NSException *exception) { NSLog(@"Veteris Auth: background operation failed, retrying later."); }
                }
            }
        } @catch (NSException *exception) { NSLog(@"Veteris Auth: initialization failed, requests remain unsigned."); }
    }
}
static void *VAWorkerThread(void *unused) {
    (void)unused;
    VAWorkerRun();
    return NULL;
}

static void VAPrepareRequest(BBHTTPRequest *request) {
    BOOL target = NO;
    @try {
        target = VATarget(request);
        if (!objc_getAssociatedObject(request, &VAOwnRequest) && target) {
            VAClearAuth(request);
            if ([VALock lockBeforeDate:[NSDate dateWithTimeIntervalSinceNow:0.05]]) {
                NSDictionary *credentials = nil; NSString *session = nil; double offset = 0;
                @try {
                    NSMutableDictionary *headers = [NSMutableDictionary dictionary];
                    for (NSString *key in [request headers]) {
                        if ([[key lowercaseString] hasPrefix:@"x-veteris-"] || [key caseInsensitiveCompare:@"Accept"] == NSOrderedSame)
                            [headers setObject:[[request headers] objectForKey:key] forKey:key];
                    }
                    if (VAHeader(headers, @"X-Veteris-Version") && VAHeader(headers, @"X-Veteris-Device")) VAHeaders = headers;
                    credentials = VACredentials; session = VASession; offset = VAOffset;
                    if (VAExpires <= [[NSDate date] timeIntervalSince1970] + offset || VANeedRegister) session = nil;
                } @finally { [VALock unlock]; }
                if (session) VASign(request, credentials, session, offset);
            }
        }
    } @catch (NSException *exception) { @try { if (target) VAClearAuth(request); } @catch (NSException *ignored) {} }
}

static void VAObserveResponse(BBHTTPRequest *request, NSDictionary *headers) {
    @try {
        // cached answers carry an old server time
        NSString *cacheStatus = VAHeader(headers, @"CF-Cache-Status");
        BOOL cached = VAHeader(headers, @"Age") != nil ||
            (cacheStatus && [cacheStatus caseInsensitiveCompare:@"HIT"] == NSOrderedSame);
        if (!cached && VATarget(request) && [VALock tryLock]) {
            @try {
                NSString *time = VAHeader(headers, VAString(VAS_SERVER_TIME));
                NSScanner *scanner = [NSScanner scannerWithString:time ?: @""];
                double serverTime;
                if ([scanner scanDouble:&serverTime] && [scanner isAtEnd] && isfinite(serverTime) && serverTime > 0 && serverTime < 1e12)
                    VAOffset = serverTime - [[NSDate date] timeIntervalSince1970];
                NSString *state = VAHeader(headers, VAString(VAS_AUTH_STATE));
                NSString *keyID = VAHeader([request headers], VAString(VAS_KEY_ID));
                if (keyID && [keyID isEqual:[VACredentials objectForKey:@"key_id"]]) {
                    if ([state isEqualToString:@"session"]) VANeedSession = YES;
                    if ([state isEqualToString:@"reregister"]) { VANeedRegister = YES; VASession = nil; }
                }
            } @finally { [VALock unlock]; }
        }
    } @catch (NSException *exception) {}
}

#ifndef VAUTH_HOST_TEST
%group VeterisAuthentication
%hook BBHTTPExecutor
- (BOOL)executeRequest:(BBHTTPRequest *)request {
    VAPrepareRequest(request);
    return %orig(request);
}
%end
%hook BBHTTPRequest
- (void)initialResponseReceived:(NSUInteger)status headers:(NSDictionary *)headers {
    VAObserveResponse(self, headers);
    %orig(status, headers);
}
%end
%end

%ctor {
    @autoreleasepool {
        @try {
            const char *image = _dyld_get_image_name(0);
            NSString *path = image ? [NSString stringWithUTF8String:image] : nil;
            if (![path hasSuffix:@"/Veteris.app/Veteris"]) return;
            NSDictionary *info = [NSDictionary dictionaryWithContentsOfFile:[[path stringByDeletingLastPathComponent] stringByAppendingPathComponent:@"Info.plist"]];
            if (![[info objectForKey:@"CFBundleIdentifier"] isEqualToString:@"com.victorlobe.veteris"]) return;
            Class request = NSClassFromString(@"BBHTTPRequest"), executor = NSClassFromString(@"BBHTTPExecutor");
            if (!request || !executor || ![request instancesRespondToSelector:@selector(initialResponseReceived:headers:)] ||
                ![executor instancesRespondToSelector:@selector(executeRequest:)]) return;
            VALock = [NSLock new];
            %init(VeterisAuthentication);
            pthread_t thread;
            pthread_attr_t attributes;
            pthread_attr_init(&attributes);
            pthread_attr_setdetachstate(&attributes, PTHREAD_CREATE_DETACHED);
            if (pthread_create(&thread, &attributes, VAWorkerThread, NULL) != 0)
                NSLog(@"Veteris Auth: initialization failed, requests remain unsigned.");
            pthread_attr_destroy(&attributes);
        } @catch (NSException *exception) {}
    }
}

#endif
