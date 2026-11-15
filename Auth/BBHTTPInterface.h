#import <Foundation/Foundation.h>
@interface BBHTTPResponse : NSObject
@property(nonatomic, readonly) NSUInteger code;
@property(nonatomic, readonly) id content;
@end
@interface BBHTTPRequest : NSObject
- (id)initWithTarget:(NSString *)url andVerb:(NSString *)verb;
@property(nonatomic, readonly) NSURL *url;
@property(nonatomic, readonly) NSString *verb;
@property(nonatomic, readonly) NSDictionary *headers;
@property(nonatomic, readonly) NSData *uploadData;
@property(nonatomic, readonly) BBHTTPResponse *response;
@property(nonatomic, readonly) NSError *error;
@property(nonatomic) NSUInteger maxRedirects;
@property(nonatomic) NSUInteger connectionTimeout;
@property(nonatomic, copy) void (^finishBlock)(id request);
- (BOOL)setValue:(NSString *)value forHeader:(NSString *)header;
- (BOOL)setHeaders:(NSDictionary *)headers;
- (BOOL)setUploadData:(NSData *)data withContentType:(NSString *)type;
- (void)downloadContentAsData;
- (BOOL)cancel;
- (void)initialResponseReceived:(NSUInteger)status headers:(NSDictionary *)headers;
@end
@interface BBHTTPExecutor : NSObject
+ (id)sharedExecutor;
- (BOOL)executeRequest:(BBHTTPRequest *)request;
@end
