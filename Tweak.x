#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AppSupport/CPDistributedMessagingCenter.h>
#import <objc/runtime.h>

static NSString *const kMessagingCenterName = @"com.victorlobe.veterishelper";
static NSString *const kMessageMarkNewlyInstalled = @"com.victorlobe.veteris.MarkNewlyInstalled";
static NSString *const kMessageLaunchApp = @"com.victorlobe.veteris.LaunchApp";
static NSString *const kBundleIdentifierKey = @"bundleIdentifier";

@interface SBApplication : NSObject
- (void)markNewlyInstalled;
@end

@interface SBApplicationController : NSObject
+ (instancetype)sharedInstance;
- (SBApplication *)applicationWithDisplayIdentifier:(NSString *)identifier;
- (SBApplication *)applicationWithBundleIdentifier:(NSString *)identifier;
@end

@interface SBUIController : NSObject
+ (instancetype)sharedInstance;
- (void)activateApplicationFromSwitcher:(SBApplication *)application;
- (void)activateApplicationAnimated:(SBApplication *)application;
@end

@interface YZMessagingCenter : NSObject {
    CPDistributedMessagingCenter *_messagingCenter;
    dispatch_queue_t _queue;
}
+ (instancetype)sharedInstance;
@end

@implementation YZMessagingCenter

+ (instancetype)sharedInstance {
    static YZMessagingCenter *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[self alloc] init];
    });
    return instance;
}

+ (void)load {
    (void)[self sharedInstance];
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _queue = dispatch_queue_create("com.victorlobe.veteris.MessagingCenter", DISPATCH_QUEUE_SERIAL);
        [self setupMessagingCenter];
    }
    return self;
}

- (void)setupMessagingCenter {
    _messagingCenter = [CPDistributedMessagingCenter centerNamed:kMessagingCenterName];
    [_messagingCenter runServerOnCurrentThread];
    [_messagingCenter registerForMessageName:kMessageMarkNewlyInstalled
                                      target:self
                                    selector:@selector(markNewlyInstalled:withUserInfo:)];
    [_messagingCenter registerForMessageName:kMessageLaunchApp
                                      target:self
                                    selector:@selector(launchApp:withUserInfo:)];
}

static id VHSharedController(NSString *className) {
    Class controllerClass = objc_getClass([className UTF8String]);
    if (!controllerClass) {
        return nil;
    }
    return [controllerClass sharedInstance];
}

- (SBApplication *)applicationForBundleIdentifier:(NSString *)bundleIdentifier {
    SBApplicationController *controller = (SBApplicationController *)VHSharedController(@"SBApplicationController");
    if (!controller) {
        NSLog(@"Veteris Helper: Failed to get SBApplicationController instance");
        return nil;
    }

    NSString *systemVersion = [[UIDevice currentDevice] systemVersion];
    if ([systemVersion compare:@"8.0" options:NSNumericSearch] == NSOrderedAscending) {
        return [controller applicationWithDisplayIdentifier:bundleIdentifier];
    }
    return [controller applicationWithBundleIdentifier:bundleIdentifier];
}

- (void)markNewlyInstalled:(NSString *)messageName withUserInfo:(NSDictionary *)userInfo {
    NSString *bundleIdentifier = userInfo[kBundleIdentifierKey];
    NSLog(@"Veteris Helper: Marking newly installed app: %@", bundleIdentifier);
    if (bundleIdentifier.length == 0) {
        return;
    }

    SBApplication *application = [self applicationForBundleIdentifier:bundleIdentifier];
    if (!application) {
        NSLog(@"Veteris Helper: Application not found: %@", bundleIdentifier);
        return;
    }

    [application markNewlyInstalled];
}

- (void)launchApp:(NSString *)messageName withUserInfo:(NSDictionary *)userInfo {
    NSString *bundleIdentifier = userInfo[kBundleIdentifierKey];
    NSLog(@"Launching app: %@", bundleIdentifier);
    if (bundleIdentifier.length == 0) {
        return;
    }

    SBApplicationController *appController = (SBApplicationController *)VHSharedController(@"SBApplicationController");
    SBUIController *uiController = (SBUIController *)VHSharedController(@"SBUIController");
    if (!appController || !uiController) {
        NSLog(@"Veteris Helper: Failed to get SBApplicationController or SBUIController instance");
        return;
    }

    SBApplication *application = [self applicationForBundleIdentifier:bundleIdentifier];
    if (!application) {
        NSLog(@"Veteris Helper: Application not found: %@", bundleIdentifier);
        return;
    }

    NSString *systemVersion = [[UIDevice currentDevice] systemVersion];
    if ([systemVersion compare:@"7.0" options:NSNumericSearch] == NSOrderedAscending) {
        [uiController activateApplicationFromSwitcher:application];
    } else {
        [uiController activateApplicationAnimated:application];
    }
}

@end

%ctor {
    (void)[YZMessagingCenter sharedInstance];
}
