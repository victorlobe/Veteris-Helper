#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <AppSupport/CPDistributedMessagingCenter.h>
#import <objc/runtime.h>
#import <dlfcn.h>
#import <errno.h>
#import <signal.h>

static NSString *const kMessagingCenterName = @"com.victorlobe.veterishelper";
static NSString *const kMessageMarkNewlyInstalled = @"com.victorlobe.veteris.MarkNewlyInstalled";
static NSString *const kMessageLaunchApp = @"com.victorlobe.veteris.LaunchApp";
static NSString *const kMessageBackgroundWorkBegin = @"com.victorlobe.veteris.BackgroundWorkBegin";
static NSString *const kMessageBackgroundWorkEnd = @"com.victorlobe.veteris.BackgroundWorkEnd";
static NSString *const kBundleIdentifierKey = @"bundleIdentifier";
static NSString *const kProcessIdentifierKey = @"pid";
static NSString *const kKeepAliveKey = @"keepAlive";
static NSString *const kVeterisBundleIdentifier = @"com.victorlobe.veteris";
static NSString *const kVeterisExecutableSuffix = @"/Veteris.app/Veteris";

static const unsigned int kAssertionFlagPreventSuspend = 1 << 0;
static const unsigned int kAssertionFlagPreventThrottleDownCPU = 1 << 1;
static const unsigned int kAssertionReasonFinishTaskUnbounded = 10004;
static const uint32_t kIOPMAssertionLevelOn = 255;

static const NSUInteger kMaxRelaunches = 3;
static const NSTimeInterval kRelaunchBudgetResetInterval = 600.0;
static const NSTimeInterval kRelaunchWindow = 60.0;
static const NSTimeInterval kFallbackLaunchDelay = 10.0;
static const NSTimeInterval kExitPollInterval = 15.0;

@interface SBApplication : NSObject
- (void)markNewlyInstalled;
- (NSString *)bundleIdentifier;
- (NSString *)displayIdentifier;
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

@interface BKSProcessAssertion : NSObject
- (instancetype)initWithPID:(int)pid flags:(unsigned int)flags reason:(unsigned int)reason name:(NSString *)name withHandler:(void (^)(BOOL acquired))handler;
- (void)invalidate;
@end

typedef int (*VHIOPMAssertionCreateWithNameFunction)(CFStringRef type, uint32_t level, CFStringRef name, uint32_t *assertionID);
typedef int (*VHIOPMAssertionReleaseFunction)(uint32_t assertionID);
typedef int (*VHLaunchApplicationFunction)(CFStringRef identifier, Boolean suspended);
typedef int (*VHProcPIDPathFunction)(int pid, void *buffer, uint32_t bufferSize);

static void *VHLookupSymbol(const char *name, const char *imagePath) {
    void *symbol = dlsym(RTLD_DEFAULT, name);
    if (symbol == NULL && imagePath != NULL) {
        void *image = dlopen(imagePath, RTLD_LAZY);
        if (image != NULL) {
            symbol = dlsym(image, name);
        }
    }
    return symbol;
}

static BOOL VHSystemVersionLessThan(NSString *version) {
    return [[[UIDevice currentDevice] systemVersion] compare:version options:NSNumericSearch] == NSOrderedAscending;
}

static BOOL VHProcessExited(pid_t pid) {
    return kill(pid, 0) != 0 && errno == ESRCH;
}

static BOOL VHIsVeterisProcess(pid_t pid) {
    if (pid <= 0) {
        return NO;
    }
    VHProcPIDPathFunction procPIDPath = (VHProcPIDPathFunction)VHLookupSymbol("proc_pidpath", NULL);
    char path[4096];
    int length = procPIDPath != NULL ? procPIDPath(pid, path, sizeof(path)) : 0;
    if (length <= 0) {
        return !VHProcessExited(pid);
    }
    NSString *executable = [[NSString alloc] initWithBytes:path length:(NSUInteger)length encoding:NSUTF8StringEncoding];
    return [executable hasSuffix:kVeterisExecutableSuffix];
}

static NSString *VHApplicationBundleIdentifier(SBApplication *application) {
    if ([application respondsToSelector:@selector(bundleIdentifier)]) {
        return [application bundleIdentifier];
    }
    if ([application respondsToSelector:@selector(displayIdentifier)]) {
        return [application displayIdentifier];
    }
    return nil;
}

static BKSProcessAssertion *VHCreateProcessAssertion(pid_t pid) {
    Class assertionClass = objc_getClass("BKSProcessAssertion");
    if (assertionClass == Nil || ![assertionClass instancesRespondToSelector:@selector(initWithPID:flags:reason:name:withHandler:)]) {
        return nil;
    }
    return [[assertionClass alloc] initWithPID:pid
                                         flags:(kAssertionFlagPreventSuspend | kAssertionFlagPreventThrottleDownCPU)
                                        reason:kAssertionReasonFinishTaskUnbounded
                                          name:@"com.victorlobe.veteris.downloads"
                                   withHandler:^(BOOL acquired) {
        NSLog(@"Veteris Helper: Process assertion for pid %d %@", pid, acquired ? @"acquired" : @"was not acquired");
    }];
}

@interface VHBackgroundWork : NSObject {
    pid_t _pid;
    BOOL _armed;
    BOOL _relaunchGranted;
    NSUInteger _relaunchCount;
    CFAbsoluteTime _registeredAt;
    CFAbsoluteTime _relaunchDeadline;
    BKSProcessAssertion *_processAssertion;
    uint32_t _powerAssertionID;
    BOOL _holdsPowerAssertion;
    BOOL _canLaunchSuspended;
    NSTimer *_exitPollTimer;
}
+ (instancetype)sharedInstance;
- (NSDictionary *)beginForProcessIdentifier:(pid_t)pid;
- (void)endForProcessIdentifier:(pid_t)pid;
- (BOOL)grantRelaunchAfterExitOfApplication:(NSString *)bundleIdentifier;
@end

@implementation VHBackgroundWork

+ (instancetype)sharedInstance {
    static VHBackgroundWork *instance = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        instance = [[self alloc] init];
    });
    return instance;
}

- (instancetype)init {
    self = [super init];
    if (self) {
        _canLaunchSuspended = !VHSystemVersionLessThan(@"7.0");
    }
    return self;
}

- (NSDictionary *)beginForProcessIdentifier:(pid_t)pid {
    if (!VHIsVeterisProcess(pid)) {
        NSLog(@"Veteris Helper: Ignoring background work request for pid %d", pid);
        return [NSDictionary dictionaryWithObject:[NSNumber numberWithBool:NO] forKey:kKeepAliveKey];
    }
    BOOL keepAlive = NO;
    @synchronized (self) {
        if (pid != _pid) {
            [self releaseProcessResourcesLocked];
            _pid = pid;
            _registeredAt = CFAbsoluteTimeGetCurrent();
        }
        _armed = YES;
        _relaunchDeadline = 0;
        [self acquirePowerAssertionLocked];
        if (_processAssertion == nil) {
            _processAssertion = VHCreateProcessAssertion(pid);
        }
        keepAlive = (_processAssertion != nil);
    }
    [self startExitPolling];
    NSLog(@"Veteris Helper: Background work started for pid %d (process assertion: %@)", pid, keepAlive ? @"yes" : @"no");
    return [NSDictionary dictionaryWithObject:[NSNumber numberWithBool:keepAlive] forKey:kKeepAliveKey];
}

- (void)endForProcessIdentifier:(pid_t)pid {
    @synchronized (self) {
        if (pid <= 0 || pid != _pid) {
            return;
        }
        _pid = 0;
        _armed = NO;
        _relaunchCount = 0;
        _relaunchDeadline = 0;
        [self releaseProcessResourcesLocked];
    }
    [self stopExitPolling];
    NSLog(@"Veteris Helper: Background work finished for pid %d", pid);
}

- (BOOL)grantRelaunchAfterExitOfApplication:(NSString *)bundleIdentifier {
    if (![bundleIdentifier isEqualToString:kVeterisBundleIdentifier]) {
        return NO;
    }
    BOOL registeredProcessExited = NO;
    BOOL granted = NO;
    @synchronized (self) {
        if (_pid > 0) {
            registeredProcessExited = YES;
            [self noteExitLocked];
        }
        granted = [self consumeRelaunchLocked];
        if (granted) {
            _relaunchGranted = YES;
        }
    }
    if (registeredProcessExited) {
        [self performSelectorOnMainThread:@selector(registeredProcessExitHandled) withObject:nil waitUntilDone:NO];
    }
    if (granted) {
        NSLog(@"Veteris Helper: Letting SpringBoard relaunch Veteris in the background");
    }
    return granted;
}

#pragma mark - Exit handling

- (void)startExitPolling {
    if (_exitPollTimer == nil) {
        _exitPollTimer = [NSTimer scheduledTimerWithTimeInterval:kExitPollInterval target:self selector:@selector(pollForExit:) userInfo:nil repeats:YES];
    }
}

- (void)stopExitPolling {
    [_exitPollTimer invalidate];
    _exitPollTimer = nil;
}

- (void)pollForExit:(NSTimer *)timer {
    BOOL exited = NO;
    @synchronized (self) {
        if (_pid > 0 && VHProcessExited(_pid)) {
            exited = YES;
            [self noteExitLocked];
        }
    }
    if (exited) {
        [self registeredProcessExitHandled];
    }
}

- (void)registeredProcessExitHandled {
    BOOL scheduleFallback = NO;
    @synchronized (self) {
        scheduleFallback = _armed && _pid == 0 && _canLaunchSuspended;
    }
    [self stopExitPolling];
    if (scheduleFallback) {
        [NSObject cancelPreviousPerformRequestsWithTarget:self selector:@selector(launchIfRelaunchPending) object:nil];
        [self performSelector:@selector(launchIfRelaunchPending) withObject:nil afterDelay:kFallbackLaunchDelay];
    }
}

- (void)launchIfRelaunchPending {
    @synchronized (self) {
        if (!_armed || _pid > 0 || CFAbsoluteTimeGetCurrent() > _relaunchDeadline) {
            return;
        }
        if (!_relaunchGranted && ![self consumeRelaunchLocked]) {
            return;
        }
    }
    [self performSelectorInBackground:@selector(launchVeterisSuspended) withObject:nil];
}

- (void)launchVeterisSuspended {
    @autoreleasepool {
        VHLaunchApplicationFunction launchApplication = (VHLaunchApplicationFunction)VHLookupSymbol("SBSLaunchApplicationWithIdentifier", "/System/Library/PrivateFrameworks/SpringBoardServices.framework/SpringBoardServices");
        if (launchApplication == NULL) {
            NSLog(@"Veteris Helper: SBSLaunchApplicationWithIdentifier is not available");
            return;
        }
        int result = launchApplication((__bridge CFStringRef)kVeterisBundleIdentifier, true);
        NSLog(@"Veteris Helper: Launched Veteris in the background to finish downloads (result %d)", result);
    }
}

#pragma mark - Locked helpers

- (void)noteExitLocked {
    pid_t pid = _pid;
    _pid = 0;
    _relaunchGranted = NO;
    [self releaseProcessResourcesLocked];
    if (!_armed) {
        return;
    }
    CFAbsoluteTime now = CFAbsoluteTimeGetCurrent();
    if (now - _registeredAt >= kRelaunchBudgetResetInterval) {
        _relaunchCount = 0;
    }
    _relaunchDeadline = now + kRelaunchWindow;
    NSLog(@"Veteris Helper: Veteris (pid %d) exited with downloads left", pid);
}

- (BOOL)consumeRelaunchLocked {
    if (!_armed) {
        return NO;
    }
    if (_pid == 0 && CFAbsoluteTimeGetCurrent() > _relaunchDeadline) {
        _armed = NO;
        return NO;
    }
    if (_relaunchCount >= kMaxRelaunches) {
        NSLog(@"Veteris Helper: Not relaunching Veteris again after %lu relaunches", (unsigned long)_relaunchCount);
        _armed = NO;
        return NO;
    }
    _relaunchCount++;
    return YES;
}

- (void)acquirePowerAssertionLocked {
    if (_holdsPowerAssertion) {
        return;
    }
    VHIOPMAssertionCreateWithNameFunction createAssertion = (VHIOPMAssertionCreateWithNameFunction)VHLookupSymbol("IOPMAssertionCreateWithName", "/System/Library/Frameworks/IOKit.framework/IOKit");
    if (createAssertion == NULL) {
        NSLog(@"Veteris Helper: IOPMAssertionCreateWithName is not available");
        return;
    }
    uint32_t assertionID = 0;
    if (createAssertion(CFSTR("PreventUserIdleSystemSleep"), kIOPMAssertionLevelOn, CFSTR("Veteris downloads"), &assertionID) == 0 ||
        createAssertion(CFSTR("NoIdleSleepAssertion"), kIOPMAssertionLevelOn, CFSTR("Veteris downloads"), &assertionID) == 0) {
        _powerAssertionID = assertionID;
        _holdsPowerAssertion = YES;
    } else {
        NSLog(@"Veteris Helper: Could not create the idle sleep assertion");
    }
}

- (void)releaseProcessResourcesLocked {
    [_processAssertion invalidate];
    _processAssertion = nil;
    if (_holdsPowerAssertion) {
        VHIOPMAssertionReleaseFunction releaseAssertion = (VHIOPMAssertionReleaseFunction)VHLookupSymbol("IOPMAssertionRelease", "/System/Library/Frameworks/IOKit.framework/IOKit");
        if (releaseAssertion != NULL) {
            releaseAssertion(_powerAssertionID);
        }
        _holdsPowerAssertion = NO;
        _powerAssertionID = 0;
    }
}

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
    [_messagingCenter registerForMessageName:kMessageBackgroundWorkBegin
                                      target:self
                                    selector:@selector(beginBackgroundWork:withUserInfo:)];
    [_messagingCenter registerForMessageName:kMessageBackgroundWorkEnd
                                      target:self
                                    selector:@selector(endBackgroundWork:withUserInfo:)];
}

static id VHSharedController(NSString *className) {
    Class controllerClass = objc_getClass([className UTF8String]);
    if (!controllerClass) {
        return nil;
    }
    return [controllerClass sharedInstance];
}

static pid_t VHProcessIdentifierFromUserInfo(NSDictionary *userInfo) {
    id value = [userInfo objectForKey:kProcessIdentifierKey];
    return [value respondsToSelector:@selector(intValue)] ? (pid_t)[value intValue] : 0;
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

- (NSDictionary *)beginBackgroundWork:(NSString *)messageName withUserInfo:(NSDictionary *)userInfo {
    return [[VHBackgroundWork sharedInstance] beginForProcessIdentifier:VHProcessIdentifierFromUserInfo(userInfo)];
}

- (void)endBackgroundWork:(NSString *)messageName withUserInfo:(NSDictionary *)userInfo {
    [[VHBackgroundWork sharedInstance] endForProcessIdentifier:VHProcessIdentifierFromUserInfo(userInfo)];
}

@end

%hook SBApplication

- (BOOL)_shouldAutoLaunchOnBootOrInstall:(BOOL)bootOrInstall {
    BOOL shouldLaunch = %orig;
    if (shouldLaunch || bootOrInstall) {
        return shouldLaunch;
    }
    return [[VHBackgroundWork sharedInstance] grantRelaunchAfterExitOfApplication:VHApplicationBundleIdentifier(self)];
}

%end

%group LegacyLocalNotifications

%hook SBApplication

- (BOOL)isInternalApplication {
    return %orig || [VHApplicationBundleIdentifier(self) isEqualToString:kVeterisBundleIdentifier];
}

%end

%end

%ctor {
    %init;
    if (kCFCoreFoundationVersionNumber < 847.20) {
        %init(LegacyLocalNotifications);
    }
    (void)[YZMessagingCenter sharedInstance];
}
