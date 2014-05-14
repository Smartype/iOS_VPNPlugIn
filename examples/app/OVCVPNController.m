//
//  OVCVPNController.m
//  OpenVPNClient
//
//  Created by Eric on 6/29/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#import "OVCVPNController.h"
#include "iOSVPNPlugIn.h"
#import "ZipArchive.h"
#import "OVCAppDelegate.h"
#include "VPNPluginMsgTypes.h"
#import "NSData+Base64.h"

extern void CFLog(int, CFStringRef, ...);
#define dbg(fmt, ...)           CFLog(1, CFSTR("<%s> "fmt), __FUNCTION__, ##__VA_ARGS__) 

#define OPENVPN_PLUGIN_TYPE     CFSTR("com.if0rce.openvpn")

static void confCallback(VPNConfigurationRef conf, unsigned int notification, void* info) {
    
    switch (notification) {
        case 0: {
            
            // Got a VPN connection status changed event from the framework
            // TODO: set status from config
            // VPNConfigurationGetStatus();
            /*
             
             6 -> 7
             2 -> 3
             3 -> 4
             4 -> 5
             5 -> 6
             0 -> 0
             1 -> 0
             
             default -> 1
             
             */
            
            /*
             Status:
             0 -> Disconnected
             1 -> Disconnected
             2 -> Contacting
             3 -> Authenticating
             4 -> Connecting
             5 -> Connected
             6 -> Disconnecting             
             7 -> Reasserting
             8 -> Updating Plugin
             default -> ?
             
             */
                int status = VPNConfigurationGetStatus(conf);
            /*
                dbg("Got a VPN connection status changed event from the framework: notification: %p, status: %d info: %p (%@)", 
                notification, status, info, info);
             */
            [[OVCVPNController sharedController] statusChangedTo:status forConfiguration:conf];

        }
            break;
            
        case 1: // Got a VPN configuration changed event from the framework
            // TODO: reload all configurations

            dbg("Got a VPN configuration changed event from the framework: notification: %p, info: %p (%@)", 
                notification, info, info);
            break;
            
        default:
            dbg("conf: %@, notification: %p, info: %p (%@)", 
                conf, notification, info, info);
            break;
    }
}

static void msgCallback(VPNConfigurationRef conf, unsigned int message, CFDataRef data, void* info) {
    //dbg("conf: %@, message: %d, data %@", conf, message, data);
    [[OVCVPNController sharedController] processMessage:message withData:data];
}

@implementation OVCVPNController

@synthesize vpnConfigurations = _vpnConfigurations;

+ (OVCVPNController*) sharedController {

    static OVCVPNController* inst = nil;
    if (inst == nil)
        inst = [[OVCVPNController alloc] init];
    return inst;
}

- (OVCVPNController*) init {
    if ((self = [super init]) != nil) {
        _ackTimer = nil;
        _ackRetries = 0;
        _isPluginAttached = NO;
        _pendingConnect = NO;
        _pendingDisconnect = NO;    
        _vendorFiles = [[NSMutableArray alloc] init];
        _vpnConfigurations = [[NSMutableArray alloc] init];
        _openVPNLogLines = [[NSMutableArray alloc] init];
        [self copyConfigurations];
    }
    return self;
}

- (void) doPendingConnect {
    VPNConfigurationRef conf = [self enabledConfig];
    Boolean enabled = true;
    //_vendorFiles = [NSMutableArray array];
    CFDictionaryRef vendorData = VPNConfigurationCopyVendorData(conf);
    if (vendorData) {
        NSDictionary* nsDict = (__bridge NSDictionary*)vendorData; 
        for (NSString* key in [nsDict allKeys]) {
            if ([key hasPrefix:@"BASE64_FILE_"]) {
                NSString* value = [nsDict objectForKey:key];
                NSData* data = [NSData dataFromBase64String:value];
                NSMutableDictionary* mDict = [NSMutableDictionary dictionary];
                [mDict setObject:data forKey:[key substringFromIndex:12]];
                [_vendorFiles addObject:mDict];
            }
            else {
                NSMutableDictionary* mDict = [NSMutableDictionary dictionary];
                NSString* value = [nsDict objectForKey:key];                
                [mDict setObject:value forKey:key];
                dbg("option %@", mDict);
                [self sendMessage:AppleVPN_MessageType_Option withDictionary:mDict];
            }
        }
    }
    
    if ([_vendorFiles count] > 0) {
        NSDictionary* dict = [_vendorFiles objectAtIndex:0];
        [self sendMessage:AppleVPN_MessageType_CreateFile withDictionary:dict];
        [_vendorFiles removeObjectAtIndex:0];
        return;
    }
    
    enabled = VPNConfigurationConnectionStart(conf, nil);
    if (!enabled) {
        dbg("VPNConfigurationConnectionStart() failed: %@", VPNCopyLastError());
        return;
    } 
    
    if (vendorData)
        CFRelease(vendorData);
}


- (void) processCreateFileDone {
    if (_vendorFiles) {
        if ([_vendorFiles count] > 0) {
            NSDictionary* dict = [_vendorFiles objectAtIndex:0];
            [self sendMessage:AppleVPN_MessageType_CreateFile withDictionary:dict];
            [_vendorFiles removeObjectAtIndex:0];
        }
        else {
            VPNConfigurationRef conf = [self enabledConfig];
            Boolean enabled = VPNConfigurationConnectionStart(conf, nil);
            if (!enabled) {
                dbg("VPNConfigurationConnectionStart() failed: %@", VPNCopyLastError());
                return;
            }   
        }
    }
}

- (void) processAckMessage {
    if (!_isPluginAttached) {
        dbg();
        [self stopAckTimer];
        _isPluginAttached = YES; 
        
        if (_pendingConnect) {
            _pendingConnect = NO;
            [self doPendingConnect];
        }
    }
}

- (void) processOpenVPNLog:(NSDictionary*)dict {
    NSString* Message = [dict objectForKey:@"Message"];
    if (Message) {
        dbg("OpenVPN: %@", Message);
        [_openVPNLogLines addObject:dict];
    }
}

- (void) processMessage:(uint32_t)message withDictionary:(NSDictionary*)dict {
    switch (message) {
        case AppleVPN_MessageType_Ack:
            [self processAckMessage];
            break;
            
        case AppleVPN_MessageType_CreateFileDone:
            [self processCreateFileDone];
            break;
            
        case AppleVPN_MessageType_OpenVPN_Log:
            [self processOpenVPNLog:dict];
            break;
            
        default:
            dbg("message: %d, data %@", message, dict);
            break;
    }
}

- (void) processMessage:(uint32_t)message withData:(CFDataRef) data {
    CFPropertyListFormat format;
    CFErrorRef error;
    
    CFDictionaryRef dict = CFPropertyListCreateWithData(kCFAllocatorDefault, data, 0, &format, &error);
    if (dict == nil) {
        dbg("CFPropertyListCreateWithData(): %@", error);
        CFRelease(error);
        return;
    }
    
    [self processMessage:message withDictionary:(__bridge NSDictionary*)dict];
    CFRelease(dict);
}

- (void) sendMessage:(int32_t)type withDictionary:(NSDictionary*)dict {
    VPNConfigurationRef conf = [self enabledConfig];
    if (conf == nil) {
        dbg("No enabled config found");
        return;
    }
    
    [self sendMessage:type withDictionary:dict toConfig:conf];
}

- (void) sendMessage:(int32_t)type withDictionary:(NSDictionary*)dict toConfig:(VPNConfigurationRef)conf {
    
    CFErrorRef error;
    CFDataRef data = CFPropertyListCreateData(kCFAllocatorDefault, (__bridge CFPropertyListRef)dict, kCFPropertyListBinaryFormat_v1_0, 0, &error);
    if (data == nil) {
        dbg("CFPropertyListCreateData(): %@", error);
        CFRelease(error);
        return;
    }
    
    dbg("VPNConfigurationSendMessage(%d, %@)", type, data);
    
    Boolean enabled = VPNConfigurationSendMessage(conf, type, data);
    if (!enabled)
        dbg("VPNConfigurationSendMessage() failed: %@", VPNCopyLastError());
    
    CFRelease(data);
}

- (void) sendSynMessage {
    [self sendMessage:AppleVPN_MessageType_Syn withDictionary:[NSDictionary dictionary]];
}

- (BOOL) isPluginAttached {
    return _isPluginAttached;
}

- (void) ackTimerFires:(NSTimer*) timer {
    
    if (++ _ackRetries > 10) {
        [self stopAckTimer];
        dbg("Failed to attach vpn plugin");
        return;
    }
    
    [self sendSynMessage];
    
}

- (void) startAckTimer {
    _ackRetries = 0;
    _ackTimer = [NSTimer scheduledTimerWithTimeInterval:1.0
                                        target:self
                                      selector:@selector(ackTimerFires:)
                                      userInfo:nil 
                                       repeats:YES];
    
}

- (void) stopAckTimer {
    if (_ackTimer) {
        [_ackTimer invalidate];
        _ackTimer = nil;
    }
}

- (void) attchToPlugin {
    if (_isPluginAttached)
        return;
    
    [self sendSynMessage];
    [self startAckTimer];
}

- (void) statusChangedTo:(int) status forConfiguration:(VPNConfigurationRef) conf {
    switch (status) {
        case 0:
            dbg("Disconnected");
            break;

        case 1:
            dbg("Connecting");
            break;

        case 2:
            dbg("Connected");
            break;

        case 3:
            dbg("Disconnecting");
            break;
            
        case -1:            
        default:
            dbg("Invalid");
            break;
    }
    
    if (_delegate) 
        [_delegate statusChangedTo:status forConfiguration:conf];
}

- (BOOL) isPluginEnabled {
    return (VPNConfigurationIsVPNTypeEnabled(OPENVPN_PLUGIN_TYPE) == TRUE);
}

- (BOOL) enablePlugin {
    if ([self isPluginEnabled])
        return YES;
    
    BOOL enabled = VPNConfigurationEnableVPNType(OPENVPN_PLUGIN_TYPE);
    if (!enabled) {        
        dbg("VPNConfigurationEnableVPNType() failed: %@", VPNCopyLastError());
    }
    
    return enabled;
}

- (BOOL) hasEnabledConfig {
    if (![self hasVPNConfig])
        return NO;
    
    NSUInteger i;
    for (i = 0; i < [_vpnConfigurations count]; i++) {
        VPNConfigurationRef c = (__bridge VPNConfigurationRef)[_vpnConfigurations objectAtIndex:i];
        if (VPNConfigurationGetEnabled(c))
            return YES;
    }
    
    return NO;
}

- (BOOL) hasVPNConfig {
    return ([_vpnConfigurations count] > 0);
}

- (void) copyConfigurations {
    if (![self isPluginEnabled])
        return;
    
    CFArrayRef confs = VPNConfigurationCopyAll(OPENVPN_PLUGIN_TYPE);
    //dbg("VPNConfigurationCopyAll(): %@", confs);
    if (confs != nil && CFArrayGetCount(confs) > 0) {
        /*
        if (_vpnConfigurations) 
            [_vpnConfigurations release];
        */
        
        _vpnConfigurations = (__bridge_transfer NSMutableArray*)CFArrayCreateMutableCopy(kCFAllocatorDefault, 0, confs);
        NSUInteger i;
        for (i = 0; i < [_vpnConfigurations count]; i++) {
            VPNConfigurationRef c = (__bridge VPNConfigurationRef)[_vpnConfigurations objectAtIndex:i];
            
            if (c) {
                
                const char* s = "<unknown>";
                int status = VPNConfigurationGetStatus(c);
                switch (status) {
                    case -1:
                        s = "Invalid";
                        break;
                    case 0:
                        s = "Disconnected";
                        break;
                    case 1:
                        s = "Connecting";
                        break;
                    case 2:
                        s = "Connected";
                        break;
                    case 3:
                        s = "Disconnecting";
                        break;                        
                        
                    default:
                        break;
                }
                
                //dbg("[%d] %@: %s (%d) %@", i, VPNConfigurationGetName(c), s, status, c);
            }
        }
    }
}

- (BOOL) startVPNConnection:(VPNConfigurationRef)conf {
    
    CFDictionaryRef vpnConf = VPNConfigurationCopy(conf);
    if (vpnConf) {
        if (CFDictionaryGetCount(vpnConf) > 0) {

            CFMutableDictionaryRef emptyDict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, NULL, NULL);     
            if (!VPNConfigurationSet(conf, emptyDict)) {
                dbg("VPNConfigurationSet() failed: %@", VPNCopyLastError());
            }
            CFRelease(emptyDict);
            
        }
    }
    
    VPNConfigurationSetMessageCallback(conf, msgCallback, NULL);
    VPNConfigurationSetCallback(conf, confCallback, NULL);
    VPNConfigurationScheduleWithRunLoop(conf, CFRunLoopGetMain(), kCFRunLoopDefaultMode);
    
    if (![self isPluginAttached]) {
        [self attchToPlugin];
        _pendingConnect = YES;
        return YES;
    }
    
    Boolean enabled = true;
    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, NULL, NULL);         
    CFDictionaryRef vendorData = VPNConfigurationCopyVendorData(conf);
    if (vendorData) 
        CFDictionarySetValue(dict, CFSTR("VendorData"), vendorData);

    enabled = VPNConfigurationConnectionStart(conf, dict);
    if (!enabled) {
        CFRelease(dict);
        dbg("VPNConfigurationConnectionStart() failed: %@", VPNCopyLastError());
        return NO;
    } 
    
    if (vendorData)
        CFRelease(vendorData);
    
    CFRelease(dict);
    return YES;
}

- (BOOL) stopConfig:(VPNConfigurationRef) conf {
    VPNConfigurationSetMessageCallback(conf, msgCallback, NULL);
    VPNConfigurationSetCallback(conf, confCallback, NULL);
    VPNConfigurationScheduleWithRunLoop(conf, CFRunLoopGetMain(), kCFRunLoopDefaultMode);
    
    Boolean enabled = true;
    enabled = VPNConfigurationConnectionStop(conf);
    if (!enabled) {
        dbg("VPNConfigurationConnectionStop() failed: %@", VPNCopyLastError());
        return NO;
    } 

    return YES;
}

- (BOOL) startEnabledConfig {
    NSUInteger i;
    for (i = 0; i < [_vpnConfigurations count]; i++) {
        VPNConfigurationRef c = (__bridge VPNConfigurationRef)[_vpnConfigurations objectAtIndex:i];
        if (VPNConfigurationGetEnabled(c)) {
            return [self startVPNConnection:c];
        }
    }
    
    return NO;
}

- (BOOL) processZippedConfigFile:(NSString*)file {
    
    OVCAppDelegate* delegate = [UIApplication sharedApplication].delegate;
    NSURL* docDir = [delegate applicationDocumentsDirectory];
    NSString* docPath = [docDir path];
    NSString* tempDir = [docPath stringByAppendingPathComponent:@"Extracted"];
    
    __autoreleasing NSError* err;
    [[NSFileManager defaultManager] removeItemAtPath:tempDir error:&err];
    
    __autoreleasing NSError* err1;
    [[NSFileManager defaultManager] createDirectoryAtPath:tempDir withIntermediateDirectories:NO attributes:nil error:&err1];
    
    ZipArchive* ar = [[ZipArchive alloc] init];
    [ar UnzipOpenFile:file];
    [ar UnzipFileTo:tempDir overWrite:YES];
    
    NSArray* subFiles = [[NSFileManager defaultManager] subpathsAtPath:tempDir];
    NSLog(@"Extracted: %@", subFiles);
    
    VPNConfigurationRef conf = VPNConfigurationCreate(OPENVPN_PLUGIN_TYPE);
    if (conf == NULL) {
        dbg("VPNConfigurationCreate() failed: %@", VPNCopyLastError());
        return NO;
    }
    
    NSString* confName = [[file lastPathComponent] stringByDeletingPathExtension];
    Boolean enabled = VPNConfigurationSetName(conf, (__bridge CFStringRef) confName);
    if (!enabled) {
        dbg("VPNConfigurationSetName() failed: %@", VPNCopyLastError());
        return NO;
    }
    
    NSMutableDictionary* settings = [NSMutableDictionary dictionary];   
    NSMutableDictionary* files = [NSMutableDictionary dictionary]; 
    [settings setObject:files forKey:@"files"];
    
    for (NSString* fileItem in subFiles) {
        NSString* fullPath = [tempDir stringByAppendingPathComponent:fileItem];
        NSData* fileData = [NSData dataWithContentsOfFile:fullPath];
        [files setObject:fileData forKey:fileItem];
    }

    
    enabled = VPNConfigurationSet(conf, (__bridge CFMutableDictionaryRef)settings);
    if (!enabled) {
        dbg("VPNConfigurationSet() failed: %@", VPNCopyLastError());
        return NO;
    }
    
    NSMutableDictionary* vendorSettings = [NSMutableDictionary dictionary];     
    enabled = VPNConfigurationSetVendorData(conf, (__bridge CFMutableDictionaryRef)vendorSettings);
    if (!enabled) {
        dbg("VPNConfigurationSetVendorData() failed: %@", VPNCopyLastError());
        return NO;
    }
    
    enabled = VPNConfigurationSetEnabled(conf, TRUE);
    if (!enabled) {
        dbg("VPNConfigurationSetEnabled() failed: %@", VPNCopyLastError());
        return NO;
    }
    
    [ar UnzipCloseFile];
    
    return YES;
}

- (void) setConfig:(VPNConfigurationRef) conf enabled:(BOOL)enable {
    NSUInteger i;
    for (i = 0; i < [_vpnConfigurations count]; i++) {
        VPNConfigurationRef c = (__bridge VPNConfigurationRef)[_vpnConfigurations objectAtIndex:i];
        if (c == conf)
            VPNConfigurationSetEnabled(c, enable);
        else
            VPNConfigurationSetEnabled(c, !enable);
    }
}

- (VPNConfigurationRef) enabledConfig {
    NSUInteger i;
    for (i = 0; i < [_vpnConfigurations count]; i++) {
        VPNConfigurationRef c = (__bridge VPNConfigurationRef)[_vpnConfigurations objectAtIndex:i];
        if (VPNConfigurationGetEnabled(c))
            return c;
    }   
    return nil;

}

- (VPNConfigurationRef) activeConfig {
    NSUInteger i;
    for (i = 0; i < [_vpnConfigurations count]; i++) {
        VPNConfigurationRef c = (__bridge VPNConfigurationRef)[_vpnConfigurations objectAtIndex:i];
        SCNetworkConnectionStatus status = VPNConfigurationGetStatus(c);
        if (status == kSCNetworkConnectionConnecting 
            || status == kSCNetworkConnectionConnected
            || status == kSCNetworkConnectionDisconnecting) {
            return c;
            
        }
    }   
    return nil;
}

- (SCNetworkConnectionStatus) activeConfigStatus {
    NSUInteger i;
    for (i = 0; i < [_vpnConfigurations count]; i++) {
        VPNConfigurationRef c = (__bridge VPNConfigurationRef)[_vpnConfigurations objectAtIndex:i];
        SCNetworkConnectionStatus status = VPNConfigurationGetStatus(c);
        if (status == kSCNetworkConnectionConnecting 
            || status == kSCNetworkConnectionConnected
            || status == kSCNetworkConnectionDisconnecting) {
            return status;
            
        }
    }   
    return kSCNetworkConnectionInvalid;   
}

- (void) setDelegate:(id) delegate {
    _delegate = delegate;
}

@end
