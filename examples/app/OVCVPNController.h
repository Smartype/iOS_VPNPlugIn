//
//  OVCVPNController.h
//  OpenVPNClient
//
//  Created by Eric on 6/29/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#include "iOSVPNPlugIn.h"
#import <Foundation/Foundation.h>

@interface OVCVPNController : NSObject {
    __strong NSMutableArray *_vpnConfigurations;
    __unsafe_unretained NSTimer* _ackTimer;
    __unsafe_unretained id _delegate;
    BOOL _pendingConnect;
    BOOL _pendingDisconnect;    
    BOOL _isPluginAttached;
    UInt32 _ackRetries; 
    __strong NSMutableArray* _vendorFiles;
    __strong NSMutableArray* _openVPNLogLines;
}

@property (nonatomic, strong) NSMutableArray *vpnConfigurations;

+ (OVCVPNController*) sharedController;

- (BOOL) isPluginEnabled;
- (BOOL) enablePlugin;
- (void) copyConfigurations;
- (BOOL) hasEnabledConfig;
- (BOOL) hasVPNConfig;
- (BOOL) processZippedConfigFile:(NSString*)file;
- (BOOL) startVPNConnection:(VPNConfigurationRef)conf;
- (BOOL) startEnabledConfig;
- (void) setConfig:(VPNConfigurationRef) conf enabled:(BOOL)enable;
- (void) statusChangedTo:(int) status forConfiguration:(VPNConfigurationRef) conf;
- (VPNConfigurationRef) activeConfig;
- (VPNConfigurationRef) enabledConfig;
- (SCNetworkConnectionStatus) activeConfigStatus;
- (BOOL) stopConfig:(VPNConfigurationRef) c;
- (void) setDelegate:(id) delegate;
- (BOOL) isPluginAttached;
- (void) startAckTimer;
- (void) stopAckTimer;
- (void) attachToPlugin;
- (void) processMessage:(uint32_t)message withData:(CFDataRef)data;
- (void) processMessage:(uint32_t)message withDictionary:(NSDictionary*)dict;
- (void) sendMessage:(int32_t)type withDictionary:(NSDictionary*)dict;
- (void) sendMessage:(int32_t)type withDictionary:(NSDictionary*)dict toConfig:(VPNConfigurationRef)conf;
- (void) sendSynMessage;
- (void) doPendingConnect;
@end
