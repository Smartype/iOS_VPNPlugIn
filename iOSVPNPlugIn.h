//
//  VPNPlugIn.h
//  OpenVPN
//
//  Created by Eric on 5/28/12.
//  Copyright (c) 2012 smartype@gmail.com. All rights reserved.
//

#ifndef OpenVPN_VPNPlugIn_h
#define OpenVPN_VPNPlugIn_h

#include <CoreFoundation/CoreFoundation.h>

/* BEGIN vpnplugin API */
enum {
    kVPNTunnelEventTypeWillSleep = 1,
    kVPNTunnelEventTypeWillWakeup = 2,
    kVPNTunnelEventTypeAttach = 3,
    kVPNTunnelEventTypeDetach = 4,
    kVPNTunnelEventTypeTransportUnavailable = 5,
    kVPNTunnelEventTypeTransportAvailable = 6,    
};
typedef int32_t VPNTunnelEventType;
typedef CFTypeRef SCVPNTunnelSessionRef;

/* export API */
Boolean Plugin_VPNTunnelInit(SCVPNTunnelSessionRef session, CFDictionaryRef settings, void** context);
void Plugin_VPNTunnelDispose(SCVPNTunnelSessionRef session, void* context);
void Plugin_VPNTunnelAuthenticateComplete(SCVPNTunnelSessionRef session, void* context);
void Plugin_VPNTunnelDisplayBannerComplete(SCVPNTunnelSessionRef session, void* context);
void Plugin_VPNTunnelConnect(SCVPNTunnelSessionRef session, void* context, CFDictionaryRef settings);
void Plugin_VPNTunnelEnvironmentEvent(SCVPNTunnelSessionRef session, void* context, VPNTunnelEventType event);    
void Plugin_VPNTunnelDisconnect(SCVPNTunnelSessionRef session, void* context, CFDictionaryRef result);
void Plugin_VPNTunnelIPCReceivedMessage(SCVPNTunnelSessionRef session, void* context, unsigned int app, unsigned int type, CFDataRef data);

/* import API */
void VPNTunnelClearConfiguration(SCVPNTunnelSessionRef session);
CFDictionaryRef VPNTunnelCopyPersistentData(SCVPNTunnelSessionRef tunnelRef, unsigned int type);
CFDictionaryRef VPNTunnelCopySocketInfo(SCVPNTunnelSessionRef session, int sock);
void VPNTunnelEnvironmentEventComplete(SCVPNTunnelSessionRef session, VPNTunnelEventType type);
void VPNTunnelIPCSendMessage(SCVPNTunnelSessionRef session, unsigned int app, unsigned int msg, CFDataRef data);
void VPNTunnelLog(SCVPNTunnelSessionRef session, int level, CFStringRef fmt, ...);
/*
 kSCEntNetDNS
 VPN {"RemoteAddress"}
 kSCEntNetProxie {kSCPropNetProxiesProxyAutoConfigEnable / kSCPropNetProxiesProxyAutoConfigJavaScript},
 kSCEntNetIPv4 {kSCPropNetIPv4Addresses, kSCPropNetIPv4SubnetMasks, kSCPropNetIPv4DestAddresses, VPN, MTU}
 kSCEntNetIPv4 { ExcludedRoutes, kSCPropNetIPv4Addresses, IncludedRoutes, 
 */
void VPNTunnelSetConfigurationEntities(SCVPNTunnelSessionRef session, CFDictionaryRef currConfig);
void VPNTunnelSetPersistentData(SCVPNTunnelSessionRef session, unsigned int type, CFDictionaryRef data);

enum  {
    kVPNTunnelStatusDisconnected = 0,
    kVPNTunnelStatusContacting = 1,
    kVPNTunnelStatusAuthenticating = 2,  
    kVPNTunnelStatusNegotiating = 3,
    kVPNTunnelStatusConnected = 4,
    kVPNTunnelStatusReasserting = 5,
    kVPNTunnelStatusDisconnecting = 6,    
};
typedef int32_t VPNTunnelStatus;

void VPNTunnelSetStatus(SCVPNTunnelSessionRef session, VPNTunnelStatus status, CFErrorRef err);
void VPNTunnelUpdatePlugin(SCVPNTunnelSessionRef session, CFURLRef ipaUrl);
void VPNTunnelAuthenticate(SCVPNTunnelSessionRef session, CFDictionaryRef dict);
void VPNTunnelIncrementDataReceived(SCVPNTunnelSessionRef session, long long packets, long long bytes);
void VPNTunnelIncrementDataSent(SCVPNTunnelSessionRef session, long long packets, long long bytes);
 
/*
"Message" -> "A new profile has been downloaded. Please open the AnyConnect App to synchronize."
"AgreementRequired" -> kCFBooleanFalse
 */
void VPNTunnelDisplayBanner(SCVPNTunnelSessionRef session, CFDictionaryRef dict);

/* END vpnplugin API */

/* BEGIN application API */
typedef void* VPNConfigurationRef;

/* import from /System/Library/Frameworks/SystemConfiguration.framework/SystemConfiguration */
extern const CFStringRef kSCPropNetVPNAuthName;
extern const CFStringRef kSCPropNetVPNAuthPassword;
extern const CFStringRef kSCPropNetVPNAuthenticationMethod;
extern const CFStringRef kSCPropNetVPNLocalCertificate;
extern const CFStringRef kSCPropNetVPNRemoteAddress;
extern const CFStringRef kSCValNetVPNAuthenticationMethodCertificate;
extern const CFStringRef kSCValNetVPNAuthenticationMethodPassword;
extern const CFStringRef kVPNConfigurationKeyCertificateRef;
extern const CFStringRef kVPNConfigurationKeyPersistentRef;
extern const CFStringRef kSCPropNetVPNReassertionTimer;

/*
UNDEF:001509A8                 IMPORT _kSCPropNetVPNAuthenticationMethod
UNDEF:001509AC                 IMPORT _kSCPropNetVPNLocalCertificate
UNDEF:001509B0                 IMPORT _kSCPropNetVPNOnDemandEnabled
UNDEF:001509B4                 IMPORT _kSCPropNetVPNOnDemandMatchDomainsAlways
UNDEF:001509B8                 IMPORT _kSCPropNetVPNOnDemandMatchDomainsNever
UNDEF:001509BC                 IMPORT _kSCPropNetVPNOnDemandMatchDomainsOnRetry
UNDEF:001509C0                 IMPORT _kSCPropNetVPNRemoteAddress
UNDEF:001509C4                 IMPORT _kSCValNetVPNAuthenticationMethodCertificate
UNDEF:001509C8                 IMPORT _kSCValNetVPNAuthenticationMethodPassword
UNDEF:001509CC                 IMPORT _kVPNConfigurationKeyCertificateRef
UNDEF:001509D0                 IMPORT _kVPNConfigurationKeyPersistentRef
*/

CFDictionaryRef VPNConfigurationCopyPersistentData(VPNConfigurationRef conf, int type);
Boolean VPNConfigurationSetPersistentData(VPNConfigurationRef conf, int type, CFDictionaryRef data);

Boolean VPNConfigurationConnectionStart(VPNConfigurationRef conf, CFDictionaryRef settings);
Boolean VPNConfigurationConnectionStop(VPNConfigurationRef conf);
CFDictionaryRef VPNConfigurationCopy(VPNConfigurationRef conf); 
CFArrayRef VPNConfigurationCopyAll(CFStringRef vpnType);
void* VPNConfigurationCopyCertificate(void* identity);
CFArrayRef VPNConfigurationCopyIdentities();
CFDictionaryRef VPNConfigurationCopyVendorData(VPNConfigurationRef conf);
VPNConfigurationRef VPNConfigurationCreate(CFStringRef vpnType);
Boolean VPNConfigurationEnableVPNType(CFStringRef vpnType);
Boolean VPNConfigurationGetEnabled(VPNConfigurationRef conf);
CFStringRef VPNConfigurationGetName(VPNConfigurationRef conf);

enum {
    kSCNetworkConnectionInvalid =  -1,
    kSCNetworkConnectionDisconnected =  0,
    kSCNetworkConnectionConnecting =  1,
    kSCNetworkConnectionConnected =  2,
    kSCNetworkConnectionDisconnecting =  3
};
typedef int32_t SCNetworkConnectionStatus;
 
SCNetworkConnectionStatus VPNConfigurationGetStatus(VPNConfigurationRef conf);
Boolean VPNConfigurationIsVPNTypeEnabled(CFStringRef vpnType);
Boolean VPNConfigurationRemove(VPNConfigurationRef conf);
Boolean VPNConfigurationScheduleWithRunLoop(VPNConfigurationRef conf, CFRunLoopRef runloop, CFStringRef runloopMode);
Boolean VPNConfigurationSendMessage(VPNConfigurationRef conf, int msgtype, CFDataRef data);
Boolean VPNConfigurationSet(VPNConfigurationRef conf, CFDictionaryRef settings);
typedef void (*VPNConfigurationCallback)(VPNConfigurationRef conf, unsigned int notification, void* info);
struct VPNConfigurationContext {
    CFIndex	version;
    void *	info;
    const void *(*retain)(const void *info);
    void	(*release)(const void *info);
    CFStringRef	(*copyDescription)(const void *info);
};
typedef struct VPNConfigurationContext VPNConfigurationContext;
Boolean VPNConfigurationSetCallback(VPNConfigurationRef conf, VPNConfigurationCallback callback, 
                                    VPNConfigurationContext* ctx);
Boolean VPNConfigurationSetEnabled(VPNConfigurationRef conf, Boolean enable);
typedef void (*VPNConfigurationMessageCallback)(VPNConfigurationRef conf, unsigned int message, CFDataRef data, void* info);
Boolean VPNConfigurationSetMessageCallback(VPNConfigurationRef conf, VPNConfigurationMessageCallback callback, VPNConfigurationContext* ctx);
Boolean VPNConfigurationSetName(VPNConfigurationRef conf, CFStringRef name);
Boolean VPNConfigurationSetVendorData(VPNConfigurationRef conf, CFDictionaryRef dict);
Boolean VPNConfigurationUnscheduleFromRunLoop(VPNConfigurationRef conf, CFRunLoopRef runloop, CFStringRef runloopMode);
CFErrorRef VPNCopyLastError();

/* END application API */
#endif
