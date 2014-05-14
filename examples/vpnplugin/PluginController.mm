//
//  PluginController.cpp
//  OpenVPN
//
//  Created by Eric on 5/31/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//
#include <sys/socket.h>
#include <netinet/in.h>
#include "PluginController.h"
#include "Logger.h"
#include "VPNPluginMsgTypes.h"
#include "LogHelper.h"

extern "C" const CFStringRef kSCEntNetIPv4;
extern "C" const CFStringRef kSCEntNetDNS;
extern "C" const CFStringRef kSCEntNetProxies;
const CFStringRef kSCEntNetVPN = CFSTR("VPN");

extern "C" const CFStringRef kSCPropNetIPv4Addresses;
extern "C" const CFStringRef kSCPropNetIPv4SubnetMasks;
extern "C" const CFStringRef kSCPropNetIPv4DestAddresses;
extern "C" const CFStringRef kSCPropNetOverridePrimary;
const CFStringRef kSCPropNetIPv4ExcludedRoutes = CFSTR("ExcludedRoutes");
const CFStringRef kSCPropNetIPv4IncludedRoutes = CFSTR("IncludedRoutes");

extern "C" const CFStringRef kSCPropNetProxiesFTPPassive;

extern "C" const CFStringRef kSCPropNetDNSSearchDomains;
extern "C" const CFStringRef kSCPropNetDNSSupplementalMatchDomains;
extern "C" const CFStringRef kSCPropNetDNSServerAddresses;

const CFStringRef kSCPropNetIPv4MTU = CFSTR("MTU");

const CFStringRef kSCPropNetVPNRemoteAddress = CFSTR("RemoteAddress");

extern "C" int openvpn_main (int argc, char *argv[]);

extern "C" void* PluginController_createInstance(SCVPNTunnelSessionRef session, CFDictionaryRef settings) {
    PluginController::instance()->initialize(session, settings);
    return PluginController::instance();
}
extern "C" void PluginController_dispose(void* ctrl, SCVPNTunnelSessionRef session) {
    ((PluginController*)ctrl)->dispose();
    
}
extern "C" void PluginController_auth_complete(void* ctrl, SCVPNTunnelSessionRef session) {
    ((PluginController*)ctrl)->authComplete();
}
extern "C" void PluginController_display_banner(void* ctrl, SCVPNTunnelSessionRef session) {
    ((PluginController*)ctrl)->displayBannerComplete();
}
extern "C" void PluginController_connect(void* ctrl, SCVPNTunnelSessionRef session, CFDictionaryRef settings) {
    ((PluginController*)ctrl)->connect(settings);
}
extern "C" void PluginController_event(void* ctrl, SCVPNTunnelSessionRef session, VPNTunnelEventType event) {
    ((PluginController*)ctrl)->event(event);
}
extern "C" void PluginController_disconnect(void* ctrl, SCVPNTunnelSessionRef session, CFDictionaryRef result) {
    ((PluginController*)ctrl)->disconnect(result);
}
extern "C" void PluginController_message(void* ctrl, SCVPNTunnelSessionRef session, unsigned int app, unsigned int type, CFDataRef data) {
    ((PluginController*)ctrl)->message(app, type, data);
}

extern "C" int PluginController_tunfd() {
    return PluginController::instance()->getTunelFd();
}

pthread_mutex_t PluginController::mutex = PTHREAD_MUTEX_INITIALIZER;

const SCVPNTunnelSessionRef PluginController::getTunnelSession() const {
    return tunnelSession_;
}

void PluginController::splitCmdline(const string& s, char c, vector<string>& v, int max) {
    string::size_type i = 0;
    string::size_type j = s.find(c);
    while (j != string::npos) {
        v.push_back(s.substr(i, j-i));
        i = ++j;
        j = s.find(c, j);
        
        if (max > 0) {
            max --;
            if (max - 1 == 0)
                j = string::npos;
        }
        
        if (j == string::npos)
            v.push_back(s.substr(i, s.length( )));
    }
}

PluginController* PluginController::instance() {
    static volatile PluginController* inst = NULL;
    if (inst == NULL) {
        pthread_mutex_lock(&(PluginController::mutex));
        if (inst == NULL) {
            inst = new PluginController();
        }
        pthread_mutex_unlock(&(PluginController::mutex));        
    }
    
    return (PluginController*)inst;
}

void PluginController::OpenVPNCallback(CFSocketRef s, CFSocketCallBackType type, CFDataRef address, const void *data, void *info) {
    switch (type) {
        case kCFSocketReadCallBack: {

            PluginController* inst = (PluginController*)info;
            static char buf[256];
            int ret = read(CFSocketGetNative(s), buf, sizeof(buf) - 1);
            if (ret < 0) {
                //dbg("read(): %s", strerror(errno));
                CFSocketInvalidate(s);
            }
            else if (ret == 0) {
                //dbg("read(): %s", strerror(errno));
                CFSocketInvalidate(s);
            }
            else {
                buf[ret] = '\0';
                inst->appendManagementBuffer(buf, ret);
            }
        }
            break;
            
        default:
            break;
    }    
}

void PluginController::mgmtSocketCallback(CFSocketRef s, CFSocketCallBackType type, CFDataRef address, const void *data, void *info) {
    switch (type) {
        case kCFSocketAcceptCallBack: {
            CFSocketNativeHandle nativeSocketHandle = *(CFSocketNativeHandle *)data;
            PluginController* inst = (PluginController*)info;
            inst->acceptManagementSocket(nativeSocketHandle);
        }
            break;
            
        default:
            break;
    }
    
}

PluginController::PluginController() 
    : mgmtStreamLen_(0),
    appAttached_(FALSE) {
    
}

void PluginController::sendManagementCmdline(const char* cmdline) {
    dbg("%s", cmdline);
    int s = CFSocketGetNative(ctrlSocket_);
    write(s, cmdline, strlen(cmdline));
    write(s, "\n", 1);    
}

void PluginController::processLogCmdline(char* cmdline) {
    //dbg("%s", cmdline);    
    //>LOG:1339418285,,OPTIONS IMPORT: timers and/or timeouts modified
    string s(cmdline + 5);
    vector<string> tokens;
    splitCmdline(s, ',', tokens, 3);
    //dbg("%s", cmdline);

    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, NULL, NULL);
    
    string& timeStr = tokens[0];
    long long timeVal = strtoll(timeStr.c_str(), NULL, 10);
    CFNumberRef timeNum = CFNumberCreate(kCFAllocatorDefault, kCFNumberSInt64Type, &timeVal);
    CFDictionarySetValue(dict, CFSTR("Timestamp"), timeNum);
    
    
    string& levelStr = tokens[1];
    CFStringRef levelVal = CFStringCreateWithCString(kCFAllocatorDefault, levelStr.c_str(), kCFStringEncodingUTF8);
    CFDictionarySetValue(dict, CFSTR("Level"), levelVal);
     
    string& logStr = tokens[2];
    CFStringRef logVal = CFStringCreateWithCString(kCFAllocatorDefault, logStr.c_str(), kCFStringEncodingUTF8);
    CFDictionarySetValue(dict, CFSTR("Message"), logVal);
/*    
    GET_CSTRING(dict, str);
    dbg("dict: %s", str);
    RELEASE_CSTRING(str);
*/    
    sendMessage(AppleVPN_MessageType_OpenVPN_Log, dict);

    CFRelease(logVal);
    CFRelease(levelVal);
    CFRelease(timeNum);
    CFRelease(dict);
}

void PluginController::processStateCmdline(char* cmdline) {
    //dbg("%s", cmdline);
    //">STATE:1339406889,WAIT,,,"  
    string s(cmdline + 7);
    vector<string> tokens;
    splitCmdline(s, ',', tokens, 0);

    string& state = tokens[1];
    dbg("STATE: %s", state.c_str());
    
    if (state == string("GET_CONFIG")) {
        VPNTunnelSetStatus(tunnelSession_, kVPNTunnelStatusNegotiating, NULL);
    }
    else if (state == string("ASSIGN_IP")) {
        VPNTunnelSetStatus(tunnelSession_, kVPNTunnelStatusNegotiating, NULL);
    }
    else if (state == string("ADD_ROUTES")) {
        VPNTunnelSetStatus(tunnelSession_, kVPNTunnelStatusNegotiating, NULL);
    }
    else if (state == string("CONNECTED")) {
        setupTun(0, 0, 0, 0);
        setRemoteAddress(0);
        setDNSAddresses(0, 0);    
        setupRoute(0, 0, 0);
        
        VPNTunnelSetConfigurationEntities(tunnelSession_, currConfig_);

        VPNTunnelSetStatus(tunnelSession_, kVPNTunnelStatusConnected, NULL);
    }
    else if (state == string("AUTH")) {
        VPNTunnelSetStatus(tunnelSession_, kVPNTunnelStatusAuthenticating, NULL);        
    }
    else if (state == string("CONNECTING")) {
        VPNTunnelSetStatus(tunnelSession_, kVPNTunnelStatusContacting, NULL);                
    }
    else if (state == string("EXITING")) {
        VPNTunnelSetStatus(tunnelSession_, kVPNTunnelStatusDisconnecting, NULL);                        
    }
    else if (state == string("RECONNECTING")) {
        VPNTunnelSetStatus(tunnelSession_, kVPNTunnelStatusReasserting, NULL);                                
    }
    else if (state == string("RESOLVE")) {
        VPNTunnelSetStatus(tunnelSession_, kVPNTunnelStatusContacting, NULL);                        
    }
    else if (state == string("TCP_CONNECT")) {
        VPNTunnelSetStatus(tunnelSession_, kVPNTunnelStatusContacting, NULL);                                
    }
    else if (state == string("UDP_CONNECT")) {
        VPNTunnelSetStatus(tunnelSession_, kVPNTunnelStatusContacting, NULL);                                
    }
    else if (state == string("WAIT")) {
        VPNTunnelSetStatus(tunnelSession_, kVPNTunnelStatusContacting, NULL);                                
    }
    else {
        VPNTunnelSetStatus(tunnelSession_, kVPNTunnelStatusContacting, NULL);                                        
    }
}

void PluginController::processHoldCmdline(char* cmdline) {
    dbg("%s", cmdline);
    sendManagementCmdline("hold release");
    sendManagementCmdline("log on");
    sendManagementCmdline("state on");   
}

void PluginController::evalManagementCmdline(char* cmdline) {

    if (strncmp(cmdline, ">LOG:", 5) == 0) {
        processLogCmdline(cmdline);
    }
    else if (strncmp(cmdline, ">HOLD:", 6) == 0) {
        processHoldCmdline(cmdline);
    }
    else if (strncmp(cmdline, ">STATE:", 7) == 0) {
        processStateCmdline(cmdline);
    }
    //SUCCESS
    else {
        dbg("ERROR: %s", cmdline);
    }
}

void PluginController::appendManagementBuffer(char* buf, int len) {
    //dbg("[%s]", buf);

    if (len > mgmtStreamSize) {
        dbg("ignore %s byte mgmt buffer", len);
        return;
    }
    
    if (mgmtStreamLen_ > len > mgmtStreamSize - 1) {
        dbg("flush mgmtstream of %u bytes", mgmtStreamLen_);
        mgmtStreamLen_ = 0;
    }
    
    memcpy(mgmtStream_ + mgmtStreamLen_, buf, len);
    mgmtStreamLen_ += len;
    

    char* pos = mgmtStream_;
    char* start = mgmtStream_; 
    char* end = mgmtStream_ + mgmtStreamLen_;
    
    while (pos < end) {
        if (*pos == '\n') {
            *pos = '\0';
            evalManagementCmdline(start);            
            start = pos + 1;
            
            if (start >= end) {
                mgmtStreamLen_ = 0;
                return;
            }
        }
        
        pos ++;
    }
    
    if (start < end) {
        mgmtStreamLen_ = end - start;
        memcpy(mgmtStream_, start, mgmtStreamLen_);
    }
    
}


int PluginController::getTunelFd() const {
    return tunFd_;
}

void PluginController::initialize(SCVPNTunnelSessionRef session, CFDictionaryRef settings) {
    NSAutoreleasePool* pool = [[NSAutoreleasePool alloc] init];
    
    tunnelSession_ = session;
    
    GET_CSTRING(settings, s2);    
    dbg("settings: %s", s2);
    RELEASE_CSTRING(s2);    
    
    serviceId_ = (CFStringRef)CFDictionaryGetValue(settings, CFSTR("ServiceID"));
    serviceId_ = (CFStringRef)CFRetain(serviceId_);
    
    CFNumberRef sockNum = (CFNumberRef)CFDictionaryGetValue(settings, CFSTR("TunnelSocket"));
    CFNumberGetValue(sockNum, kCFNumberSInt32Type, &tunFd_);
    
    NSBundle* bundle = [NSBundle bundleWithIdentifier:@"com.if0rce.openvpn"];
    NSString* working = [[bundle bundlePath] stringByDeletingLastPathComponent];
    workingDir_ = (__bridge CFStringRef)[working stringByAppendingPathComponent:@"tmp"];
    workingDir_ = (CFStringRef)CFRetain(workingDir_);
    
    initializeConfig();
    
    listenForManagement();
    [pool release];
}

void PluginController::dispose() {
    dbg();
    
}

void PluginController::authComplete() {
    dbg();
    
}

void PluginController::displayBannerComplete() {
    dbg();
}

void PluginController::connect(CFDictionaryRef settings) {
    GET_CSTRING(settings, s1);    
    dbg("settings: %s", s1);
    RELEASE_CSTRING(s1);
    
    startOpenVPN();
}

void PluginController::disconnect(CFDictionaryRef result) {
    GET_CSTRING(result, s1);    
    dbg("result: %s", s1);
    RELEASE_CSTRING(s1);

    stopOpenVPN();
    
}

void PluginController::sendMessage(unsigned int msg, CFDictionaryRef dict) {
    if (!appAttached_)
        return;
    
    CFErrorRef error;
    CFDataRef data = CFPropertyListCreateData(kCFAllocatorDefault,
                                              dict, 
                                              kCFPropertyListBinaryFormat_v1_0,
                                              0, 
                                              &error);
    if (data == nil) {
        dbg("CFPropertyListCreateData(): %@", error);
        CFRelease(error);
        return;
    }

    VPNTunnelIPCSendMessage(tunnelSession_, 1, msg, data);
    CFRelease(data);
}
    
void PluginController::createFile(CFDictionaryRef dict1) {
    
    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, NULL, NULL);
    
    NSDictionary* filesDict = (__bridge NSDictionary*)dict1;
    for (NSString* key in filesDict) {
        CFDictionarySetValue(dict, CFSTR("FileName"), key);
        
        NSData* fileData = [filesDict objectForKey:key];
        NSString* dir = (__bridge NSString*)(this->workingDir_);
        [fileData writeToFile:[dir stringByAppendingPathComponent:key] atomically:YES];
    }
        
    sendMessage(AppleVPN_MessageType_CreateFileDone, dict);
    CFRelease(dict);    
}

void PluginController::sendAckMessage() {
    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, NULL, NULL);
    sendMessage(AppleVPN_MessageType_Ack, dict);
    CFRelease(dict);
}

void PluginController::event(VPNTunnelEventType event) {
    if (event < kVPNTunnelEventTypeWillSleep || event > kVPNTunnelEventTypeTransportAvailable) 
        dbg("%d", event);
    else {
        const char* events[] = {
            "",
            "kVPNTunnelEventTypeWillSleep",
            "kVPNTunnelEventTypeWillWakeup",
            "kVPNTunnelEventTypeAttach",
            "kVPNTunnelEventTypeDetach",
            "kVPNTunnelEventTypeTransportUnavailable",
            "kVPNTunnelEventTypeTransportAvailable",
        };
        dbg("%s", events[event]);
        
        switch (event) {
            case kVPNTunnelEventTypeWillSleep:
                VPNTunnelEnvironmentEventComplete(tunnelSession_, kVPNTunnelEventTypeWillSleep);
                break;
            
            case kVPNTunnelEventTypeAttach:
                appAttached_ = TRUE;
                //sendAckMessage();
                break;
                
            case kVPNTunnelEventTypeDetach:
                appAttached_ = FALSE;
                break;
                
            default:
                break;
        }
    }
}

void PluginController::message(unsigned int app, unsigned int type, CFDataRef data) {
    GET_CSTRING(data, s1);    
    dbg("app %d type %d data %s", app, type, s1);
    RELEASE_CSTRING(s1);
    CFPropertyListFormat format;
    CFErrorRef error;
    CFDictionaryRef dict = (CFDictionaryRef)CFPropertyListCreateWithData(kCFAllocatorDefault, data, 0, &format, &error);
    if (dict == NULL) {
        dbg("CFPropertyListCreateWithData() failed");
        CFRelease(error);
    }
    
    switch (type) {
        case AppleVPN_MessageType_Syn:
            sendAckMessage();
            break;
            
        case AppleVPN_MessageType_CreateFile:
            createFile(dict);
            break;
            
        default:
            break;
    }
    
    if (dict)
        CFRelease(dict);
}

CFStringRef PluginController::getWorkingDirectory() const {
    return workingDir_;
}

void* PluginController::OpenVPNThread(void *param) {
    
    PluginController* ctrl = (PluginController*)param;
    
    const char* argv[] = {
        "OpenVPN",
        "--cd", 
        "[WORKING-DIRECTORY]",
        "--log",
        "openvpn.log",
        "--management",
        "127.0.0.1",
        "[PORT]",
        "--management-client",
        "--management-query-passwords",
        "--management-log-cache",
        "200",
        "--management-hold",
        "--config",
        "openvpn.conf",
        "--script-security",
        "0",
    };
    
    CFStringRef dir = ctrl->getWorkingDirectory();
    static char cDir[512];
    CFStringGetCString(dir, cDir, sizeof(cDir), kCFStringEncodingASCII);
    argv[2] = cDir;
    
    static char Port[32];
    sprintf(Port, "%u", ctrl->getManagementPort());
    argv[7] = Port;
   
    openvpn_main(sizeof(argv)/sizeof(const char*), (char**)argv);
    return NULL;
}

void PluginController::acceptManagementSocket(int s) {
    dbg();
    CFSocketContext ctx = { 0, this, NULL, NULL, NULL };
    ctrlSocket_ = CFSocketCreateWithNative(kCFAllocatorDefault,
                                           s,
                                           kCFSocketReadCallBack, 
                                           PluginController::OpenVPNCallback,
                                           &ctx);
    
    CFSocketSetSocketFlags(ctrlSocket_, kCFSocketAutomaticallyReenableReadCallBack);
    
    CFRunLoopSourceRef rls = CFSocketCreateRunLoopSource(kCFAllocatorDefault, ctrlSocket_, 0);
    CFRunLoopAddSource(CFRunLoopGetCurrent(), rls, kCFRunLoopDefaultMode);
    CFRelease(rls);
}

unsigned int PluginController::getManagementPort() {
    
    int s = CFSocketGetNative(mgmtListenSocket_);
    struct sockaddr_in sk;
    socklen_t sl = sizeof(sk);
    getsockname(s, (struct sockaddr*)&sk, &sl);
    return  ntohs(sk.sin_port);
}

bool PluginController::listenForManagement() {
 
    CFSocketContext ctx = { 0, this, NULL, NULL, NULL };
    mgmtListenSocket_ = CFSocketCreate(kCFAllocatorDefault, 
                                       AF_INET, 
                                       SOCK_STREAM, 
                                       IPPROTO_TCP,
                                       kCFSocketAcceptCallBack, 
                                       PluginController::mgmtSocketCallback, 
                                       &ctx);
    
    sockaddr_in inaddr;
    bzero(&inaddr, sizeof(inaddr));
    inaddr.sin_family = AF_INET;
    inaddr.sin_port = 0;
    inaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    CFDataRef addr = CFDataCreate(kCFAllocatorDefault, (const UInt8 *)&inaddr, sizeof(inaddr));
    CFSocketSetAddress(mgmtListenSocket_, addr);
    CFRelease(addr);
    CFSocketSetSocketFlags(mgmtListenSocket_, kCFSocketAutomaticallyReenableAcceptCallBack);
    CFRunLoopSourceRef rls = CFSocketCreateRunLoopSource(kCFAllocatorDefault, mgmtListenSocket_, 0);
    CFRunLoopAddSource(CFRunLoopGetCurrent(), rls, kCFRunLoopDefaultMode);
    CFRelease(rls);
    
    return true;
}

void PluginController::startOpenVPN() {

    pthread_attr_t attr;
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
    
    VPNTunnelSetStatus(tunnelSession_, kVPNTunnelStatusContacting, NULL);
    pthread_create(&ovthread_, &attr, PluginController::OpenVPNThread, this);
}

void PluginController::stopOpenVPN() {

    sendManagementCmdline("exit");
    if (ovthread_ > 0) {
        void *ret;
        pthread_join(ovthread_, &ret);
        ovthread_ = NULL;        
    }
}

void PluginController::initializeConfig() {
    
    currConfig_ = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
 
    //kSCEntNetDNS
    CFMutableDictionaryRef dns = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFMutableArrayRef servers = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    CFArrayAppendValue(servers, CFSTR("8.8.8.8"));
    CFArrayAppendValue(servers, CFSTR("8.8.4.4"));
    CFDictionarySetValue(dns, kSCPropNetDNSServerAddresses, servers);
    CFRelease(servers);
    
    CFDictionarySetValue(currConfig_, kSCEntNetDNS, dns);
    CFRelease(dns);

    //kSCEntNetProxies
    CFMutableDictionaryRef proxies = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(proxies, kSCPropNetProxiesFTPPassive, kCFBooleanTrue);
    CFDictionarySetValue(currConfig_, kSCEntNetProxies, proxies);
    CFRelease(proxies);
    
    // kSCEntNetIPv4
    CFMutableDictionaryRef ipv4 = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(currConfig_, kSCEntNetIPv4, ipv4);
    CFRelease(ipv4);
    
    // kSCEntNetVPN
    CFMutableDictionaryRef vpn = CFDictionaryCreateMutable(kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(currConfig_, kSCEntNetVPN, vpn);
    CFRelease(vpn);    
}

void PluginController::setupTun(uint32_t address, uint32_t netmask, uint32_t gateway, uint32_t mtu) {
    
    CFMutableDictionaryRef ipv4 = (CFMutableDictionaryRef)CFDictionaryGetValue(currConfig_, (const void *)kSCEntNetIPv4);
    /*
     <dictionary> {
     Addresses : <array> {
     0 : 172.16.1.17
     }
     DestAddresses : <array> {
     0 : 172.16.1.1
     }
     InterfaceName : ppp0
     NetworkSignature : VPN.RemoteAddress=f.vaone.info
     OverridePrimary : 1
     Router : 172.16.1.1
     ServerAddress : 108.171.248.170
     }
     */
    
    /*
     > get State:/Network/Service/2580362A-75B1-4602-AA18-D9995D7CFD3E/IPv4
     > d.show
     <dictionary> {
     Addresses : <array> {
     0 : 10.8.0.6
     }
     DestAddresses : <array> {
     0 : 10.8.0.5
     }
     InterfaceName : utun0
     MTU : 1500
     Router : 10.8.0.6
     ServerAddress : 10.8.0.5
     SubnetMasks : <array> {
     0 : 255.255.255.255
     }
     }
     */

    //kSCPropNetIPv4Addresses    
    CFMutableArrayRef addresses = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    CFArrayAppendValue(addresses, CFSTR("10.8.0.6"));
    CFDictionarySetValue(ipv4, kSCPropNetIPv4Addresses, addresses);
    CFRelease(addresses);

    /*
    //kSCPropNetIPv4SubnetMasks
    CFMutableArrayRef masks = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    CFArrayAppendValue(masks, CFSTR("255.255.255.255"));
    CFDictionarySetValue(ipv4, kSCPropNetIPv4SubnetMasks, masks);
    CFRelease(masks);    
    */
    
    //kSCPropNetIPv4DestAddresses
    CFMutableArrayRef destAddresses = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);    
    CFArrayAppendValue(destAddresses, CFSTR("10.8.0.5"));
    CFDictionarySetValue(ipv4, kSCPropNetIPv4DestAddresses, destAddresses);
    CFRelease(destAddresses);    

    //CFDictionarySetValue(ipv4, CFSTR("Router"), CFSTR("10.8.0.5"));
    //CFDictionarySetValue(ipv4, CFSTR("ServerAddress"), CFSTR("184.82.244.25"));    

    //kSCPropNetIPv4MTU
    int mtuVal = 1500;
    CFNumberRef mtuNum  = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &mtuVal);
    CFDictionarySetValue(ipv4, kSCPropNetIPv4MTU, mtuNum);
    CFRelease(mtuNum);
    
    
    
}

void PluginController::setRemoteAddress(uint32_t addr) {
    CFMutableDictionaryRef vpn = (CFMutableDictionaryRef)CFDictionaryGetValue(currConfig_, (const void *)kSCEntNetVPN);    
    
    //kSCPropNetVPNRemoteAddress
    CFDictionarySetValue(vpn, kSCPropNetVPNRemoteAddress, CFSTR("184.82.244.25"));
    
}

void PluginController::setDNSAddresses(uint32_t primary, uint32_t secondary) {
    CFMutableDictionaryRef dns = (CFMutableDictionaryRef)CFDictionaryGetValue(currConfig_, (const void *)kSCEntNetDNS);        
    
    //kSCPropNetDNSSearchDomains;
    
    //kSCPropNetDNSSupplementalMatchDomains;
    
    //kSCPropNetDNSServerAddresses;
    CFMutableArrayRef addresses = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
    CFArrayAppendValue(addresses, CFSTR("8.8.8.8"));
    CFArrayAppendValue(addresses, CFSTR("8.8.4.4"));    
    CFDictionarySetValue(dns, kSCPropNetDNSServerAddresses, addresses);
    CFRelease(addresses);

}

void PluginController::setupRoute(uint32_t dest, uint32_t netmask, uint32_t gateway) {
    CFMutableDictionaryRef ipv4 = (CFMutableDictionaryRef)CFDictionaryGetValue(currConfig_, (const void *)kSCEntNetIPv4);
    
    //kSCPropNetIPv4ExcludedRoutes
    //kSCPropNetIPv4IncludedRoutes
    //kSCPropNetOverridePrimary
    
    int int1 = 1;
    CFNumberRef one = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType,  &int1);
    CFDictionarySetValue(ipv4, kSCPropNetOverridePrimary, one);
    CFRelease(one);
    
    //kSCPropNetIPv4Addresses
}

/* PPTP VPN on iOS */
/*
 > get  State:/Network/Service/0505C977-CD9A-4759-AE38-F5C84B68332D/DNS
 > d.show
 <dictionary> {
 ServerAddresses : <array> {
 0 : 8.8.8.8
 1 : 208.67.222.222
 }
 SupplementalMatchDomains : <array> {
 0 : 
 }
 SupplementalMatchOrders : <array> {
 0 : 100000
 }
 }
 > get State:/Network/Service/0505C977-CD9A-4759-AE38-F5C84B68332D/IPv4
 > d.show
 <dictionary> {
 Addresses : <array> {
 0 : 172.16.1.17
 }
 DestAddresses : <array> {
 0 : 172.16.1.1
 }
 InterfaceName : ppp0
 NetworkSignature : VPN.RemoteAddress=f.vaone.info
 OverridePrimary : 1
 Router : 172.16.1.1
 ServerAddress : 108.171.248.170
 }
 > get State:/Network/Global/IPv4
 > d.show
 <dictionary> {
 PrimaryInterface : ppp0
 PrimaryService : 0505C977-CD9A-4759-AE38-F5C84B68332D
 Router : 172.16.1.1
 }
 > get State:/Network/Global/DNS
 > d.show
 <dictionary> {
 ServerAddresses : <array> {
 0 : 8.8.8.8
 1 : 208.67.222.222
 }
 }
 > 
 
 Erics-iPod:~ root# netstat -rn
 Routing tables
 
 Internet:
 Destination        Gateway            Flags    Refs      Use  Netif Expire
 default            172.16.1.1         UGSc        0        0   ppp0
 default            192.168.1.1        UGSc        0        0    en0
 127                127.0.0.1          UCS         0        0    lo0
 127.0.0.1          127.0.0.1          UH         10   167050    lo0
 169.254            link#2             UCS         0        0    en0
 172.16             ppp0               USc         0        0   ppp0
 172.16.1.1         172.16.1.8         UH          1        0   ppp0
 192.168.1          link#2             UCS         2        0    en0
 192.168.1.1        0:25:86:6a:f0:16   UHLW        2        0    en0   1029
 192.168.1.203      68:a8:6d:48:79:84  UHLW        1      199    en0   1199
 192.168.1.204      127.0.0.1          UHS         0        0    lo0
 199.119.201.40     192.168.1.1        UGHS        0        1    en0
 
 Protocol Family 30:
 Destination        Gateway            Flags      Netif Expire
 (30) 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0001 0000 0000 (30) 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0001 0000 0000 UH        lo0
 (30) 0000 0000 0000 fe80 0001 0000 0000 0000 0000 0000 0000 0000 0000 (30) 0000 0000 0000 fe80 0001 0000 0000 0000 0000 0000 0001 0000 0000 Uc        lo0
 (30) 0000 0000 0000 fe80 0001 0000 0000 0000 0000 0000 0001 0000 0000 link#1             UHL       lo0
 (30) 0000 0000 0000 fe80 0002 0000 0000 0000 0000 0000 0000 0000 0000 link#2             UC        en0
 (30) 0000 0000 0000 fe80 0002 0000 0000 0223 32ff fe55 6738 0000 0000 0:23:32:55:67:38   UHL       lo0
 (30) 0000 0000 0000 ff01 0000 0000 0000 0000 0000 0000 0000 0000 0000 (30) 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0001 0000 0000 U         lo0
 (30) 0000 0000 0000 ff02 0001 0000 0000 0000 0000 0000 0000 0000 0000 (30) 0000 0000 0000 0000 0000 0000 0000 0000 0000 0000 0001 0000 0000 UC        lo0
 (30) 0000 0000 0000 ff02 0002 0000 0000 0000 0000 0000 0000 0000 0000 link#2             UC        en0
 (30) 0000 0000 0000 ff02 0002 0000 0000 0000 0000 0000 00fb 0000 0000 link#2             UHLW      en0
 ppp0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1444
 inet 172.16.1.8 --> 172.16.1.1 netmask 0xffff0000 
 
 */

 /* OpenVPN net30 on Mac OS X */
 /*
 - ifconfig
tun0: flags=8851<UP,POINTOPOINT,RUNNING,SIMPLEX,MULTICAST> mtu 1500
    inet 10.8.0.6 --> 10.8.0.5 netmask 0xffffffff 
    open (pid 733)

Erics-MacBook-Pro:~ eric$ netstat -rn
Routing tables

Internet:
Destination        Gateway            Flags        Refs      Use   Netif Expire
0/1                10.8.0.5           UGSc            3        0    tun0
default            192.168.1.1        UGSc            3        0     en1
10.8.0.1/32        10.8.0.5           UGSc            0        0    tun0
10.8.0.5           10.8.0.6           UH             12        0    tun0
10.37.129/24       link#9             UC              2        0   vnic1
10.37.129.2        0:1c:42:0:0:9      UHLWIi          1        2     lo0
10.37.129.255      ff:ff:ff:ff:ff:ff  UHLWbI          0        4   vnic1
10.211.55/24       link#8             UC              2        0   vnic0
10.211.55.2        0:1c:42:0:0:8      UHLWIi          1        2     lo0
10.211.55.255      ff:ff:ff:ff:ff:ff  UHLWbI          0        4   vnic0
127                127.0.0.1          UCS             0        0     lo0
127.0.0.1          127.0.0.1          UH              5      796     lo0
128.0/1            10.8.0.5           UGSc            6        0    tun0
169.254            link#5             UCS             0        0     en1
184.82.244.25/32   192.168.1.1        UGSc            1        0     en1
192.168.1          link#5             UCS             3        0     en1
192.168.1.1        0:25:86:6a:f0:16   UHLWIi          2        4     en1    748
192.168.1.202      e0:f8:47:d9:dc:d7  UHLWIi          1      532     en1   1190
192.168.1.203      127.0.0.1          UHS             0        2     lo0
192.168.1.255      ff:ff:ff:ff:ff:ff  UHLWbI          0        4     en1

Internet6:
Destination                             Gateway                         Flags         Netif Expire
::1                                     link#1                          UHL             lo0
fdb2:2c26:f4e4::/64                     link#8                          UC            vnic0
fdb2:2c26:f4e4::1                       0:1c:42:0:0:8                   UHL             lo0
fdb2:2c26:f4e4:1::/64                   link#9                          UC            vnic1
fdb2:2c26:f4e4:1::1                     0:1c:42:0:0:9                   UHL             lo0
fe80::%lo0/64                           fe80::1%lo0                     UcI             lo0
fe80::1%lo0                             link#1                          UHLI            lo0
fe80::%en1/64                           link#5                          UCI             en1
fe80::6aa8:6dff:fe48:7984%en1           68:a8:6d:48:79:84               UHLI            lo0
fe80::%vnic0/64                         link#8                          UCI           vnic0
fe80::21c:42ff:fe00:8%vnic0             0:1c:42:0:0:8                   UHLI            lo0
fe80::%vnic1/64                         link#9                          UCI           vnic1
fe80::21c:42ff:fe00:9%vnic1             0:1c:42:0:0:9                   UHLI            lo0
ff01::%lo0/32                           fe80::1%lo0                     UmCI            lo0
ff01::%en1/32                           link#5                          UmCI            en1
ff01::%vnic0/32                         link#8                          UmCI          vnic0
ff01::%vnic1/32                         link#9                          UmCI          vnic1
ff02::%lo0/32                           fe80::1%lo0                     UmCI            lo0
ff02::%en1/32                           link#5                          UmCI            en1
ff02::%vnic0/32                         link#8                          UmCI          vnic0
ff02::%vnic1/32                         link#9                          UmCI          vnic1

*/


/* OpenVPN p2p on Mac OS X */
/*
tun0: flags=8851<UP,POINTOPOINT,RUNNING,SIMPLEX,MULTICAST> mtu 1500
inet 10.8.0.4 --> 10.8.0.1 netmask 0xffffffff 
open (pid 1305) 

Erics-MacBook-Pro:~ eric$ netstat -rn
Routing tables

Internet:
Destination        Gateway            Flags        Refs      Use   Netif Expire
0/1                10.8.0.1           UGSc            3        0    tun0
default            192.168.1.1        UGSc            3        0     en1
10.8.0.1           10.8.0.4           UH             11        0    tun0
10.37.129/24       link#9             UC              2        0   vnic1
10.37.129.2        0:1c:42:0:0:9      UHLWIi          1        2     lo0
10.37.129.255      ff:ff:ff:ff:ff:ff  UHLWbI          0       15   vnic1
10.211.55/24       link#8             UC              2        0   vnic0
10.211.55.2        0:1c:42:0:0:8      UHLWIi          1        2     lo0
10.211.55.255      ff:ff:ff:ff:ff:ff  UHLWbI          0       15   vnic0
127                127.0.0.1          UCS             0        0     lo0
127.0.0.1          127.0.0.1          UH              5     1560     lo0
128.0/1            10.8.0.1           UGSc            6        0    tun0
169.254            link#5             UCS             0        0     en1
184.82.244.25/32   192.168.1.1        UGSc            1        0     en1
192.168.1          link#5             UCS             3        0     en1
192.168.1.1        0:25:86:6a:f0:16   UHLWIi          3        4     en1    701
192.168.1.202      e0:f8:47:d9:dc:d7  UHLWIi          1      662     en1   1102
192.168.1.203      127.0.0.1          UHS             0        2     lo0
192.168.1.255      ff:ff:ff:ff:ff:ff  UHLWbI          0       15     en1

Internet6:
Destination                             Gateway                         Flags         Netif Expire
::1                                     link#1                          UHL             lo0
fdb2:2c26:f4e4::/64                     link#8                          UC            vnic0
fdb2:2c26:f4e4::1                       0:1c:42:0:0:8                   UHL             lo0
fdb2:2c26:f4e4:1::/64                   link#9                          UC            vnic1
fdb2:2c26:f4e4:1::1                     0:1c:42:0:0:9                   UHL             lo0
fe80::%lo0/64                           fe80::1%lo0                     UcI             lo0
fe80::1%lo0                             link#1                          UHLI            lo0
fe80::%en1/64                           link#5                          UCI             en1
fe80::6aa8:6dff:fe48:7984%en1           68:a8:6d:48:79:84               UHLI            lo0
fe80::%vnic0/64                         link#8                          UCI           vnic0
fe80::21c:42ff:fe00:8%vnic0             0:1c:42:0:0:8                   UHLI            lo0
fe80::%vnic1/64                         link#9                          UCI           vnic1
fe80::21c:42ff:fe00:9%vnic1             0:1c:42:0:0:9                   UHLI            lo0
ff01::%lo0/32                           fe80::1%lo0                     UmCI            lo0
ff01::%en1/32                           link#5                          UmCI            en1
ff01::%vnic0/32                         link#8                          UmCI          vnic0
ff01::%vnic1/32                         link#9                          UmCI          vnic1
ff02::%lo0/32                           fe80::1%lo0                     UmCI            lo0
ff02::%en1/32                           link#5                          UmCI            en1
ff02::%vnic0/32                         link#8                          UmCI          vnic0
ff02::%vnic1/32                         link#9                          UmCI          vnic1

*/

/* OpenVPN subnet on Mac OS X */
/*
tun0: flags=8851<UP,POINTOPOINT,RUNNING,SIMPLEX,MULTICAST> mtu 1500
inet 10.8.0.4 --> 10.8.0.4 netmask 0xffffff00 
open (pid 1497)

Erics-MacBook-Pro:~ eric$ netstat -rn
Routing tables

Internet:
Destination        Gateway            Flags        Refs      Use   Netif Expire
0/1                10.8.0.1           UGSc            2        0    tun0
default            192.168.1.1        UGSc            3        0     en1
10.8/24            10.8.0.4           UGSc            9        0    tun0
10.8.0.4           10.8.0.4           UH              1        0    tun0
10.37.129/24       link#9             UC              2        0   vnic1
10.37.129.2        0:1c:42:0:0:9      UHLWIi          1        2     lo0
10.37.129.255      ff:ff:ff:ff:ff:ff  UHLWbI          0       28   vnic1
10.211.55/24       link#8             UC              2        0   vnic0
10.211.55.2        0:1c:42:0:0:8      UHLWIi          1        2     lo0
10.211.55.255      ff:ff:ff:ff:ff:ff  UHLWbI          0       28   vnic0
127                127.0.0.1          UCS             0        0     lo0
127.0.0.1          127.0.0.1          UH              5     1745     lo0
128.0/1            10.8.0.1           UGSc            5        0    tun0
169.254            link#5             UCS             0        0     en1
184.82.244.25/32   192.168.1.1        UGSc            1        0     en1
192.168.1          link#5             UCS             3        0     en1
192.168.1.1        0:25:86:6a:f0:16   UHLWIi          2        4     en1   1166
192.168.1.202      e0:f8:47:d9:dc:d7  UHLWIi          1      690     en1   1169
192.168.1.203      127.0.0.1          UHS             0        2     lo0
192.168.1.255      ff:ff:ff:ff:ff:ff  UHLWbI          0       28     en1

Internet6:
Destination                             Gateway                         Flags         Netif Expire
::1                                     link#1                          UHL             lo0
fdb2:2c26:f4e4::/64                     link#8                          UC            vnic0
fdb2:2c26:f4e4::1                       0:1c:42:0:0:8                   UHL             lo0
fdb2:2c26:f4e4:1::/64                   link#9                          UC            vnic1
fdb2:2c26:f4e4:1::1                     0:1c:42:0:0:9                   UHL             lo0
fe80::%lo0/64                           fe80::1%lo0                     UcI             lo0
fe80::1%lo0                             link#1                          UHLI            lo0
fe80::%en1/64                           link#5                          UCI             en1
fe80::6aa8:6dff:fe48:7984%en1           68:a8:6d:48:79:84               UHLI            lo0
fe80::%vnic0/64                         link#8                          UCI           vnic0
fe80::21c:42ff:fe00:8%vnic0             0:1c:42:0:0:8                   UHLI            lo0
fe80::%vnic1/64                         link#9                          UCI           vnic1
fe80::21c:42ff:fe00:9%vnic1             0:1c:42:0:0:9                   UHLI            lo0
ff01::%lo0/32                           fe80::1%lo0                     UmCI            lo0
ff01::%en1/32                           link#5                          UmCI            en1
ff01::%vnic0/32                         link#8                          UmCI          vnic0
ff01::%vnic1/32                         link#9                          UmCI          vnic1
ff02::%lo0/32                           fe80::1%lo0                     UmCI            lo0
ff02::%en1/32                           link#5                          UmCI            en1
ff02::%vnic0/32                         link#8                          UmCI          vnic0
ff02::%vnic1/32                         link#9                          UmCI          vnic1

*/
