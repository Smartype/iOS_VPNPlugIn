//
//  PluginController.h
//  OpenVPN
//
//  Created by Eric on 5/31/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//

#ifndef OpenVPN_PluginController_h
#define OpenVPN_PluginController_h

#include <string>
#include <vector>
#include <functional>
#include <iostream>

extern "C" {
#include "iOSVPNPlugIn.h"
#include <pthread.h>
#include <stdint.h>
#include <CoreFoundation/CoreFoundation.h>
}

using namespace std;

class PluginController {
    
public:
    static PluginController* instance();
    PluginController();
    
    static void* OpenVPNThread(void *param);
    static void OpenVPNCallback(CFSocketRef s, CFSocketCallBackType type, CFDataRef address, const void *data, void *info);
    static void mgmtSocketCallback(CFSocketRef s, CFSocketCallBackType type, CFDataRef address, const void *data, void *info);
    
    void setupTun(uint32_t address, uint32_t netmask, uint32_t gateway, uint32_t mtu);
    void setRemoteAddress(uint32_t addr);
    void setDNSAddresses(uint32_t primary, uint32_t secondary);    
    void setupRoute(uint32_t dest, uint32_t netmask, uint32_t gateway);
    void startOpenVPN();
    void stopOpenVPN();
    void initialize(SCVPNTunnelSessionRef session, CFDictionaryRef settings);    
    CFStringRef getWorkingDirectory() const;


    void dispose();
    void authComplete();
    void displayBannerComplete();
    void connect(CFDictionaryRef settings);
    void disconnect(CFDictionaryRef result);
    void event(VPNTunnelEventType event);
    void message(unsigned int app, unsigned int type, CFDataRef data); 
    int getTunelFd() const;
    bool listenForManagement();
    unsigned int getManagementPort();
    void acceptManagementSocket(int s);
    void appendManagementBuffer(char* buf, int len);
    void evalManagementCmdline(char* cmdline);
    void sendManagementCmdline(const char* cmdline);
    void processLogCmdline(char* cmdline);    
    void processStateCmdline(char* cmdline);
    void processHoldCmdline(char* cmdline);
    void splitCmdline(const string& s, char c, vector<string>& v, int max);
    const SCVPNTunnelSessionRef getTunnelSession() const;
    
    void sendMessage(unsigned int msg, CFDictionaryRef dict);
    void sendAckMessage();
    void createFile(CFDictionaryRef dict);

    
private:

    void initializeConfig();
    
    static pthread_mutex_t mutex;
    
    CFMutableDictionaryRef  currConfig_;
    int                     tunFd_;
    CFSocketRef             ctrlSocket_;
    CFSocketRef             mgmtListenSocket_;    
    pthread_t               ovthread_;

    SCVPNTunnelSessionRef   tunnelSession_;
    CFStringRef             serviceId_;
    CFStringRef             workingDir_;
    
    enum { mgmtStreamSize = 1024 };
    int             mgmtStreamLen_;
    char            mgmtStream_[mgmtStreamSize];
    bool            appAttached_;
};

#endif
