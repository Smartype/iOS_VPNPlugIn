//
//  main.m
//  OpenVPN
//
//  Created by Eric on 5/28/12.
//  Copyright (c) 2012 __MyCompanyName__. All rights reserved.
//
#include <unistd.h>
#include <fcntl.h>
#include "iOSVPNPlugIn.h"

#define DLL_PUBLIC __attribute__ ((visibility ("default")))
//#define DLL_LOCAL  __attribute__ ((visibility ("hidden")))

extern void* PluginController_createInstance(SCVPNTunnelSessionRef session, CFDictionaryRef settings);
extern void PluginController_dispose(void* ctrl, SCVPNTunnelSessionRef session);
extern void PluginController_auth_complete(void* ctrl, SCVPNTunnelSessionRef session);
extern void PluginController_display_banner(void* ctrl, SCVPNTunnelSessionRef session);
extern void PluginController_connect(void* ctrl, SCVPNTunnelSessionRef session, CFDictionaryRef settings);
extern void PluginController_event(void* ctrl, SCVPNTunnelSessionRef session, VPNTunnelEventType event);
extern void PluginController_disconnect(void* ctrl, SCVPNTunnelSessionRef session, CFDictionaryRef result);
extern void PluginController_message(void* ctrl, SCVPNTunnelSessionRef session, unsigned int app, unsigned int type, CFDataRef data);

DLL_PUBLIC Boolean Plugin_VPNTunnelInit(SCVPNTunnelSessionRef session, CFDictionaryRef settings, void** context) {
    *context = PluginController_createInstance(session, settings);
    return TRUE;
}

DLL_PUBLIC void Plugin_VPNTunnelDispose(SCVPNTunnelSessionRef session, void* context) {
    PluginController_dispose(context, session);
}

DLL_PUBLIC void Plugin_VPNTunnelAuthenticateComplete(SCVPNTunnelSessionRef session, void* context) {
    PluginController_auth_complete(context, session);
}

DLL_PUBLIC void Plugin_VPNTunnelDisplayBannerComplete(SCVPNTunnelSessionRef session, void* context) {
    PluginController_display_banner(context, session);
}

DLL_PUBLIC void Plugin_VPNTunnelConnect(SCVPNTunnelSessionRef session, void* context, CFDictionaryRef settings) {
    PluginController_connect(context, session, settings);
}

DLL_PUBLIC void Plugin_VPNTunnelEnvironmentEvent(SCVPNTunnelSessionRef session, void* context, VPNTunnelEventType event){
    PluginController_event(context, session, event);
}

DLL_PUBLIC void Plugin_VPNTunnelDisconnect(SCVPNTunnelSessionRef session, void* context, CFDictionaryRef result) {
    PluginController_disconnect(context, session, result);
}

DLL_PUBLIC void Plugin_VPNTunnelIPCReceivedMessage(SCVPNTunnelSessionRef session, void* context, unsigned int app, unsigned int type, CFDataRef data) {
    PluginController_message(context, session, app, type, data);
}
