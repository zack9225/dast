#!/usr/bin/env python
# A  ZAP Python Script which spiders and perform active and passive scans on a target URL.

import time
from pprint import pprint
from zapv2 import ZAPv2
import os
#Import Configuration : config.py 
from config import TestConfig as cfg   

########################
### ZAP Execution    ###
########################

# Configure ZAP with localProxy and apiKey
zap = ZAPv2(apikey=cfg.apiKey, proxies=cfg.localProxy)

# Create New Session
if cfg.isNewSession:
    pprint('Create ZAP session: ' + cfg.sessionName + ' -> ' +
            zap.core.new_session(name=cfg.sessionName, overwrite=True))
else:
    pprint('Load ZAP session: ' + cfg.sessionName + ' -> ' +
            zap.core.load_session(name=cfg.sessionName))

# Create New Context
if cfg.useContextForScan:
    if cfg.defineNewContext:
        contextId = zap.context.new_context(contextname=cfg.contextName)
    pprint('Use context ID: ' + contextId)

    print('Include URL in context:')
    for url in cfg.contextIncludeURL:
        pprint(url + ' -> ' + zap.context.include_in_context(contextname=cfg.contextName,regex=url))

    print('Exclude URL from context:')
    for url in cfg.contextExcludeURL:
        pprint(url + ' -> ' + zap.context.exclude_from_context(contextname=cfg.contextName,regex=url))

    pprint('Set session management method: ' + cfg.sessionManagement + ' -> ' +
            zap.sessionManagement.set_session_management_method(
                contextid=contextId, methodname=cfg.sessionManagement,
                methodconfigparams=None))

    pprint('Set authentication method: ' + cfg.authMethod + ' -> ' +
            zap.authentication.set_authentication_method(contextid=contextId,
                                           authmethodname=cfg.authMethod,
                                           authmethodconfigparams=cfg.authParams))
   
    if cfg.isLoggedInIndicator:
        pprint('Define Loggedin indicator: ' + cfg.indicatorRegex + ' -> ' +
                zap.authentication.set_logged_in_indicator(contextid=contextId,
                                        loggedinindicatorregex=cfg.indicatorRegex))
    else:
        pprint('Define Loggedout indicator: ' + cfg.indicatorRegex + ' -> ' +
                zap.authentication.set_logged_out_indicator(contextid=contextId,
                                        loggedoutindicatorregex=cfg.indicatorRegex))
    userIdList = []
    users = zap.users
    if cfg.createUser:
        for user in cfg.userList:
            userName = user.get('name')
            print('Create user ' + userName + ':')
            userId = users.new_user(contextid=contextId, name=userName)
            userIdList.append(userId)
            pprint('User ID: ' + userId + '; username -> ' +
                    users.set_user_name(contextid=contextId, userid=userId,
                                        name=userName) +
                    '; credentials -> ' +
                    users.set_authentication_credentials(contextid=contextId,
                        userid=userId,
                        authcredentialsconfigparams=user.get('credentials')) +
                    '; enabled -> ' +
                    users.set_user_enabled(contextid=contextId, userid=userId,
                                           enabled=True))

pprint('Enable all passive scanners -> ' + zap.pscan.enable_all_scanners())

scanId=0
print('Starting Scans on target: ' + cfg.target)
if cfg.useContextForScan:
    for userId in userIdList:
        print('Starting scans with User ID: ' + userId)
        #*****************************
        # SPIDER and passive Scan    *
        #*****************************
        
        scanId = zap.spider.scan_as_user(contextid=contextId, userid=userId,
                url=cfg.target, maxchildren=None, recurse=True, subtreeonly=None)
        print('Start Spider scan with user ID: ' + userId + '. Scan ID equals: ' + scanId)
        time.sleep(2)
        while (int(zap.spider.status(scanId)) < 100):
            print('Spider progress: ' + zap.spider.status(scanId) + '%')
            time.sleep(2)
        print('Spider scan for user ID ' + userId + ' completed')
        
        #*****************************
        # Ajax Spider Scan           *
        #*****************************
        
        if cfg.useAjaxSpider:
            pprint('Set forced user mode enabled -> ' + zap.forcedUser.set_forced_user_mode_enabled(boolean=True))
            pprint('Set user ID: ' + userId + ' for forced user mode -> ' +  
                   zap.forcedUser.set_forced_user(contextid=contextId, userid=userId))
            # Ajax Spider the target URL
            pprint('Ajax Spider the target with user ID: ' + userId + ' -> ' + zap.ajaxSpider.scan(url=cfg.target, inscope=None))
            # Give the Ajax spider a chance to start
            time.sleep(10)
            while (zap.ajaxSpider.status != 'stopped'):
                print('Ajax Spider is ' + zap.ajaxSpider.status)
                time.sleep(5)
            for url in cfg.applicationURL:
                # Ajax Spider every url configured
                pprint('Ajax Spider the URL: ' + url + ' with user ID: ' + userId + ' -> ' + zap.ajaxSpider.scan(url=url, inscope=None))
                # Give the Ajax spider a chance to start
                time.sleep(10)
                while (zap.ajaxSpider.status != 'stopped'):
                    print('Ajax Spider is ' + zap.ajaxSpider.status)
                    time.sleep(5)
            pprint('Set forced user mode disabled -> ' + zap.forcedUser.set_forced_user_mode_enabled(boolean=False))
            print('Ajax Spider scan for user ID ' + userId + ' completed')

        #*****************************
        # Active Scanning            *
        #*****************************
        
        scanId = zap.ascan.scan_as_user(url=cfg.target, contextid=contextId,
                userid=userId, recurse=True, scanpolicyname=cfg.scanPolicyName,
                method=None, postdata=True)
        print('Start Active Scan with user ID: ' + userId + '. Scan ID equals: ' + scanId)
        # Give the scanner a chance to start
        time.sleep(2)
        while (int(zap.ascan.status(scanId)) < 100):
            print('Active Scan progress: ' + zap.ascan.status(scanId) + '%')
            time.sleep(2)
        print('Active Scan for user ID ' + userId + ' completed')

# Give the passive scanner a chance to finish
time.sleep(5)

# HTML Report
print('HTML report:')
f1 = open('owasp-zap.html','w')
f1.write(zap.core.htmlreport())
f1.close()

# XML Report
print('XML report:')
f = open('owasp-zap.xml','w')
f.write(zap.core.xmlreport())
f.close()