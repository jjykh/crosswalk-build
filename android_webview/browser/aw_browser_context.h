// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#ifndef ANDROID_WEBVIEW_BROWSER_AW_BROWSER_CONTEXT_H_
#define ANDROID_WEBVIEW_BROWSER_AW_BROWSER_CONTEXT_H_

#include <memory>
#include <vector>

#include "android_webview/browser/aw_ssl_host_state_delegate.h"
#include "base/compiler_specific.h"
#include "base/files/file_path.h"
#include "base/macros.h"
#include "base/memory/ref_counted.h"
#include "components/prefs/pref_change_registrar.h"
#include "components/visitedlink/browser/visitedlink_delegate.h"
#include "components/web_restrictions/browser/web_restrictions_client.h"
#include "content/public/browser/browser_context.h"

class GURL;
class PrefService;

namespace content {
class PermissionControllerDelegate;
class ResourceContext;
class SSLHostStateDelegate;
class WebContents;
}

namespace net {
class NetLog;
}

namespace policy {
class BrowserPolicyConnectorBase;
}

namespace visitedlink {
class VisitedLinkMaster;
}

namespace safe_browsing {
class TriggerManager;
}  // namespace safe_browsing

namespace android_webview {

class AwFormDatabaseService;
class AwQuotaManagerBridge;
class AwSafeBrowsingWhitelistManager;
class AwURLRequestContextGetter;

namespace prefs {

// Used for Kerberos authentication.
extern const char kAuthAndroidNegotiateAccountType[];
extern const char kAuthServerWhitelist[];
extern const char kWebRestrictionsAuthority[];

}  // namespace prefs

class AwBrowserContext : public content::BrowserContext,
                         public visitedlink::VisitedLinkDelegate {
 public:
  AwBrowserContext(const base::FilePath path);
  ~AwBrowserContext() override;

  // Currently only one instance per process is supported.
  static AwBrowserContext* GetDefault();

  // Convenience method to returns the AwBrowserContext corresponding to the
  // given WebContents.
  static AwBrowserContext* FromWebContents(
      content::WebContents* web_contents);

  // Maps to BrowserMainParts::PreMainMessageLoopRun.
  void PreMainMessageLoopRun(net::NetLog* net_log);

  // These methods map to Add methods in visitedlink::VisitedLinkMaster.
  void AddVisitedURLs(const std::vector<GURL>& urls);

  AwQuotaManagerBridge* GetQuotaManagerBridge();
  AwURLRequestContextGetter* GetAwURLRequestContext();

  web_restrictions::WebRestrictionsClient* GetWebRestrictionProvider();

  // content::BrowserContext implementation.
  base::FilePath GetPath() const override;
  base::FilePath GetCachePath() const override;
  bool IsOffTheRecord() const override;
  content::ResourceContext* GetResourceContext() override;
  content::DownloadManagerDelegate* GetDownloadManagerDelegate() override;
  content::BrowserPluginGuestManager* GetGuestManager() override;
  storage::SpecialStoragePolicy* GetSpecialStoragePolicy() override;
  content::PushMessagingService* GetPushMessagingService() override;
  content::SSLHostStateDelegate* GetSSLHostStateDelegate() override;
  content::PermissionControllerDelegate* GetPermissionControllerDelegate()
      override;
  content::BackgroundFetchDelegate* GetBackgroundFetchDelegate() override;
  content::BackgroundSyncController* GetBackgroundSyncController() override;
  content::BrowsingDataRemoverDelegate* GetBrowsingDataRemoverDelegate()
      override;
  net::URLRequestContextGetter* CreateRequestContext(
      content::ProtocolHandlerMap* protocol_handlers,
      content::URLRequestInterceptorScopedVector request_interceptors) override;
  net::URLRequestContextGetter* CreateRequestContextForStoragePartition(
      const base::FilePath& partition_path,
      bool in_memory,
      content::ProtocolHandlerMap* protocol_handlers,
      content::URLRequestInterceptorScopedVector request_interceptors) override;
  net::URLRequestContextGetter* CreateMediaRequestContext() override;
  net::URLRequestContextGetter* CreateMediaRequestContextForStoragePartition(
      const base::FilePath& partition_path,
      bool in_memory) override;

  // visitedlink::VisitedLinkDelegate implementation.
  void RebuildTable(const scoped_refptr<URLEnumerator>& enumerator) override;

 private:
  void InitUserPrefService();
  void OnWebRestrictionsAuthorityChanged();

  // The file path where data for this context is persisted.
  base::FilePath context_storage_path_;

  scoped_refptr<AwURLRequestContextGetter> url_request_context_getter_;
  scoped_refptr<AwQuotaManagerBridge> quota_manager_bridge_;

  std::unique_ptr<visitedlink::VisitedLinkMaster> visitedlink_master_;
  std::unique_ptr<content::ResourceContext> resource_context_;

  std::unique_ptr<PrefService> user_pref_service_;
  std::unique_ptr<AwSSLHostStateDelegate> ssl_host_state_delegate_;
  std::unique_ptr<content::PermissionControllerDelegate> permission_manager_;
  std::unique_ptr<web_restrictions::WebRestrictionsClient>
      web_restriction_provider_;
  PrefChangeRegistrar pref_change_registrar_;

  DISALLOW_COPY_AND_ASSIGN(AwBrowserContext);
};

}  // namespace android_webview

#endif  // ANDROID_WEBVIEW_BROWSER_AW_BROWSER_CONTEXT_H_
