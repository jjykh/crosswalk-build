// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.support_lib_glue;

import android.webkit.SafeBrowsingResponse;
import android.webkit.ServiceWorkerWebSettings;
import android.webkit.WebMessagePort;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;

import com.android.webview.chromium.ServiceWorkerSettingsAdapter;
import com.android.webview.chromium.WebMessagePortAdapter;
import com.android.webview.chromium.WebResourceErrorAdapter;
import com.android.webview.chromium.WebkitToSharedGlueConverter;

import org.chromium.support_lib_boundary.WebkitToCompatConverterBoundaryInterface;
import org.chromium.support_lib_boundary.util.BoundaryInterfaceReflectionUtil;
import org.chromium.support_lib_callback_glue.SupportLibWebResourceError;

import java.lang.reflect.InvocationHandler;

/**
 * Adapter used for fetching implementations for Compat objects given their corresponding
 * webkit-object.
 */
class SupportLibWebkitToCompatConverterAdapter implements WebkitToCompatConverterBoundaryInterface {
    SupportLibWebkitToCompatConverterAdapter() {}

    // WebSettingsBoundaryInterface
    @Override
    public InvocationHandler convertSettings(WebSettings webSettings) {
        return BoundaryInterfaceReflectionUtil.createInvocationHandlerFor(
                new SupportLibWebSettingsAdapter(
                        WebkitToSharedGlueConverter.getSettings(webSettings)));
    }

    // WebResourceRequestBoundaryInterface
    @Override
    public InvocationHandler convertWebResourceRequest(WebResourceRequest request) {
        return BoundaryInterfaceReflectionUtil.createInvocationHandlerFor(
                new SupportLibWebResourceRequest(
                        WebkitToSharedGlueConverter.getWebResourceRequest(request)));
    }

    // ServiceWorkerWebSettingsBoundaryInterface
    @Override
    public InvocationHandler convertServiceWorkerSettings(
            /* ServiceWorkerWebSettings */ Object serviceWorkerWebSettings) {
        return BoundaryInterfaceReflectionUtil.createInvocationHandlerFor(
                new SupportLibServiceWorkerSettingsAdapter(
                        WebkitToSharedGlueConverter.getServiceWorkerSettings(
                                (ServiceWorkerWebSettings) serviceWorkerWebSettings)));
    }

    @Override
    public /* ServiceWorkerWebSettings */ Object convertServiceWorkerSettings(
            /* SupportLibServiceWorkerSettings */ InvocationHandler serviceWorkerSettings) {
        SupportLibServiceWorkerSettingsAdapter supportLibWebSettings =
                (SupportLibServiceWorkerSettingsAdapter) BoundaryInterfaceReflectionUtil
                        .getDelegateFromInvocationHandler(serviceWorkerSettings);
        return new ServiceWorkerSettingsAdapter(supportLibWebSettings.getAwServiceWorkerSettings());
    }

    @Override
    public /* SupportLibWebResourceError */ InvocationHandler convertWebResourceError(
            /* WebResourceError */ Object webResourceError) {
        return BoundaryInterfaceReflectionUtil.createInvocationHandlerFor(
                new SupportLibWebResourceError(WebkitToSharedGlueConverter.getAwWebResourceError(
                        (WebResourceError) webResourceError)));
    }

    @Override
    public /* WebResourceError */ Object convertWebResourceError(
            /* SupportLibWebResourceError */ InvocationHandler webResourceError) {
        SupportLibWebResourceError supportLibError =
                (SupportLibWebResourceError) BoundaryInterfaceReflectionUtil
                        .getDelegateFromInvocationHandler(webResourceError);
        return new WebResourceErrorAdapter(supportLibError.getAwWebResourceError());
    }

    @Override
    public /* SupportLibSafeBrowsingResponse */ InvocationHandler convertSafeBrowsingResponse(
            /* SafeBrowsingResponse */ Object safeBrowsingResponse) {
        return null;
    }

    @Override
    public /* SafeBrowsingResponse */ Object convertSafeBrowsingResponse(
            /* SupportLibSafeBrowsingResponse */ InvocationHandler safeBrowsingResponse) {
        return null;
    }

    @Override
    public /* SupportLibWebMessagePort */ InvocationHandler convertWebMessagePort(
            /* WebMessagePort */ Object webMessagePort) {
        return BoundaryInterfaceReflectionUtil.createInvocationHandlerFor(
                new SupportLibWebMessagePortAdapter(WebkitToSharedGlueConverter.getMessagePort(
                        (WebMessagePort) webMessagePort)));
    }

    @Override
    public /* WebMessagePort */ Object convertWebMessagePort(
            /* SupportLibWebMessagePort */ InvocationHandler webMessagePort) {
        SupportLibWebMessagePortAdapter supportLibMessagePort =
                (SupportLibWebMessagePortAdapter) BoundaryInterfaceReflectionUtil
                        .getDelegateFromInvocationHandler(webMessagePort);
        return new WebMessagePortAdapter(supportLibMessagePort.getPort());
    }
}
