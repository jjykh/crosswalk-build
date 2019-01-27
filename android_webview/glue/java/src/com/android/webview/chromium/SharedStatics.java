// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package com.android.webview.chromium;

import android.app.ActivityManager;
import android.content.Context;
import android.content.Intent;
import android.net.Uri;
import android.os.Looper;

import org.chromium.android_webview.AwContentsClient;
import org.chromium.android_webview.AwContentsStatics;
import org.chromium.android_webview.AwSettings;
import org.chromium.android_webview.command_line.CommandLineUtil;
import org.chromium.base.Callback;
import org.chromium.base.MemoryPressureLevel;
import org.chromium.base.ThreadUtils;
import org.chromium.base.memory.MemoryPressureMonitor;

import java.util.List;

/**
 * This class provides functionality that is accessed in a static way from apps using WebView.
 * This class is meant to be shared between the webkit-glue layer and the support library glue
 * layer.
 * Ideally this class would live in a lower layer than the webkit-glue layer, to allow sharing the
 * implementation between different glue layers without needing to depend on the webkit-glue layer
 * (right now there are dependencies from this class on the webkit-glue layer though).
 */
public class SharedStatics {

    public SharedStatics() {}

    public String findAddress(String addr) {
        return AwContentsStatics.findAddress(addr);
    }

    public String getDefaultUserAgent(Context context) {
        return AwSettings.getDefaultUserAgent();
    }

    public void setWebContentsDebuggingEnabled(boolean enable) {
        // Web Contents debugging is always enabled on debug builds.
        if (!CommandLineUtil.isBuildDebuggable()) {
            setWebContentsDebuggingEnabledUnconditionally(enable);
        }
    }

    public void setWebContentsDebuggingEnabledUnconditionally(boolean enable) {
        if (Looper.myLooper() != ThreadUtils.getUiThreadLooper()) {
            throw new RuntimeException(
                    "Toggling of Web Contents Debugging must be done on the UI thread");
        }
    }

    public void clearClientCertPreferences(Runnable onCleared) {
        // clang-format off
        ThreadUtils.runOnUiThread(() ->
                AwContentsStatics.clearClientCertPreferences(onCleared));
        // clang-format on
    }

    public void freeMemoryForTests() {
        if (ActivityManager.isRunningInTestHarness()) {
            ThreadUtils.postOnUiThread(() -> {
                // This variable is needed to prevent weird formatting by "git cl format".
                MemoryPressureMonitor pressureMonitor = MemoryPressureMonitor.INSTANCE;
                pressureMonitor.notifyPressure(MemoryPressureLevel.CRITICAL);
            });
        }
    }

    public void enableSlowWholeDocumentDraw() {
        WebViewChromium.enableSlowWholeDocumentDraw();
    }

    public Uri[] parseFileChooserResult(int resultCode, Intent intent) {
        return AwContentsClient.parseFileChooserResult(resultCode, intent);
    }

    /**
     * Starts Safe Browsing initialization. This should only be called once.
     * @param context is the application context the WebView will be used in.
     * @param callback will be called with the value true if initialization is
     * successful. The callback will be run on the UI thread.
     */
    public void initSafeBrowsing(Context context, Callback<Boolean> callback) {
    }

    public void setSafeBrowsingWhitelist(List<String> urls, Callback<Boolean> callback) {
    }

    public void setProxyOverride(String host, int port, String[] exclusionList) {
        ThreadUtils.runOnUiThread(
                () -> AwContentsStatics.setProxyOverride(host, port, exclusionList));
    }

    public void clearProxyOverride() {
        ThreadUtils.runOnUiThread(() -> AwContentsStatics.clearProxyOverride());
    }
}
