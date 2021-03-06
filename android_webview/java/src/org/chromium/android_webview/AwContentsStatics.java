// Copyright 2014 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

package org.chromium.android_webview;

import android.content.Context;
import android.net.Uri;

import org.chromium.base.Callback;
import org.chromium.base.ThreadUtils;
import org.chromium.base.annotations.CalledByNative;
import org.chromium.base.annotations.JNINamespace;

import java.util.List;

/**
 * Implementations of various static methods, and also a home for static
 * data structures that are meant to be shared between all webviews.
 */
@JNINamespace("android_webview")
public class AwContentsStatics {

    private static ClientCertLookupTable sClientCertLookupTable;

    private static String sUnreachableWebDataUrl;

    private static boolean sRecordFullDocument;

    /**
     * Return the client certificate lookup table.
     */
    public static ClientCertLookupTable getClientCertLookupTable() {
        ThreadUtils.assertOnUiThread();
        if (sClientCertLookupTable == null) {
            sClientCertLookupTable = new ClientCertLookupTable();
        }
        return sClientCertLookupTable;
    }

    /**
     * Clear client cert lookup table. Should only be called from UI thread.
     */
    public static void clearClientCertPreferences(Runnable callback) {
        ThreadUtils.assertOnUiThread();
        getClientCertLookupTable().clear();
        nativeClearClientCertPreferences(callback);
    }

    @CalledByNative
    private static void clientCertificatesCleared(Runnable callback) {
        if (callback == null) return;
        callback.run();
    }

    public static String getUnreachableWebDataUrl() {
        // Note that this method may be called from both IO and UI threads,
        // but as it only retrieves a value of a constant from native, even if
        // two calls will be running at the same time, this should not cause
        // any harm.
        if (sUnreachableWebDataUrl == null) {
            sUnreachableWebDataUrl = nativeGetUnreachableWebDataUrl();
        }
        return sUnreachableWebDataUrl;
    }

    public static void setRecordFullDocument(boolean recordFullDocument) {
        sRecordFullDocument = recordFullDocument;
    }

    /* package */ static boolean getRecordFullDocument() {
        return sRecordFullDocument;
    }

    public static String getProductVersion() {
        return nativeGetProductVersion();
    }

    public static void setServiceWorkerIoThreadClient(AwContentsIoThreadClient ioThreadClient,
            AwBrowserContext browserContext) {
        nativeSetServiceWorkerIoThreadClient(ioThreadClient, browserContext);
    }

    @CalledByNative
    private static void safeBrowsingWhitelistAssigned(Callback<Boolean> callback, boolean success) {
        if (callback == null) return;
        callback.onResult(success);
    }

    public static void setCheckClearTextPermitted(boolean permitted) {
        nativeSetCheckClearTextPermitted(permitted);
    }

    public static void setProxyOverride(String host, int port, String[] exclusionList) {
        nativeSetProxyOverride(host, port, exclusionList);
    }

    public static void clearProxyOverride() {
        nativeClearProxyOverride();
    }

    /**
     * Return the first substring consisting of the address of a physical location.
     * @see {@link android.webkit.WebView#findAddress(String)}
     *
     * @param addr The string to search for addresses.
     * @return the address, or if no address is found, return null.
     */
    public static String findAddress(String addr) {
        if (addr == null) {
            throw new NullPointerException("addr is null");
        }
        return FindAddress.findAddress(addr);
    }

    //--------------------------------------------------------------------------------------------
    //  Native methods
    //--------------------------------------------------------------------------------------------
    private static native void nativeClearClientCertPreferences(Runnable callback);
    private static native String nativeGetUnreachableWebDataUrl();
    private static native String nativeGetProductVersion();
    private static native void nativeSetServiceWorkerIoThreadClient(
            AwContentsIoThreadClient ioThreadClient, AwBrowserContext browserContext);
    private static native void nativeSetCheckClearTextPermitted(boolean permitted);
    private static native void nativeSetProxyOverride(
            String host, int port, String[] exclusionList);
    private static native void nativeClearProxyOverride();
}
