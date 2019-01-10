// Copyright 2018 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

#include "android_webview/renderer/aw_websocket_handshake_throttle_provider.h"

#include <utility>

#include "base/feature_list.h"
#include "content/public/common/content_features.h"
#include "content/public/common/service_names.mojom.h"
#include "content/public/renderer/render_thread.h"
#include "services/network/public/cpp/features.h"
#include "services/service_manager/public/cpp/connector.h"
#include "third_party/blink/public/platform/websocket_handshake_throttle.h"

namespace android_webview {

AwWebSocketHandshakeThrottleProvider::AwWebSocketHandshakeThrottleProvider() {
  DETACH_FROM_THREAD(thread_checker_);
}

AwWebSocketHandshakeThrottleProvider::~AwWebSocketHandshakeThrottleProvider() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
}

AwWebSocketHandshakeThrottleProvider::AwWebSocketHandshakeThrottleProvider(
    const AwWebSocketHandshakeThrottleProvider& other) {
  DETACH_FROM_THREAD(thread_checker_);
}

std::unique_ptr<content::WebSocketHandshakeThrottleProvider>
AwWebSocketHandshakeThrottleProvider::Clone() {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
  return base::WrapUnique(new AwWebSocketHandshakeThrottleProvider(*this));
}

std::unique_ptr<blink::WebSocketHandshakeThrottle>
AwWebSocketHandshakeThrottleProvider::CreateThrottle(int render_frame_id) {
  DCHECK_CALLED_ON_VALID_THREAD(thread_checker_);
    return nullptr;
}

}  // namespace android_webview
