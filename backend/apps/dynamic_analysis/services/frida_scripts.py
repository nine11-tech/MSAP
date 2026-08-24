from __future__ import annotations


RUNTIME_UI_MODIFICATION_PROOF_NAME = "Frida — Runtime UI Modification Proof"
RUNTIME_UI_MODIFICATION_VALUE = "MSAP FRIDA ACTIVE"

# This script intentionally avoids a hard-coded application Activity class. It
# selects the live android.app.Activity instance that owns window focus, retains
# it across the heap scan callback, and performs the title update on Android's
# main thread. Success is reported only after reading the modified title back.
RUNTIME_UI_MODIFICATION_PROOF_SOURCE = r"""
Java.perform(function () {
  var selectedActivity = null;
  Java.choose("android.app.Activity", {
    onMatch: function (activity) {
      try {
        if (activity.hasWindowFocus()) {
          selectedActivity = Java.retain(activity);
          return "stop";
        }
      } catch (ignored) {
      }
    },
    onComplete: function () {
      if (selectedActivity === null) {
        send({
          type: "ui_modification",
          success: false,
          target: "android.app.Activity",
          original_value: "",
          new_value: "MSAP FRIDA ACTIVE",
          error: "No focused Activity instance was found"
        });
        return;
      }
      Java.scheduleOnMainThread(function () {
        try {
          var JavaString = Java.use("java.lang.String");
          var originalTitle = selectedActivity.getTitle();
          var originalValue = originalTitle === null ? "" : originalTitle.toString();
          var target = selectedActivity.getClass().getName().toString();
          selectedActivity.setTitle(JavaString.$new("MSAP FRIDA ACTIVE"));
          var changedTitle = selectedActivity.getTitle();
          var changedValue = changedTitle === null ? "" : changedTitle.toString();
          send({
            type: "ui_modification",
            success: changedValue === "MSAP FRIDA ACTIVE",
            target: target,
            original_value: originalValue,
            new_value: changedValue
          });
        } catch (error) {
          send({
            type: "ui_modification",
            success: false,
            target: "android.app.Activity",
            original_value: "",
            new_value: "MSAP FRIDA ACTIVE",
            error: String(error)
          });
        }
      });
    }
  });
});
""".strip()

ROOT_SIGNAL_OBSERVATION_SOURCE = r"""
Java.perform(function () {
  var File = Java.use("java.io.File");
  var originalExists = File.exists.overload();
  originalExists.implementation = function () {
    var path = this.getAbsolutePath().toString();
    var result = originalExists.call(this);
    if (path.indexOf("/su") >= 0 || path.indexOf("/magisk") >= 0 || path.indexOf("/system/xbin") >= 0) {
      send({type: "root_signal_observation", api: "java.io.File.exists", path_suffix: path.slice(-96), exists: !!result});
    }
    return result;
  };
  send({type: "root_signal_observation_ready", hooks: ["java.io.File.exists"], bypass: false});
});
""".strip()

EMULATOR_SIGNAL_OBSERVATION_SOURCE = r"""
Java.perform(function () {
  var Build = Java.use("android.os.Build");
  send({
    type: "emulator_signal_observation",
    fingerprint: Build.FINGERPRINT.value.toString().slice(0, 96),
    model: Build.MODEL.value.toString().slice(0, 96),
    manufacturer: Build.MANUFACTURER.value.toString().slice(0, 96),
    product: Build.PRODUCT.value.toString().slice(0, 96),
    bypass: false
  });
});
""".strip()

ROOT_DETECTION_LAB_BYPASS_SOURCE = r"""
Java.perform(function () {
  var File = Java.use("java.io.File");
  var exists = File.exists.overload();
  exists.implementation = function () {
    var path = this.getAbsolutePath().toString();
    if (path.indexOf("/su") >= 0 || path.indexOf("/magisk") >= 0 || path.indexOf("/system/xbin") >= 0) {
      send({type: "lab_root_signal_modified", path_suffix: path.slice(-96), original: true, modified: false});
      return false;
    }
    return exists.call(this);
  };
  send({type: "lab_root_bypass_applied", template: "ROOT_DETECTION_LAB_BYPASS", observation_only_target: true});
});
""".strip()

ROOT_DETECTION_UI_CHANGE_SOURCE = r"""
Java.perform(function () {
  var changed = false;
  Java.choose("android.app.AlertDialog", {
    onMatch: function (dialog) {
      try {
        var message = dialog.findViewById(16908299);
        if (message !== null) {
          var originalValue = message.getText().toString();
          message.setText("Device is rooted");
          changed = true;
          send({
            type: "root_detection_ui_changed",
            success: true,
            original_value: originalValue,
            new_value: "Device is rooted",
            control: "android.R.id.message"
          });
          return "stop";
        }
      } catch (error) {
        send({type: "root_detection_ui_change_error", success: false, error: String(error)});
      }
    },
    onComplete: function () {
      send({
        type: "root_detection_ui_change_complete",
        success: changed,
        changed: changed,
        limitation: changed ? "" : "The active root-result dialog was not found"
      });
    }
  });
});
""".strip()

ROOT_DETECTION_NATIVE_HOOK_SOURCE = r"""
(function () {
  var modified = false;
  var hookNames = ["access", "faccessat", "stat", "stat64"];
  hookNames.forEach(function (name) {
    var address = Module.findGlobalExportByName(name);
    if (address === null) return;
    Interceptor.attach(address, {
      onEnter: function (args) {
        try {
          var pathIndex = name === "faccessat" ? 1 : 0;
          var path = args[pathIndex].readUtf8String();
          if (path && (path.indexOf("/su") >= 0 || path.indexOf("/magisk") >= 0 || path.indexOf("/system/xbin") >= 0)) {
            this.msapRootSignal = path.slice(-96);
          }
        } catch (ignored) {}
      },
      onLeave: function (retval) {
        if (this.msapRootSignal) {
          var originalResult = retval.toInt32();
          modified = true;
          retval.replace(-1);
          send({type: "root_detection_native_signal_modified", success: true, api: name, path_suffix: this.msapRootSignal, original_result: originalResult, modified_result: -1});
        }
      }
    });
  });
  Java.perform(function () {
    var File = Java.use("java.io.File");
    var View = Java.use("android.view.View");
    var originalExists = File.exists.overload();
    originalExists.implementation = function () {
      var path = this.getAbsolutePath().toString();
      if (path.indexOf("/su") >= 0 || path.indexOf("/magisk") >= 0 || path.indexOf("/system/xbin") >= 0) {
        modified = true;
        send({type: "root_detection_java_signal_modified", success: true, api: "java.io.File.exists", path_suffix: path.slice(-96), modified_result: false});
        return false;
      }
      return originalExists.call(this);
    };
    send({type: "root_detection_bypass_hooks_installed", success: true, hooks: hookNames.concat(["java.io.File.exists"])});
    Java.choose("android.app.Activity", {
      onMatch: function (activity) {
        try {
          if (!activity.hasWindowFocus()) {
            return;
          }
        } catch (ignored) {
          return;
        }
        var retained = Java.retain(activity);
        Java.scheduleOnMainThread(function () {
          try {
            var id = retained.getResources().getIdentifier("rootCheck", "id", retained.getPackageName());
            var button = id > 0 ? retained.findViewById(id) : null;
            var clicked = false;
            if (button !== null) {
              try {
                clicked = View.performClick.overload().call(button);
              } catch (performError) {
                clicked = View.callOnClick.overload().call(button);
              }
            }
            send({type: "root_detection_check_triggered", success: !!clicked, modified: modified, activity: retained.getClass().getName().toString().slice(0, 255)});
          } catch (error) {
            send({type: "root_detection_check_triggered", success: false, modified: modified, error: String(error).slice(0, 500)});
          }
        });
        return "stop";
      },
      onComplete: function () {
        send({type: "root_detection_activity_search_complete", success: true});
      }
    });
  });
})();
""".strip()

TLS_PINNING_OKHTTP_BYPASS_SOURCE = r"""
Java.perform(function () {
  var hookCount = 0;
  var bypassCount = 0;
  try {
    var CertificatePinner = Java.use("okhttp3.CertificatePinner");
    CertificatePinner.check.overloads.forEach(function (overload) {
      overload.implementation = function () {
        bypassCount += 1;
        send({type: "tls_pinning_check_bypassed", success: true, host: String(arguments[0]).slice(0, 255), overload: overload.argumentTypes.length});
        return;
      };
      hookCount += 1;
    });
  } catch (error) {
    send({type: "tls_pinning_hook_warning", success: false, layer: "okhttp3.CertificatePinner", error: String(error).slice(0, 500)});
  }
  try {
    var X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
    var TrustManager = Java.registerClass({
      name: "org.msap.BoundedProxyTrustManager",
      implements: [X509TrustManager],
      methods: {
        checkClientTrusted: function () {},
        checkServerTrusted: function () {},
        getAcceptedIssuers: function () { return []; }
      }
    });
    var SSLContext = Java.use("javax.net.ssl.SSLContext");
    var originalInit = SSLContext.init.overload(
      "[Ljavax.net.ssl.KeyManager;",
      "[Ljavax.net.ssl.TrustManager;",
      "java.security.SecureRandom"
    );
    originalInit.implementation = function (keyManagers, trustManagers, secureRandom) {
      send({type: "tls_proxy_trust_injected", success: true, scope: "current_process"});
      return originalInit.call(this, keyManagers, [TrustManager.$new()], secureRandom);
    };
    hookCount += 1;
  } catch (error) {
    send({type: "tls_trust_hook_warning", success: false, layer: "SSLContext.init", error: String(error).slice(0, 500)});
  }
  send({type: "tls_pinning_bypass_hooks_installed", success: hookCount > 0, hook_count: hookCount, target_host: "owasp.org"});
  Java.choose("android.app.Activity", {
    onMatch: function (activity) {
      try {
        if (!activity.hasWindowFocus()) {
          return;
        }
      } catch (ignored) {
        return;
      }
      var retained = Java.retain(activity);
      Java.scheduleOnMainThread(function () {
        try {
          var id = retained.getResources().getIdentifier("PinningButton", "id", retained.getPackageName());
          var button = id > 0 ? retained.findViewById(id) : null;
          var clicked = button !== null && button.performClick();
          send({type: "tls_pinned_request_triggered", success: !!clicked, target_host: "owasp.org", activity: retained.getClass().getName().toString().slice(0, 255)});
        } catch (error) {
          send({type: "tls_pinned_request_triggered", success: false, target_host: "owasp.org", error: String(error).slice(0, 500)});
        }
      });
      return "stop";
    },
    onComplete: function () {
      send({type: "tls_activity_search_complete", success: true, target_host: "owasp.org"});
    }
  });
  setTimeout(function () {
    send({type: "tls_pinning_bypass_observation", success: bypassCount > 0, bypass_count: bypassCount, target_host: "owasp.org"});
  }, 2500);
});
""".strip()

EMULATOR_DETECTION_LAB_BYPASS_SOURCE = r"""
Java.perform(function () {
  var Build = Java.use("android.os.Build");
  var replacements = {
    FINGERPRINT: "google/redfin/redfin:14/AP2A.240705.004/12186266:user/release-keys",
    MODEL: "Pixel 7",
    MANUFACTURER: "Google",
    BRAND: "google",
    DEVICE: "panther",
    PRODUCT: "panther",
    HARDWARE: "tensor"
  };
  Object.keys(replacements).forEach(function (name) {
    try {
      var field = Build[name];
      var original = field.value.toString();
      field.value = replacements[name];
      send({type: "lab_emulator_signal_modified", field: name, original: original.slice(0, 96), modified: replacements[name]});
    } catch (ignored) {}
  });
  send({type: "lab_emulator_bypass_applied", template: "EMULATOR_DETECTION_LAB_BYPASS", observation_only_target: true});
});
""".strip()

# Backend-owned registry: automatic planning selects identifiers, never source.
FRIDA_TEMPLATE_REGISTRY = {
    "existing_ui_modification_proof": {
        "source_identifier": "__MSAP_BUILTIN_FRIDA_UI_MODIFICATION_PROOF__",
        "purpose": "Controlled visible-property modification proof",
        "requires_additional_approval": False,
        "source": RUNTIME_UI_MODIFICATION_PROOF_SOURCE,
    },
    "root_signal_observation_template": {
        "source_identifier": "__MSAP_ROOT_SIGNAL_OBSERVATION_TEMPLATE__",
        "purpose": "Observe root-detection signals without bypassing them",
        "requires_additional_approval": True,
        "source": ROOT_SIGNAL_OBSERVATION_SOURCE,
    },
    "emulator_signal_observation_template": {
        "source_identifier": "__MSAP_EMULATOR_SIGNAL_OBSERVATION_TEMPLATE__",
        "purpose": "Observe emulator-detection signals without bypassing them",
        "requires_additional_approval": True,
        "source": EMULATOR_SIGNAL_OBSERVATION_SOURCE,
    },
    "runtime_tamper_resilience_template": {
        "source_identifier": "__MSAP_RUNTIME_TAMPER_RESILIENCE_TEMPLATE__",
        "purpose": "Observe a controlled runtime property change",
        "requires_additional_approval": True,
        "source": "// backend-owned observation template; observation only",
    },
    "root_detection_lab_bypass_template": {
        "source_identifier": "__MSAP_ROOT_DETECTION_LAB_BYPASS_TEMPLATE__",
        "purpose": "Authorized lab-only root-detection resilience modification",
        "requires_additional_approval": True,
        "source": ROOT_DETECTION_LAB_BYPASS_SOURCE,
        "authorized_lab_targets_only": True,
    },
    "root_detection_ui_change_template": {
        "source_identifier": "__MSAP_ROOT_DETECTION_UI_CHANGE_TEMPLATE__",
        "purpose": "Authorized lab-only change of the visible AndroGoat root result",
        "requires_additional_approval": True,
        "source": ROOT_DETECTION_UI_CHANGE_SOURCE,
        "authorized_lab_targets_only": True,
    },
    "root_detection_native_hook_template": {
        "source_identifier": "__MSAP_ROOT_DETECTION_NATIVE_HOOK_TEMPLATE__",
        "purpose": "Authorized lab-only native root-signal instrumentation for AndroGoat",
        "requires_additional_approval": True,
        "source": ROOT_DETECTION_NATIVE_HOOK_SOURCE,
        "authorized_lab_targets_only": True,
    },
    "tls_pinning_okhttp_bypass_template": {
        "source_identifier": "__MSAP_TLS_PINNING_OKHTTP_BYPASS_TEMPLATE__",
        "purpose": "Authorized AndroGoat OkHttp pinning bypass for controlled proxy evidence",
        "requires_additional_approval": True,
        "source": TLS_PINNING_OKHTTP_BYPASS_SOURCE,
        "authorized_lab_targets_only": True,
    },
    "emulator_detection_lab_bypass_template": {
        "source_identifier": "__MSAP_EMULATOR_DETECTION_LAB_BYPASS_TEMPLATE__",
        "purpose": "Authorized lab-only emulator-detection resilience modification",
        "requires_additional_approval": True,
        "source": EMULATOR_DETECTION_LAB_BYPASS_SOURCE,
        "authorized_lab_targets_only": True,
    },
}
APPROVED_FRIDA_SOURCE_IDENTIFIERS = frozenset(
    item["source_identifier"] for item in FRIDA_TEMPLATE_REGISTRY.values()
)
