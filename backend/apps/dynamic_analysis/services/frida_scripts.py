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
