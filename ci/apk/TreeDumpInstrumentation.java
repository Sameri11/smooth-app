package org.rulesflutter.apkcheck.treedump;

import android.app.Activity;
import android.app.Instrumentation;
import android.app.UiAutomation;
import android.graphics.Rect;
import android.os.Bundle;
import android.util.Xml;
import android.view.accessibility.AccessibilityNodeInfo;

import org.xmlpull.v1.XmlSerializer;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.regex.Pattern;

/**
 * Writes the active window's accessibility tree to a file in the app's private directory.
 *
 * Reads getRootInActiveWindow() directly, so the snapshot is taken from the current tree
 * without waiting for the window to go quiet. Children that are not visible to the user are
 * skipped, as the AOSP accessibility dumper does; the root is always written. A null child
 * fails the snapshot instead of being skipped, so the driver never accepts a partial tree.
 * Instrumentation.finish() disconnects the UiAutomation obtained through getUiAutomation().
 *
 * The output file name carries the request token passed as the "token" argument, so a
 * snapshot left by an earlier or cancelled request can never be mistaken for this one.
 * The XML attributes are the ones the driver parses: text, content-desc, class, bounds, clickable.
 */
public final class TreeDumpInstrumentation extends Instrumentation {
    static final String SNAPSHOT_PREFIX = "window_dump-";
    private static final Pattern TOKEN = Pattern.compile("[0-9a-f]{32}");
    private static final int MAX_NODES = 50000;

    private String token;
    private int nodeCount;

    @Override
    public void onCreate(Bundle arguments) {
        super.onCreate(arguments);
        token = arguments == null ? null : arguments.getString("token");
        start();
    }

    @Override
    public void onStart() {
        Bundle result = new Bundle();
        int code = Activity.RESULT_CANCELED;
        File temp = null;
        try {
            if (token == null || !TOKEN.matcher(token).matches()) {
                throw new IllegalStateException("missing or invalid request token");
            }
            UiAutomation automation = getUiAutomation();
            AccessibilityNodeInfo root = automation.getRootInActiveWindow();
            if (root == null) {
                throw new IllegalStateException("null root node from the active window");
            }
            File directory = getTargetContext().getFilesDir();
            File target = new File(directory, SNAPSHOT_PREFIX + token + ".xml");
            temp = new File(directory, SNAPSHOT_PREFIX + token + ".tmp");
            try (OutputStream out = new FileOutputStream(temp)) {
                write(root, out);
            }
            if (!temp.renameTo(target)) {
                throw new IllegalStateException("could not publish " + target);
            }
            result.putString("token", token);
            result.putInt("nodes", nodeCount);
            result.putLong("bytes", target.length());
            code = Activity.RESULT_OK;
        } catch (Throwable error) {
            result.putString("error", String.valueOf(error));
        } finally {
            if (temp != null) {
                temp.delete();
            }
            finish(code, result);
        }
    }

    private void write(AccessibilityNodeInfo root, OutputStream out) throws IOException {
        XmlSerializer serializer = Xml.newSerializer();
        serializer.setOutput(out, "UTF-8");
        serializer.startDocument("UTF-8", true);
        serializer.startTag("", "hierarchy");
        dumpNode(root, 0, serializer);
        serializer.endTag("", "hierarchy");
        serializer.endDocument();
    }

    private void dumpNode(AccessibilityNodeInfo node, int index, XmlSerializer serializer) throws IOException {
        if (++nodeCount > MAX_NODES) {
            throw new IllegalStateException("accessibility tree exceeds " + MAX_NODES + " nodes");
        }
        serializer.startTag("", "node");
        attribute(serializer, "index", String.valueOf(index));
        attribute(serializer, "text", node.getText());
        attribute(serializer, "resource-id", node.getViewIdResourceName());
        attribute(serializer, "class", node.getClassName());
        attribute(serializer, "package", node.getPackageName());
        attribute(serializer, "content-desc", node.getContentDescription());
        attribute(serializer, "checkable", node.isCheckable());
        attribute(serializer, "checked", node.isChecked());
        attribute(serializer, "clickable", node.isClickable());
        attribute(serializer, "enabled", node.isEnabled());
        attribute(serializer, "focusable", node.isFocusable());
        attribute(serializer, "focused", node.isFocused());
        attribute(serializer, "scrollable", node.isScrollable());
        attribute(serializer, "long-clickable", node.isLongClickable());
        attribute(serializer, "password", node.isPassword());
        attribute(serializer, "selected", node.isSelected());
        Rect bounds = new Rect();
        node.getBoundsInScreen(bounds);
        attribute(serializer, "bounds",
                String.format("[%d,%d][%d,%d]", bounds.left, bounds.top, bounds.right, bounds.bottom));
        int count = node.getChildCount();
        for (int i = 0; i < count; i++) {
            AccessibilityNodeInfo child = node.getChild(i);
            if (child == null) {
                throw new IllegalStateException("child " + i + "/" + count + " of node " + nodeCount + " unavailable");
            }
            if (!child.isVisibleToUser()) {
                continue;
            }
            dumpNode(child, i, serializer);
        }
        serializer.endTag("", "node");
    }

    private static void attribute(XmlSerializer serializer, String name, CharSequence value) throws IOException {
        serializer.attribute("", name, value == null ? "" : value.toString());
    }

    private static void attribute(XmlSerializer serializer, String name, boolean value) throws IOException {
        serializer.attribute("", name, value ? "true" : "false");
    }
}
