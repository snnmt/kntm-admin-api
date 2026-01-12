// Admin API cho KNTM – Node/Express + Firebase Admin

const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const bodyParser = require("body-parser");

const app = express();
app.use(cors());
app.use(bodyParser.json({ limit: "1mb" }));

// ===== Firebase Admin init =====
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: (process.env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n"),
    }),
  });
}
const db = admin.firestore();
const auth = admin.auth();

// ===== Cấu hình super admin qua ENV =====
const SUPER_ADMIN_EMAILS = (process.env.SUPER_ADMINS || "")
  .split(",")
  .map(s => s.trim().toLowerCase())
  .filter(Boolean);

// ===== Helpers =====
const isSuperEmail = (email) => SUPER_ADMIN_EMAILS.includes((email || "").toLowerCase());

async function isTargetSuperadmin(uid) {
  let email = "";
  try {
    const u = await auth.getUser(uid);
    email = (u.email || "").toLowerCase();
  } catch (_) {}

  let role = "";
  try {
    const snap = await db.collection("users").doc(uid).get();
    role = ((snap.exists ? snap.data() : {})?.role || "").toLowerCase();
  } catch (_) {}

  return role === "superadmin" || isSuperEmail(email);
}

// Ping/wake
app.get("/ping", (_req, res) => res.json({ ok: true, ts: Date.now() }));
app.get("/", (_req, res) => res.json({ service: "kntm-admin-api", ok: true }));

// Xác thực bằng Firebase ID token
async function authMiddleware(req, res, next) {
  try {
    const hdr = req.headers.authorization || "";
    if (!hdr.startsWith("Bearer ")) {
      return res.status(401).json({ error: "missing bearer token" });
    }
    const idToken = hdr.slice("Bearer ".length);
    const decoded = await auth.verifyIdToken(idToken);
    req.user = decoded;
    next();
  } catch (e) {
    res.status(401).json({ error: "invalid token", details: String(e?.message || e) });
  }
}

// Yêu cầu quyền admin/superadmin
async function requireAdmin(req, res, next) {
  try {
    const uid = req.user.uid;
    const meDoc = await db.collection("users").doc(uid).get();
    const profile = meDoc.exists ? meDoc.data() : {};
    const role = String(profile.role || "").toLowerCase();
    const email = String(req.user.email || "").toLowerCase();

    const isSuper = role === "superadmin" || isSuperEmail(email);
    const isAdmin = isSuper || role === "admin";

    if (!isAdmin) return res.status(403).json({ error: "forbidden" });

    req.me = {
      ...profile,
      role,
      email,
      isSuper,
      isAdmin,
    };
    next();
  } catch (e) {
    return res.status(500).json({ error: "auth check failed", details: String(e) });
  }
}

app.get("/health", authMiddleware, (_req, res) => res.json({ ok: true }));

// ====== Core handler dùng cho /admin và /admin/:action ======
async function adminHandler(req, res) {
  const action = (req.params.action || req.body?.action || req.query?.action || "").trim();
  const data = req.body?.data || {};
  console.log("[ADMIN]", { action, by: req.user?.email, dataKeys: Object.keys(data) });

  try {
    // ============================================================
    // 1. USER MANAGEMENT (CREATE, UPDATE, RESET, DELETE)
    // ============================================================

    // ---------- CREATE USER ----------
    if (action === "createUser") {
      const { email, password, fullName, role, orgId, departmentId } = data || {};
      if (!email || !password || !fullName || !role || !orgId) {
        return res.status(400).json({ error: "missing fields" });
      }

      // Admin thường chỉ tạo trong Org của mình
      if (!req.me.isSuper) {
        if (!req.me.orgId || orgId !== req.me.orgId) {
          return res.status(403).json({ error: "admin can only create in own org" });
        }
        if (String(role).toLowerCase() === "superadmin" || isSuperEmail(email)) {
          return res.status(403).json({ error: "admin cannot create superadmin" });
        }
      }

      const userRecord = await auth.createUser({
        email,
        password,
        displayName: fullName,
        emailVerified: false,
        disabled: false,
      });

      const payload = {
        uid: userRecord.uid,
        email: (email || "").toLowerCase(),
        fullName,
        role: String(role || "user").toLowerCase(),
        orgId,
        departmentId: departmentId || null,
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
      };
      await db.collection("users").doc(userRecord.uid).set(payload, { merge: true });
      return res.json({ uid: userRecord.uid });
    }

    // ---------- UPDATE USER ----------
    if (action === "updateUser") {
      const { uid, ...rest } = data || {};
      if (!uid) return res.status(400).json({ error: "missing uid" });

      if (!req.me.isSuper && await isTargetSuperadmin(uid)) {
        return res.status(403).json({ error: "cannot modify superadmin" });
      }

      if (!req.me.isSuper) {
        if (rest.role && String(rest.role).toLowerCase() === "superadmin") {
          return res.status(403).json({ error: "cannot promote to superadmin" });
        }
        if (rest.email && isSuperEmail(rest.email)) {
          return res.status(403).json({ error: "cannot set email of superadmin" });
        }
        // Giới hạn chuyển Org
        if (rest.orgId && (!req.me.orgId || rest.orgId !== req.me.orgId)) {
          return res.status(403).json({ error: "admin can only move within own org" });
        }
      }

      await db.collection("users").doc(uid).set(rest, { merge: true });
      try {
        const updates = {};
        if (rest.fullName) updates.displayName = rest.fullName;
        if (rest.email) updates.email = rest.email;
        if (Object.keys(updates).length) await auth.updateUser(uid, updates);
      } catch (_) {}
      return res.json({ ok: true });
    }

    // ---------- RESET/SET PASSWORD ----------
    if (["setPassword", "resetPassword", "adminResetPassword"].includes(action)) {
      const { uid, password, newPassword } = data || {};
      const pwd = password || newPassword;
      if (!uid || !pwd) return res.status(400).json({ error: "missing uid/password" });

      if (!req.me.isSuper && await isTargetSuperadmin(uid)) {
        return res.status(403).json({ error: "cannot change password of superadmin" });
      }

      if (!req.me.isSuper) {
        const targetSnap = await db.collection("users").doc(uid).get();
        if (!targetSnap.exists) {
          return res.status(403).json({ error: "only superadmin can reset users without profile" });
        }
        const target = targetSnap.data() || {};
        if (!req.me.orgId || target.orgId !== req.me.orgId) {
          return res.status(403).json({ error: "admin can only reset password within own org" });
        }
      }

      try {
        await auth.updateUser(uid, { password: pwd });
        return res.json({ ok: true });
      } catch (e) {
        return res.status(500).json({ error: "updateUser failed", details: String(e.message) });
      }
    }

    // ---------- DELETE USER ----------
    if (action === "deleteUser") {
      const { uid, cascade } = data || {};
      if (!uid) return res.status(400).json({ error: "missing uid" });

      if (!req.me.isSuper && await isTargetSuperadmin(uid)) {
        return res.status(403).json({ error: "cannot delete superadmin" });
      }

      await db.collection("users").doc(uid).delete().catch(() => {});
      try { await auth.deleteUser(uid); } catch (_) {}

      if (cascade) {
        const qs = await db.collection("schedules").where("createdBy", "==", uid).get();
        const batch = db.batch();
        qs.forEach(d => batch.delete(d.ref));
        await batch.commit();
      }
      return res.json({ ok: true });
    }

    // ============================================================
    // 2. ORGANIZATION MANAGEMENT (MỚI BỔ SUNG)
    // ============================================================

    // ---------- CREATE ORGANIZATION ----------
    if (action === "createOrganization") {
      if (!req.me.isSuper) return res.status(403).json({ error: "only superadmin" });

      const { id, name, code, status } = data || {};
      if (!id || !name) return res.status(400).json({ error: "missing id/name" });

      await db.collection("organizations").doc(id).set({
        id,
        name,
        code: code || "",
        status: status || "active",
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });

      return res.json({ ok: true, id });
    }

    // ---------- DELETE ORGANIZATION ----------
    if (action === "deleteOrganization") {
      if (!req.me.isSuper) return res.status(403).json({ error: "only superadmin" });
      const { id } = data || {};
      if (!id) return res.status(400).json({ error: "missing id" });

      // Có thể thêm logic check có user/dept nào thuộc org này không để chặn xóa
      await db.collection("organizations").doc(id).delete();
      return res.json({ ok: true });
    }

    // ============================================================
    // 3. DEPARTMENT MANAGEMENT (MỚI BỔ SUNG)
    // ============================================================

    // ---------- CREATE DEPARTMENT ----------
    if (action === "createDepartment") {
      const { id, name, orgId } = data || {};
      if (!id || !name || !orgId) return res.status(400).json({ error: "missing fields" });

      // SuperAdmin: Tạo đâu cũng được
      // Admin: Chỉ được tạo cho Org của mình
      if (!req.me.isSuper) {
        if (!req.me.orgId || orgId !== req.me.orgId) {
          return res.status(403).json({ error: "admin can only create dept in own org" });
        }
      }

      await db.collection("departments").doc(id).set({
        id,
        name,
        orgId,
        createdAt: admin.firestore.FieldValue.serverTimestamp()
      }, { merge: true });

      return res.json({ ok: true, id });
    }

    // ---------- DELETE DEPARTMENT ----------
    if (action === "deleteDepartment") {
      const { id } = data || {};
      if (!id) return res.status(400).json({ error: "missing id" });

      // Check quyền admin thường
      if (!req.me.isSuper) {
        const deptSnap = await db.collection("departments").doc(id).get();
        if (deptSnap.exists) {
          const deptData = deptSnap.data();
          if (!req.me.orgId || deptData.orgId !== req.me.orgId) {
            return res.status(403).json({ error: "admin can only delete dept in own org" });
          }
        }
      }

      await db.collection("departments").doc(id).delete();
      return res.json({ ok: true });
    }


// ... (Các đoạn code quản lý user, organization, department ở trên giữ nguyên) ...

    // ============================================================
    // 4. NOTIFICATION MANAGEMENT (MỚI THÊM VÀO ĐÂY)
    // ============================================================

    // ---------- SEND NOTIFICATION (DATA-ONLY) ----------
    if (action === "sendNotification") {
      const { title, body, targetType, targetValue } = data || {};

      // 1. Validate dữ liệu
      if (!title || !body) {
        return res.status(400).json({ error: "Missing title or body" });
      }

      // 2. Xác định Topic nhận tin
      let topic = "ALL";
      if (targetType === "ORG") topic = `ORG_${targetValue}`;
      else if (targetType === "USER") topic = `USER_${targetValue}`;

      // 3. Cấu trúc tin nhắn DATA-ONLY (Quan trọng: KHÔNG có key "notification")
      const message = {
        topic: topic,
        android: {
          priority: "high", // Đánh thức máy kể cả khi tắt màn hình
          ttl: 3600 * 1000 // Thời gian sống của tin nhắn (1 giờ)
        },
        data: {
          title: title,
          body: body,
          targetType: targetType || "ALL",
          targetValue: targetValue || "",
          click_action: "OPEN_MAIN_ACTIVITY", // Action để Android bắt được
          docId: String(Date.now()) // ID giả để App không bị crash nếu cần ID
        }
      };

      console.log(`[Notification] Sending to topic: ${topic}`);

      // 4. Gửi tin bằng Admin SDK
      const response = await admin.messaging().send(message);
      console.log("[Notification] Success:", response);
      
      return res.json({ success: true, messageId: response });
    }

    // ---------- UNKNOWN ACTION ----------
    // return res.status(400).json({ error: "unknown action: " + action });
    
    // ---------- UNKNOWN ACTION ----------
    return res.status(400).json({ error: "unknown action: " + action });

  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "server error", details: String(e?.message || e) });
  }
}

// Nhận cả dạng body action lẫn path action
app.post("/admin", authMiddleware, requireAdmin, adminHandler);
app.post("/admin/:action", authMiddleware, requireAdmin, adminHandler);

// Kéo dài timeout tránh cold-start cắt sớm (Render free plan)
const server = app.listen(process.env.PORT || 3000, () => {
  console.log("Admin API listening on", server.address().port);
});
server.setTimeout(120000);
