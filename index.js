// index.js
// Admin API cho Lịch Công Tác – Node/Express + Firebase Admin

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
  // Lấy email từ Firebase Auth
  let email = "";
  try {
    const u = await auth.getUser(uid);
    email = (u.email || "").toLowerCase();
  } catch (_) {}

  // Lấy role từ Firestore (nếu có)
  let role = "";
  try {
    const snap = await db.collection("users").doc(uid).get();
    role = ((snap.exists ? snap.data() : {})?.role || "").toLowerCase();
  } catch (_) {}

  return role === "superadmin" || isSuperEmail(email);
}

// Ping/wake
app.get("/ping", (_req, res) => res.json({ ok: true, ts: Date.now() }));
app.get("/", (_req, res) => res.json({ service: "lichcongtac-admin-api", ok: true }));

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

    // gắn thông tin lên req
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
    // ---------- CREATE USER ----------
    if (action === "createUser") {
      const { email, password, fullName, role, orgId, departmentId } = data || {};
      if (!email || !password || !fullName || !role || !orgId) {
        return res.status(400).json({ error: "missing fields" });
      }

      // admin chỉ được tạo trong org của mình và KHÔNG được tạo superadmin/hoặc email thuộc SUPER_ADMIN_EMAILS
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

      // admin không được sửa superadmin
      if (!req.me.isSuper && await isTargetSuperadmin(uid)) {
        return res.status(403).json({ error: "cannot modify superadmin" });
      }

      // admin không được promote thành superadmin hoặc đổi email thành email superadmin
      if (!req.me.isSuper) {
        if (rest.role && String(rest.role).toLowerCase() === "superadmin") {
          return res.status(403).json({ error: "cannot promote to superadmin" });
        }
        if (rest.email && isSuperEmail(rest.email)) {
          return res.status(403).json({ error: "cannot set email of superadmin" });
        }
      }

      // Giới hạn org khi admin cập nhật
      if (!req.me.isSuper && rest.orgId) {
        if (!req.me.orgId || rest.orgId !== req.me.orgId) {
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

      // admin không được đổi mật khẩu superadmin
      if (!req.me.isSuper && await isTargetSuperadmin(uid)) {
        return res.status(403).json({ error: "cannot change password of superadmin" });
      }

      // Nếu là admin thường thì chỉ reset trong org của mình và chỉ khi có profile
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
        const msg = String(e?.message || e);
        if (msg.includes("auth/user-not-found")) {
          return res.status(404).json({ error: "auth user not found" });
        }
        return res.status(500).json({ error: "updateUser failed", details: msg });
      }
    }

    // ---------- DELETE USER ----------
    if (action === "deleteUser") {
      const { uid, cascade } = data || {};
      if (!uid) return res.status(400).json({ error: "missing uid" });

      // admin không được xoá superadmin
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

    // ---------- Unknown ----------
    return res.status(400).json({ error: "unknown action" });
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
