// Admin API cho KNTM AI – Node/Express + Firebase Admin

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

// ====== Core handler ======
async function adminHandler(req, res) {
  // Lấy action từ URL hoặc Body
  const action = (req.params.action || req.body?.action || req.query?.action || "").trim();
  const data = req.body?.data || {}; // Lấy dữ liệu từ key "data"
  
  console.log("[ADMIN]", { action, by: req.user?.email });

  try {
    // ============================================================
    // 1. QUẢN LÝ USER (CREATE, UPDATE,...)
    // ============================================================
    
    // ---------- CREATE USER ----------
    if (action === "createUser") {
      const { email, password, fullName, role, orgId, departmentId } = data || {};
      if (!email || !password || !fullName || !role || !orgId) {
        return res.status(400).json({ error: "missing fields" });
      }

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
    // 2. GỬI THÔNG BÁO (PHẦN BẠN ĐANG THIẾU)
    // ============================================================
    
    // ---------- SEND NOTIFICATION ----------
    // Đây là đoạn code QUAN TRỌNG để sửa lỗi 400
    if (action === "sendNotification") {
      const { title, body, targetType, targetValue } = data || {};

      if (!title || !body) {
        return res.status(400).json({ error: "Missing title or body" });
      }

      let topic = "ALL";
      if (targetType === "ORG") topic = `ORG_${targetValue}`;
      else if (targetType === "USER") topic = `USER_${targetValue}`;

      const message = {
        topic: topic,
        // Dùng DATA MESSAGE để App tự xử lý hiển thị (ổn định hơn)
        data: {
          title: title,
          body: body,
          targetType: targetType || "ALL",
          targetValue: targetValue || "",
          click_action: "OPEN_MAIN_ACTIVITY",
          docId: String(Date.now())
        },
        android: {
          priority: "high",
          ttl: 3600 * 1000 // 1 giờ
        }
      };

      console.log(`[Notification] Sending to topic: ${topic}`);
      const response = await admin.messaging().send(message);
      console.log("[Notification] Success:", response);
      
      return res.json({ success: true, messageId: response });
    }

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

// Kéo dài timeout
const server = app.listen(process.env.PORT || 3000, () => {
  console.log("Admin API listening on", server.address().port);
});
server.setTimeout(120000);
