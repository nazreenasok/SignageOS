import asyncio
import json
import os
import shutil
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Dict, List, Optional

import uvicorn
from fastapi import FastAPI, HTTPException, Request, UploadFile, File, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from database import Database, verify_password, USE_PG

def get_token(request: Request) -> Optional[str]:
    auth = request.headers.get("Authorization", "")
    if auth.startswith("Bearer "):
        return auth[7:]
    return request.cookies.get("session_token")

def require_auth(request: Request):
    token = get_token(request)
    if not token:
        raise HTTPException(401, "Not authenticated")
    session = db.verify_session(token)
    if not session:
        raise HTTPException(401, "Session expired")
    return session

def require_superadmin(request: Request):
    session = require_auth(request)
    if session["role"] != "superadmin":
        raise HTTPException(403, "Superadmin required")
    return session

CLOUDINARY_CONFIGURED = all([
    os.environ.get("CLOUDINARY_CLOUD_NAME"),
    os.environ.get("CLOUDINARY_API_KEY"),
    os.environ.get("CLOUDINARY_API_SECRET"),
])
if CLOUDINARY_CONFIGURED:
    import cloudinary
    import cloudinary.uploader
    cloudinary.config(
        cloud_name = os.environ.get("CLOUDINARY_CLOUD_NAME"),
        api_key    = os.environ.get("CLOUDINARY_API_KEY"),
        api_secret = os.environ.get("CLOUDINARY_API_SECRET"),
        secure     = True,
    )

AUTO_APPROVE_HOUR = int(os.environ.get("AUTO_APPROVE_HOUR", "9"))

LOGIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>SignageOS — Login</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{--bg:#0c0c10;--surface:#15151d;--border:rgba(255,255,255,0.08);--border2:rgba(255,255,255,0.14);--text:#ededf0;--muted:#777;--accent:#f59e0b;--red:#ef4444}
body{background:var(--bg);color:var(--text);font-family:'Segoe UI',system-ui,sans-serif;min-height:100vh;display:flex;align-items:center;justify-content:center}
.box{background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:36px;width:100%;max-width:360px}
.logo{display:flex;align-items:center;gap:10px;margin-bottom:28px;justify-content:center}
.logo-icon{width:36px;height:36px;border-radius:10px;background:var(--accent);display:flex;align-items:center;justify-content:center;font-size:18px}
.logo-name{font-size:18px;font-weight:700}
label{display:block;font-size:11px;color:var(--muted);margin-bottom:5px;margin-top:14px}
input{width:100%;padding:10px 12px;border-radius:8px;border:1px solid var(--border2);background:#1e1e28;color:var(--text);font-size:14px;outline:none}
input:focus{border-color:var(--accent)}
.btn{width:100%;margin-top:20px;padding:11px;border-radius:8px;border:none;background:var(--accent);color:#000;font-weight:700;font-size:14px;cursor:pointer}
.btn:hover{background:#d97706}
.err{color:var(--red);font-size:12px;margin-top:10px;text-align:center;display:none}
.hint{font-size:11px;color:var(--muted);text-align:center;margin-top:14px}
code{background:#1e1e28;padding:2px 6px;border-radius:4px;font-family:monospace;font-size:11px;color:var(--accent)}
</style>
</head>
<body>
<div class="box">
  <div class="logo">
    <div class="logo-icon">📺</div>
    <div class="logo-name">SignageOS</div>
  </div>
  <label>Username</label>
  <input type="text" id="username" placeholder="admin" autocomplete="username"/>
  <label>Password</label>
  <input type="password" id="password" placeholder="••••••••" autocomplete="current-password" onkeydown="if(event.key==='Enter')login()"/>
  <button class="btn" onclick="login()">Sign In</button>
  <div class="err" id="err">Invalid username or password</div>
  <div class="hint">Default credentials: <code>admin</code> / <code>admin123</code></div>
</div>
<script>
async function login(){
  const username=document.getElementById('username').value.trim();
  const password=document.getElementById('password').value;
  const err=document.getElementById('err');
  err.style.display='none';
  if(!username||!password)return;
  const r=await fetch('/api/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password})});
  if(r.ok){
    const data=await r.json();
    localStorage.setItem('signage_token',data.token);
    localStorage.setItem('signage_role',data.role);
    localStorage.setItem('signage_username',data.username);
    location.href='/';
  } else {
    const errData = await r.json().catch(()=>({}));
    const errMsg = errData.detail || JSON.stringify(errData) || 'Login failed';
    err.textContent = typeof errMsg === 'string' ? errMsg : JSON.stringify(errMsg);
    err.style.display='block';
  }
}
if(localStorage.getItem('signage_token')) location.href='/';
</script>
</body>
</html>"""

ADMIN_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<title>SignageOS — Admin</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0c0c10;--surface:#15151d;--surface2:#1e1e28;
  --border:rgba(255,255,255,0.07);--border2:rgba(255,255,255,0.13);
  --text:#ededf0;--muted:#777;--muted2:#555;
  --accent:#f59e0b;--accent-dim:rgba(245,158,11,0.12);
  --red:#ef4444;--blue:#3b82f6;--purple:#8b5cf6;--green:#22c55e;--teal:#14b8a6;
  --r:10px;--font:'Segoe UI',system-ui,sans-serif;--mono:'Consolas',monospace;
}
body{background:var(--bg);color:var(--text);font-family:var(--font);min-height:100vh;display:flex;flex-direction:column}
.hdr{background:var(--surface);border-bottom:1px solid var(--border);padding:12px 20px;display:flex;align-items:center;justify-content:space-between;flex-shrink:0}
.logo{display:flex;align-items:center;gap:10px}
.logo-icon{width:30px;height:30px;border-radius:8px;background:var(--accent);display:flex;align-items:center;justify-content:center;font-size:15px}
.logo-name{font-size:15px;font-weight:600}
.logo-sub{font-size:10px;color:var(--muted);font-family:var(--mono);margin-top:1px}
.hdr-right{display:flex;gap:8px;align-items:center}
.ws-pill{font-size:10px;font-family:var(--mono);padding:3px 9px;border-radius:20px;border:1px solid}
.ws-ok{border-color:rgba(34,197,94,.3);background:rgba(34,197,94,.1);color:#22c55e}
.ws-bad{border-color:rgba(239,68,68,.3);background:rgba(239,68,68,.1);color:#ef4444}
.btn{border:none;border-radius:8px;padding:8px 16px;font-size:12px;font-weight:600;cursor:pointer;text-decoration:none;display:inline-flex;align-items:center;gap:5px}
.btn-accent{background:var(--accent);color:#000}.btn-accent:hover{background:#d97706}
.btn-ghost{background:none;border:1px solid var(--border2);color:var(--text)}.btn-ghost:hover{border-color:var(--accent);color:var(--accent)}
.btn-danger{background:rgba(239,68,68,.12);border:1px solid rgba(239,68,68,.25);color:var(--red)}.btn-danger:hover{background:rgba(239,68,68,.2)}
.btn-sm{padding:5px 10px;font-size:11px;border-radius:6px}
.tabs{display:flex;gap:2px;background:var(--surface);border-bottom:1px solid var(--border);padding:0 20px;flex-shrink:0}
.tab{padding:11px 18px;font-size:12px;font-weight:600;color:var(--muted);border:none;background:none;cursor:pointer;border-bottom:2px solid transparent;transition:all .15s}
.tab.active{color:var(--accent);border-bottom-color:var(--accent)}.tab:hover:not(.active){color:var(--text)}
.content{display:none;flex:1;overflow:hidden}.content.active{display:flex}
.two-col{display:grid;grid-template-columns:340px 1fr;flex:1;min-height:0}
.sidebar{border-right:1px solid var(--border);overflow-y:auto;display:flex;flex-direction:column}
.main-panel{overflow-y:auto;padding:20px}
.sec-label{font-size:10px;font-weight:600;color:var(--muted);letter-spacing:1.5px;text-transform:uppercase;margin-bottom:10px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:14px}
.slide-item{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:9px 11px;display:flex;align-items:center;gap:9px;transition:border-color .15s}
.slide-item:hover{border-color:var(--border2)}.slide-item.disabled{opacity:.45}
.thumb{width:52px;height:36px;border-radius:5px;overflow:hidden;flex-shrink:0;background:#1a1a25;display:flex;align-items:center;justify-content:center;font-size:16px}
.thumb img{width:100%;height:100%;object-fit:cover;display:block}
.slide-info{flex:1;min-width:0}
.slide-title{font-size:12px;font-weight:500;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.slide-meta{display:flex;gap:5px;align-items:center;margin-top:3px;flex-wrap:wrap}
.badge{font-size:9px;font-weight:700;padding:2px 7px;border-radius:4px;text-transform:uppercase;letter-spacing:.5px}
.badge-youtube{background:rgba(239,68,68,.15);color:#f87171}
.badge-image{background:rgba(59,130,246,.15);color:#60a5fa}
.badge-video{background:rgba(139,92,246,.15);color:#a78bfa}
.badge-sched{background:rgba(20,184,166,.15);color:#2dd4bf}
.badge-off{background:rgba(100,100,100,.2);color:var(--muted)}
.badge-interrupt{background:rgba(245,158,11,.15);color:#fbbf24}
.slide-dur{font-size:10px;color:var(--muted);font-family:var(--mono)}
.sort-col{display:flex;flex-direction:column;gap:2px}
.sort-btn{border:1px solid var(--border);background:none;border-radius:4px;width:20px;height:17px;cursor:pointer;color:var(--muted);font-size:8px;display:flex;align-items:center;justify-content:center}
.sort-btn:hover:not(:disabled){border-color:var(--border2);color:var(--text)}.sort-btn:disabled{opacity:.2;cursor:default}
.icon-btn{border:none;background:none;cursor:pointer;padding:3px 5px;border-radius:4px;font-size:13px;line-height:1;opacity:.6}.icon-btn:hover{opacity:1}
.form-group{margin-bottom:10px}.form-group label{display:block;font-size:11px;color:var(--muted);margin-bottom:4px}
.inp{width:100%;padding:8px 10px;border-radius:7px;border:1px solid var(--border2);background:var(--surface);color:var(--text);font-size:12px;outline:none;font-family:var(--mono)}
.inp:focus{border-color:var(--accent)}.inp::placeholder{color:var(--muted2)}
.inp-reg{font-family:var(--font)}.inp-sm{width:80px}
.row{display:flex;gap:8px;align-items:flex-end}
.type-grid{display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:4px;margin-bottom:10px}
.type-btn{padding:7px 2px;border-radius:6px;border:1.5px solid var(--border);background:none;color:var(--muted);font-size:10px;font-weight:600;cursor:pointer;text-align:center;transition:all .15s}
.type-btn.act-youtube{border-color:var(--red);background:rgba(239,68,68,.1);color:#f87171}
.type-btn.act-image{border-color:var(--blue);background:rgba(59,130,246,.1);color:#60a5fa}
.type-btn.act-video{border-color:var(--purple);background:rgba(139,92,246,.1);color:#a78bfa}
.type-btn.act-upload{border-color:var(--teal);background:rgba(20,184,166,.1);color:#2dd4bf}
.sched-toggle{font-size:11px;color:var(--teal);cursor:pointer;text-decoration:underline;margin-bottom:8px;display:inline-block}
.sched-panel{background:rgba(20,184,166,.06);border:1px solid rgba(20,184,166,.2);border-radius:8px;padding:12px;margin-bottom:10px;display:none}
.sched-panel.open{display:block}
.day-grid{display:flex;gap:4px;flex-wrap:wrap;margin-top:4px}
.day-btn{padding:4px 8px;border-radius:5px;border:1px solid var(--border2);background:none;color:var(--muted);font-size:10px;cursor:pointer}
.day-btn.sel{border-color:var(--teal);background:rgba(20,184,166,.15);color:#2dd4bf}
.divider{height:1px;background:var(--border);margin:12px 0}
.upload-zone{border:1.5px dashed var(--border2);border-radius:8px;padding:18px;text-align:center;cursor:pointer;transition:border-color .15s}
.upload-zone:hover,.upload-zone.drag{border-color:var(--teal);background:rgba(20,184,166,.05)}
.upload-zone p{font-size:12px;color:var(--muted);margin-top:4px}
.screen-item{background:var(--surface2);border:1px solid var(--border);border-radius:8px;padding:11px 14px;display:flex;align-items:center;gap:12px;margin-bottom:8px}
.screen-dot{width:9px;height:9px;border-radius:50%;flex-shrink:0}
.dot-online{background:var(--green);box-shadow:0 0 0 3px rgba(34,197,94,.2)}.dot-offline{background:var(--muted2)}
.screen-info{flex:1;min-width:0}
.screen-name{font-size:13px;font-weight:500}
.screen-sub{font-size:10px;color:var(--muted);font-family:var(--mono);margin-top:2px}
.screen-actions{display:flex;gap:5px}
select.inp{cursor:pointer}
.group-card{background:var(--surface2);border:1px solid var(--border);border-radius:var(--r);padding:14px;margin-bottom:8px}
.group-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}
.group-name{font-size:13px;font-weight:600}.group-meta{font-size:10px;color:var(--muted)}
.tv-grid{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin-bottom:20px}
.tv-box{border-radius:8px;overflow:hidden;border:1.5px solid var(--border);background:#0a0a10;position:relative;aspect-ratio:16/9;cursor:pointer}
.tv-box img{width:100%;height:100%;object-fit:cover;display:block;opacity:.8}
.tv-ph{width:100%;height:100%;display:flex;align-items:center;justify-content:center;font-size:16px;opacity:.2}
.tv-grad{position:absolute;inset:0;background:linear-gradient(to top,rgba(0,0,0,.75) 0%,transparent 55%)}
.tv-lbl{position:absolute;bottom:4px;left:6px;right:6px;display:flex;justify-content:space-between;align-items:flex-end}
.tv-num{font-size:9px;color:rgba(255,255,255,.75);font-family:var(--mono)}
.tv-status{font-size:9px;font-family:var(--mono)}.tv-online{color:var(--accent)}.tv-offline{color:var(--muted2)}
.now-bar{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:12px 16px;display:flex;align-items:center;gap:12px;margin-bottom:14px}
.now-dot{width:9px;height:9px;border-radius:50%;background:var(--accent);flex-shrink:0}
.deploy{background:var(--surface);border:1px solid var(--border);border-radius:var(--r);padding:14px}
.deploy ol{list-style:none;display:flex;flex-direction:column;gap:7px;margin-top:8px}
.deploy li{font-size:12px;color:var(--muted);display:flex;gap:10px;line-height:1.6}
.step{font-family:var(--mono);font-size:10px;background:var(--surface2);padding:2px 6px;border-radius:4px;flex-shrink:0;margin-top:2px}
code{font-family:var(--mono);background:var(--surface2);padding:1px 5px;border-radius:4px;font-size:11px;color:#60a5fa}
.pl-row{display:flex;gap:6px;align-items:center;margin-bottom:14px;flex-wrap:wrap}
.pl-chip{padding:6px 12px;border-radius:20px;border:1px solid var(--border2);background:none;color:var(--muted);font-size:11px;cursor:pointer;font-weight:500}
.pl-chip.active{border-color:var(--accent);background:var(--accent-dim);color:var(--accent)}
.pl-chip:hover:not(.active){color:var(--text)}
.progress-wrap{height:3px;background:var(--border);border-radius:2px;overflow:hidden;margin-top:6px}
.progress-bar{height:100%;background:var(--accent);border-radius:2px;transition:width .3s}
#toast{position:fixed;bottom:20px;right:20px;z-index:999;display:flex;flex-direction:column;gap:6px}
.toast{background:var(--surface2);border:1px solid var(--border2);border-radius:8px;padding:10px 16px;font-size:12px;animation:slideIn .2s ease;max-width:280px}
.toast.success{border-color:rgba(34,197,94,.3);color:#4ade80}.toast.error{border-color:rgba(239,68,68,.3);color:#f87171}
@keyframes slideIn{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
::-webkit-scrollbar{width:5px}::-webkit-scrollbar-track{background:transparent}::-webkit-scrollbar-thumb{background:var(--border2);border-radius:3px}
</style>
</head>
<body>
<header class="hdr">
  <div class="logo">
    <div class="logo-icon">📺</div>
    <div><div class="logo-name">SignageOS</div><div class="logo-sub" id="hdr-sub">connecting...</div></div>
  </div>
  <div class="hdr-right">
    <span class="ws-pill ws-bad" id="ws-ind">⬤ offline</span>
    <span style="font-size:11px;color:var(--muted);font-family:var(--mono)" id="user-pill">—</span>
    <button onclick="openDisplay()" class="btn btn-ghost btn-sm">Open Display ↗</button>
    <button class="btn btn-ghost btn-sm" onclick="showChangePassword()">🔑 Password</button>
    <button class="btn btn-danger btn-sm" onclick="logout()">Sign Out</button>
  </div>
</header>
<nav class="tabs">
  <button class="tab active" onclick="openTab('playlist')" id="tab-playlist">Playlists</button>
  <button class="tab" onclick="openTab('screens')" id="tab-screens">Screens</button>
  <button class="tab" onclick="openTab('groups')" id="tab-groups">Groups</button>
  <button class="tab" onclick="openTab('admins')" id="tab-admins" style="display:none">Admins</button>
</nav>
<div class="content active" id="content-playlist">
  <div class="two-col">
    <div class="sidebar" style="padding:14px">
      <div class="sec-label">Playlists</div>
      <div class="pl-row" id="pl-chips"></div>
      <div style="display:flex;gap:6px;margin-bottom:14px">
        <input class="inp inp-reg" id="new-pl-name" placeholder="New playlist name" style="flex:1"/>
        <button class="btn btn-ghost btn-sm" onclick="createPlaylist()">+ Create</button>
      </div>
      <div class="divider"></div>
      <div id="fallback-card" style="display:none;margin-bottom:12px">
        <div style="background:rgba(245,158,11,.07);border:1px solid rgba(245,158,11,.25);border-radius:10px;padding:13px">
          <div style="font-size:10px;color:#fbbf24;font-weight:600;letter-spacing:1px;margin-bottom:10px">⚡ YOUTUBE FALLBACK</div>
          <div class="form-group">
            <label>YouTube Live URL</label>
            <input class="inp" id="fb-url" placeholder="https://youtube.com/watch?v=..." style="font-size:11px"/>
          </div>
          <div style="display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-bottom:10px">
            <div>
              <label style="font-size:10px;color:var(--muted);display:block;margin-bottom:4px">Loop content for</label>
              <div style="display:flex;gap:4px;align-items:center">
                <input class="inp" id="fb-loop-h" type="number" min="0" max="23" value="0" style="width:46px;text-align:center" oninput="updateFbPreview()"/>
                <span style="color:var(--muted);font-size:10px">h</span>
                <input class="inp" id="fb-loop-m" type="number" min="0" max="59" value="30" style="width:46px;text-align:center" oninput="updateFbPreview()"/>
                <span style="color:var(--muted);font-size:10px">m</span>
              </div>
            </div>
            <div>
              <label style="font-size:10px;color:var(--muted);display:block;margin-bottom:4px">Then play YouTube for</label>
              <div style="display:flex;gap:4px;align-items:center">
                <input class="inp" id="fb-for-m" type="number" min="0" max="59" value="5" style="width:46px;text-align:center" oninput="updateFbPreview()"/>
                <span style="color:var(--muted);font-size:10px">m</span>
                <input class="inp" id="fb-for-s" type="number" min="0" max="59" value="0" style="width:46px;text-align:center" oninput="updateFbPreview()"/>
                <span style="color:var(--muted);font-size:10px">s</span>
              </div>
            </div>
          </div>
          <div style="font-size:10px;color:var(--accent);font-family:var(--mono);margin-bottom:10px" id="fb-preview">Loop 30m → YouTube 5m → repeat</div>
          <button class="btn btn-accent" style="width:100%;font-size:12px" onclick="saveFallback()">Save Fallback Settings</button>
          <button class="btn btn-ghost" style="width:100%;font-size:11px;margin-top:5px" onclick="clearFallback()">✕ Remove Fallback</button>
        </div>
      </div>
      <div class="sec-label" style="margin-top:12px">Slides in playlist</div>
      <div id="slides-list" style="display:flex;flex-direction:column;gap:6px;margin-bottom:10px"></div>
      <div class="card" style="margin-top:4px">
        <div class="sec-label">Add Content</div>
        <div class="type-grid">
          <button class="type-btn act-youtube" onclick="setType('youtube')">▶ YouTube</button>
          <button class="type-btn" onclick="setType('image')">◼ Image</button>
          <button class="type-btn" onclick="setType('video')">⬤ Video</button>
          <button class="type-btn" onclick="setType('upload')">⬆ Upload</button>
        </div>
        <div id="url-section">
          <div class="form-group">
            <label id="url-label">YouTube URL</label>
            <input class="inp" id="f-url" placeholder="https://youtube.com/watch?v=..."/>
          </div>
        </div>
        <div id="upload-section" style="display:none">
          <div class="upload-zone" id="drop-zone" onclick="document.getElementById('file-input').click()">
            <div style="font-size:24px">⬆</div>
            <p>Click or drag & drop<br><span style="font-size:10px;color:var(--muted2)">Images: JPG PNG GIF WEBP · Videos: MP4 WEBM</span></p>
          </div>
          <input type="file" id="file-input" style="display:none" accept="image/*,video/*" onchange="handleFileSelect(this)"/>
          <div id="upload-progress" style="margin-top:8px;display:none">
            <div style="font-size:11px;color:var(--muted)">Uploading...</div>
            <div class="progress-wrap"><div class="progress-bar" id="upload-bar" style="width:0%"></div></div>
          </div>
        </div>
        <div class="form-group">
          <label>Title</label>
          <input class="inp inp-reg" id="f-title" placeholder="(optional)"/>
        </div>
        <div class="form-group">
          <label>Duration</label>
          <div style="display:flex;gap:6px;align-items:center">
            <input class="inp" id="f-dur-h" type="number" min="0" max="23" value="0" style="width:54px;text-align:center" oninput="updateDurPreview()"/>
            <span style="color:var(--muted);font-size:11px">h</span>
            <input class="inp" id="f-dur-m" type="number" min="0" max="59" value="0" style="width:54px;text-align:center" oninput="updateDurPreview()"/>
            <span style="color:var(--muted);font-size:11px">m</span>
            <input class="inp" id="f-dur-s" type="number" min="0" max="59" value="15" style="width:54px;text-align:center" oninput="updateDurPreview()"/>
            <span style="color:var(--muted);font-size:11px">s</span>
            <span id="dur-preview" style="font-size:10px;color:var(--accent);font-family:var(--mono)">= 15s</span>
          </div>
        </div>
        <span class="sched-toggle" onclick="toggleSched()">⏰ Add schedule</span>
        <div class="sched-panel" id="sched-panel">
          <div style="font-size:10px;color:var(--teal);margin-bottom:8px;font-weight:600">SCHEDULE (all fields optional)</div>
          <div class="row" style="margin-bottom:8px">
            <div style="flex:1"><label style="font-size:10px;color:var(--muted);display:block;margin-bottom:3px">Date from</label><input class="inp" id="f-sched-start" type="date"/></div>
            <div style="flex:1"><label style="font-size:10px;color:var(--muted);display:block;margin-bottom:3px">Date to</label><input class="inp" id="f-sched-end" type="date"/></div>
          </div>
          <div style="margin-bottom:8px">
            <label style="font-size:10px;color:var(--muted);display:block;margin-bottom:4px">Days of week</label>
            <div class="day-grid" id="day-grid">
              <button class="day-btn" onclick="toggleDay(this)" data-d="Mon">Mon</button>
              <button class="day-btn" onclick="toggleDay(this)" data-d="Tue">Tue</button>
              <button class="day-btn" onclick="toggleDay(this)" data-d="Wed">Wed</button>
              <button class="day-btn" onclick="toggleDay(this)" data-d="Thu">Thu</button>
              <button class="day-btn" onclick="toggleDay(this)" data-d="Fri">Fri</button>
              <button class="day-btn" onclick="toggleDay(this)" data-d="Sat">Sat</button>
              <button class="day-btn" onclick="toggleDay(this)" data-d="Sun">Sun</button>
            </div>
          </div>
          <div class="row">
            <div style="flex:1"><label style="font-size:10px;color:var(--muted);display:block;margin-bottom:3px">Time from</label><input class="inp" id="f-time-start" type="time"/></div>
            <div style="flex:1"><label style="font-size:10px;color:var(--muted);display:block;margin-bottom:3px">Time to</label><input class="inp" id="f-time-end" type="time"/></div>
          </div>
        </div>
        <div id="interrupt-section" style="display:none;margin-bottom:10px">
          <div style="background:rgba(245,158,11,.07);border:1px solid rgba(245,158,11,.2);border-radius:8px;padding:12px">
            <div style="display:flex;align-items:center;gap:8px;margin-bottom:8px">
              <input type="checkbox" id="interrupt-enabled" onchange="toggleInterruptFields(this.checked)" style="width:14px;height:14px;cursor:pointer"/>
              <label for="interrupt-enabled" style="font-size:10px;color:#fbbf24;font-weight:600;cursor:pointer">⚡ ENABLE INTERRUPT SCHEDULE</label>
            </div>
            <div id="interrupt-fields" style="display:none">
              <div style="font-size:11px;color:var(--muted);margin-bottom:8px">This slide will interrupt the normal playlist at a fixed interval.</div>
              <div class="row" style="margin-bottom:8px">
                <div style="flex:1">
                  <label style="font-size:10px;color:var(--muted);display:block;margin-bottom:3px">Play every</label>
                  <div style="display:flex;gap:4px;align-items:center">
                    <input class="inp" id="f-int-h" type="number" min="0" max="23" value="1" style="width:50px;text-align:center" oninput="updateIntPreview()"/>
                    <span style="color:var(--muted);font-size:11px">h</span>
                    <input class="inp" id="f-int-m" type="number" min="0" max="59" value="0" style="width:50px;text-align:center" oninput="updateIntPreview()"/>
                    <span style="color:var(--muted);font-size:11px">m</span>
                  </div>
                </div>
                <div style="flex:1">
                  <label style="font-size:10px;color:var(--muted);display:block;margin-bottom:3px">Play for</label>
                  <div style="display:flex;gap:4px;align-items:center">
                    <input class="inp" id="f-int-for-m" type="number" min="0" max="59" value="5" style="width:50px;text-align:center" oninput="updateIntPreview()"/>
                    <span style="color:var(--muted);font-size:11px">m</span>
                    <input class="inp" id="f-int-for-s" type="number" min="0" max="59" value="0" style="width:50px;text-align:center" oninput="updateIntPreview()"/>
                    <span style="color:var(--muted);font-size:11px">s</span>
                  </div>
                </div>
              </div>
              <div style="font-size:10px;color:var(--accent);font-family:var(--mono)" id="int-preview">Every 1h → plays for 5m</div>
            </div>
          </div>
        </div>
        <button class="btn btn-accent" style="width:100%;margin-top:4px" onclick="addSlide()">+ Add to Playlist</button>
      </div>
    </div>
    <div class="main-panel">
      <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:14px">
        <div class="sec-label" style="margin:0">Live Preview</div>
        <div style="font-size:11px;color:var(--muted)" id="online-count">0 screens online</div>
      </div>
      <div class="tv-grid" id="tv-grid"></div>
      <div class="now-bar" id="now-bar" style="display:none">
        <div class="now-dot"></div>
        <div style="flex:1">
          <div style="font-size:13px;font-weight:500" id="np-title">—</div>
          <div style="font-size:10px;color:var(--muted);font-family:var(--mono);margin-top:2px" id="np-sub">—</div>
        </div>
        <button onclick="openPreview()" class="btn btn-ghost btn-sm">Preview →</button>
      </div>
      <div class="deploy">
        <div class="sec-label">Deploy to TVs</div>
        <ol>
          <li><span class="step">1</span>Run: <code>python main1.py</code> — server on port 8000</li>
          <li><span class="step">2</span>Find your PC's local IP: open CMD → <code>ipconfig</code></li>
          <li><span class="step">3</span>On each TV open Chrome with flag: <code>--autoplay-policy=no-user-gesture-required</code></li>
          <li><span class="step">4</span>Navigate to: <code>http://YOUR_IP:8000/display</code></li>
          <li><span class="step">5</span>Each TV auto-registers in the Screens tab</li>
        </ol>
      </div>
    </div>
  </div>
</div>
<div class="content" id="content-screens">
  <div style="padding:20px;flex:1;overflow-y:auto">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
      <div class="sec-label" style="margin:0">Registered Screens</div>
      <div style="display:flex;gap:8px">
        <button class="btn btn-accent btn-sm" onclick="approveAllAutoplay()" style="font-size:11px">▶ Approve YouTube on All TVs</button>
        <button class="btn btn-danger btn-sm" onclick="cleanupGhostScreens()" style="font-size:11px">🗑 Remove Offline Ghosts</button>
      </div>
    </div>
    <div id="screens-list"></div>
  </div>
</div>
<div class="content" id="content-groups">
  <div style="padding:20px;flex:1;overflow-y:auto">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
      <div class="sec-label" style="margin:0">Screen Groups</div>
      <div style="display:flex;gap:8px">
        <input class="inp inp-reg" id="new-group-name" placeholder="Group name" style="width:160px"/>
        <button class="btn btn-ghost btn-sm" onclick="createGroup()">+ New Group</button>
      </div>
    </div>
    <div id="groups-list"></div>
  </div>
</div>
<div class="content" id="content-admins">
  <div style="padding:20px;flex:1;overflow-y:auto">
    <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">
      <div class="sec-label" style="margin:0">Admin Accounts</div>
      <div style="display:flex;gap:8px;align-items:center">
        <input class="inp inp-reg" id="new-admin-user" placeholder="Username" style="width:120px"/>
        <input class="inp" id="new-admin-pass" type="password" placeholder="Password" style="width:120px;font-family:var(--font)"/>
        <select class="inp" id="new-admin-role" style="width:110px;padding:8px 6px">
          <option value="subadmin">Sub-admin</option>
          <option value="superadmin">Super Admin</option>
        </select>
        <button class="btn btn-accent btn-sm" onclick="createAdmin()">+ Add Admin</button>
      </div>
    </div>
    <div id="admins-list"></div>
  </div>
</div>
<div id="pw-modal" style="display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);z-index:9999;align-items:center;justify-content:center">
  <div style="background:var(--surface);border:1px solid var(--border2);border-radius:14px;padding:28px;width:100%;max-width:340px;position:relative">
    <div style="font-size:14px;font-weight:600;margin-bottom:18px" id="pw-modal-title">Change Password</div>
    <div id="pw-current-wrap">
      <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:4px">Current Password</label>
      <input class="inp inp-reg" type="password" id="pw-current" placeholder="Current password" style="margin-bottom:10px"/>
    </div>
    <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:4px">New Password</label>
    <input class="inp inp-reg" type="password" id="pw-new" placeholder="New password (min 6 chars)" style="margin-bottom:10px"/>
    <label style="font-size:11px;color:var(--muted);display:block;margin-bottom:4px">Confirm New Password</label>
    <input class="inp inp-reg" type="password" id="pw-confirm" placeholder="Confirm new password" style="margin-bottom:16px"/>
    <div id="pw-error" style="color:var(--red);font-size:11px;margin-bottom:10px;display:none"></div>
    <div style="display:flex;gap:8px">
      <button class="btn btn-accent" style="flex:1" onclick="submitPasswordChange()">Save</button>
      <button class="btn btn-ghost" style="flex:1" onclick="hidePasswordModal()">Cancel</button>
    </div>
  </div>
</div>
<div id="toast"></div>
<script>
let playlists=[],slides=[],screens=[],groups=[];
let activePid=null,formType='youtube',schedOpen=false,tvIdx=0,tvTimer=null;
let ws;
const TOKEN=localStorage.getItem('signage_token');
const ROLE=localStorage.getItem('signage_role');
const ME=localStorage.getItem('signage_username');
if(!TOKEN){location.href='/login';}
function authFetch(url,opts={}){
  opts.headers={...(opts.headers||{}),'Authorization':'Bearer '+TOKEN};
  return fetch(url,opts).then(r=>{if(r.status===401){localStorage.clear();location.href='/login';}return r;});
}
async function logout(){await authFetch('/api/auth/logout',{method:'POST'});localStorage.clear();location.href='/login';}
let pwModalAdminId=null;
function showChangePassword(){
  pwModalAdminId=null;
  document.getElementById('pw-modal-title').textContent='Change My Password';
  document.getElementById('pw-current-wrap').style.display='block';
  document.getElementById('pw-current').value='';
  document.getElementById('pw-new').value='';
  document.getElementById('pw-confirm').value='';
  document.getElementById('pw-error').style.display='none';
  document.getElementById('pw-modal').style.display='flex';
}
function showResetPassword(aid,username){
  pwModalAdminId=aid;
  document.getElementById('pw-modal-title').textContent=`Reset Password: ${username}`;
  document.getElementById('pw-current-wrap').style.display='none';
  document.getElementById('pw-new').value='';
  document.getElementById('pw-confirm').value='';
  document.getElementById('pw-error').style.display='none';
  document.getElementById('pw-modal').style.display='flex';
}
function hidePasswordModal(){document.getElementById('pw-modal').style.display='none';}
async function submitPasswordChange(){
  const newPw=document.getElementById('pw-new').value;
  const confirm=document.getElementById('pw-confirm').value;
  const errEl=document.getElementById('pw-error');
  errEl.style.display='none';
  if(newPw.length<6){errEl.textContent='Password must be at least 6 characters';errEl.style.display='block';return;}
  if(newPw!==confirm){errEl.textContent='Passwords do not match';errEl.style.display='block';return;}
  let r;
  if(pwModalAdminId===null){
    const current=document.getElementById('pw-current').value;
    r=await authFetch('/api/auth/password',{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({current_password:current,new_password:newPw})});
  } else {
    r=await authFetch(`/api/admins/${pwModalAdminId}/password`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({new_password:newPw})});
  }
  if(r.ok){hidePasswordModal();toast(pwModalAdminId?'Password reset successfully':'Password changed successfully','success');}
  else{const d=await r.json().catch(()=>({}));errEl.textContent=d.detail||'Error changing password';errEl.style.display='block';}
}
function openDisplay(){window.open('/display','_blank');}
function openPreview(){const url=activePid?`/display?preview=${activePid}`:'/display';window.open(url,'_blank');}
function connectWS(){
  const proto=location.protocol==='https:'?'wss':'ws';
  ws=new WebSocket(`${proto}://${location.host}/ws/admin?token=${TOKEN}`);
  ws.onopen=()=>{setWS(true);loadAll()};
  ws.onmessage=e=>{
    if(e.data==='pong')return;
    let msg;try{msg=JSON.parse(e.data);}catch(err){return;}
    if(msg.event==='slides_updated'&&msg.playlist_id===activePid){slides=msg.slides;renderSlides();}
    if(msg.event==='playlists_updated'){playlists=msg.playlists;renderPlChips();}
    if(msg.event==='screens_updated'){screens=msg.screens;renderScreens();updateTVGrid();}
    if(msg.event==='groups_updated'){groups=msg.groups;renderGroups();}
  };
  ws.onclose=()=>{setWS(false);setTimeout(connectWS,2500)};
  setInterval(()=>ws.readyState===1&&ws.send('ping'),25000);
}
function setWS(ok){const el=document.getElementById('ws-ind');el.textContent=ok?'⬤ live':'⬤ offline';el.className='ws-pill '+(ok?'ws-ok':'ws-bad');}
async function loadAll(){
  const pill=document.getElementById('user-pill');
  if(pill)pill.textContent=`${ME||'?'} (${ROLE==='superadmin'?'Super Admin':'Sub-admin'})`;
  if(ROLE==='superadmin'){
    document.getElementById('tab-admins').style.display='block';
    await Promise.all([loadPlaylists(),loadScreens(),loadGroups(),loadAdmins()]);
  } else {
    await Promise.all([loadPlaylists(),loadScreens(),loadGroups()]);
  }
}
async function loadPlaylists(){const r=await authFetch('/api/playlists').then(r=>r.json());playlists=r.playlists;renderPlChips();if(!activePid&&playlists.length)selectPlaylist(playlists[0].id);}
async function loadSlides(pid){const r=await authFetch(`/api/playlists/${pid}/slides`).then(r=>r.json());slides=r.slides;renderSlides();}
async function loadScreens(){const r=await authFetch('/api/screens').then(r=>r.json());screens=r.screens;renderScreens();updateTVGrid();}
async function loadGroups(){const r=await authFetch('/api/groups').then(r=>r.json());groups=r.groups;renderGroups();}
function openTab(t){
  document.querySelectorAll('.tab').forEach(el=>el.classList.remove('active'));
  document.querySelectorAll('.content').forEach(el=>el.classList.remove('active'));
  document.getElementById('tab-'+t).classList.add('active');
  document.getElementById('content-'+t).classList.add('active');
}
function selectPlaylist(pid){
  activePid=pid;renderPlChips();loadSlides(pid);
  const pl=playlists.find(p=>p.id===pid);
  const card=document.getElementById('fallback-card');
  if(pl){
    card.style.display='block';
    document.getElementById('fb-url').value=pl.fallback_url||'';
    const lh=Math.floor((pl.loop_duration||1800)/3600);
    const lm=Math.floor(((pl.loop_duration||1800)%3600)/60);
    const fm=Math.floor((pl.fallback_duration||300)/60);
    const fs=(pl.fallback_duration||300)%60;
    document.getElementById('fb-loop-h').value=lh;
    document.getElementById('fb-loop-m').value=lm;
    document.getElementById('fb-for-m').value=fm;
    document.getElementById('fb-for-s').value=fs;
    updateFbPreview();
  }
}
function renderPlChips(){
  const total=playlists.reduce((s,p)=>s+(p.slide_count||0),0);
  document.getElementById('hdr-sub').textContent=`${screens.filter(s=>s.status==='online').length} online · ${total} total slides`;
  document.getElementById('pl-chips').innerHTML=playlists.map(p=>`
    <div style="display:inline-flex;align-items:center;gap:0;margin-bottom:4px">
      <button class="pl-chip ${p.id===activePid?'active':''}" style="border-radius:20px 0 0 20px;border-right:none" onclick="selectPlaylist(${p.id})">${p.name}${p.fallback_url?'<span style="color:#fbbf24;margin-left:4px">⚡</span>':''} <span style="opacity:.5;font-size:9px">${p.slide_count}</span></button>
      <button onclick="deletePlaylist(${p.id},'${p.name}')" style="padding:6px 8px;border-radius:0 20px 20px 0;border:1px solid var(--border2);border-left:none;background:none;color:var(--muted);cursor:pointer;font-size:11px;line-height:1" onmouseenter="this.style.color='var(--red)'" onmouseleave="this.style.color='var(--muted)'">✕</button>
    </div>`).join('');
}
async function createPlaylist(){
  const name=document.getElementById('new-pl-name').value.trim();
  if(!name)return;
  await authFetch('/api/playlists',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});
  document.getElementById('new-pl-name').value='';
  await loadPlaylists();
}
async function deletePlaylist(pid,name){
  if(!confirm(`Delete playlist "${name}" and all its slides?`))return;
  await authFetch(`/api/playlists/${pid}`,{method:'DELETE'});
  if(activePid===pid){activePid=null;document.getElementById('slides-list').innerHTML='';document.getElementById('fallback-card').style.display='none';document.getElementById('now-bar').style.display='none';}
  await loadPlaylists();
  toast(`Deleted "${name}"`, 'success');
}
function thumb(s){if(s.type==='image')return s.url;return null;}
function renderSlides(){
  const el=document.getElementById('slides-list');
  if(!slides.length){el.innerHTML='<div style="text-align:center;color:var(--muted);font-size:12px;padding:20px 0">No slides — add some below</div>';updateNowBar();return;}
  el.innerHTML=slides.map((s,i)=>{
    const t=thumb(s);
    const thumbHtml=t?`<img src="${t}" alt="" onerror="this.style.display='none'">`:`<div style="font-size:16px;opacity:.3">${s.type==='youtube'?'▶':s.type==='video'?'🎬':'◼'}</div>`;
    const hasSched=s.sched_start||s.sched_end||s.days_of_week||s.time_start||s.time_end;
    return `<div class="slide-item ${s.active?'':'disabled'}">
      <div class="thumb">${thumbHtml}</div>
      <div class="slide-info">
        <div class="slide-title">${s.title||'Untitled'}</div>
        <div class="slide-meta">
          <span class="badge badge-${s.type}">${s.type}</span>
          <span class="slide-dur">${fmtDur(s.duration)}</span>
          ${hasSched?'<span class="badge badge-sched">⏰ sched</span>':''}
          ${s.interrupt_every>0?`<span class="badge badge-interrupt">⚡ every ${fmtDur(s.interrupt_every)}</span>`:''}
          ${!s.active?'<span class="badge badge-off">off</span>':''}
        </div>
      </div>
      <div class="sort-col">
        <button class="sort-btn" onclick="moveSlide(${i},${i-1})" ${i===0?'disabled':''}>▲</button>
        <button class="sort-btn" onclick="moveSlide(${i},${i+1})" ${i===slides.length-1?'disabled':''}>▼</button>
      </div>
      <button class="icon-btn" onclick="toggleSlide(${s.id})" title="${s.active?'Disable':'Enable'}">${s.active?'⏸':'▶'}</button>
      <button class="icon-btn" onclick="deleteSlide(${s.id})" title="Delete" style="color:var(--red)">✕</button>
    </div>`;
  }).join('');
  updateNowBar();
}
function updateNowBar(){
  const bar=document.getElementById('now-bar');
  if(!slides.length){bar.style.display='none';return;}
  bar.style.display='flex';
  const s=slides[tvIdx%slides.length];
  document.getElementById('np-title').textContent=`Now showing: ${s?.title||'Untitled'}`;
  document.getElementById('np-sub').textContent=`Slide ${(tvIdx%slides.length)+1} of ${slides.length} · ${fmtDur(s?.duration||0)} · ${s?.type}`;
}
function fmtDur(s){
  if(!s)return'0s';
  const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sec=s%60;
  if(h)return`${h}h ${m}m ${sec}s`;if(m)return`${m}m ${sec}s`;return`${sec}s`;
}
function getDurSecs(){
  const h=parseInt(document.getElementById('f-dur-h').value)||0;
  const m=parseInt(document.getElementById('f-dur-m').value)||0;
  const s=parseInt(document.getElementById('f-dur-s').value)||0;
  return Math.max(3,h*3600+m*60+s);
}
function updateIntPreview(){
  const everyH=parseInt(document.getElementById('f-int-h').value)||0;
  const everyM=parseInt(document.getElementById('f-int-m').value)||0;
  const forM=parseInt(document.getElementById('f-int-for-m').value)||0;
  const forS=parseInt(document.getElementById('f-int-for-s').value)||0;
  const everyLabel=everyH?`${everyH}h${everyM?` ${everyM}m`:''}`:everyM?`${everyM}m`:'—';
  const forLabel=forM?`${forM}m${forS?` ${forS}s`:''}`:forS?`${forS}s`:'—';
  document.getElementById('int-preview').textContent=`Every ${everyLabel} → plays for ${forLabel}`;
}
function toggleInterruptFields(enabled){document.getElementById('interrupt-fields').style.display=enabled?'block':'none';}
function getInterruptEvery(){const h=parseInt(document.getElementById('f-int-h').value)||0;const m=parseInt(document.getElementById('f-int-m').value)||0;return h*3600+m*60;}
function getInterruptFor(){const m=parseInt(document.getElementById('f-int-for-m').value)||0;const s=parseInt(document.getElementById('f-int-for-s').value)||0;return m*60+s;}
function updateFbPreview(){
  const lh=parseInt(document.getElementById('fb-loop-h').value)||0;
  const lm=parseInt(document.getElementById('fb-loop-m').value)||0;
  const fm=parseInt(document.getElementById('fb-for-m').value)||0;
  const fs=parseInt(document.getElementById('fb-for-s').value)||0;
  const loopLabel=lh?`${lh}h ${lm}m`:lm?`${lm}m`:'—';
  const forLabel=fm?`${fm}m ${fs}s`:fs?`${fs}s`:'—';
  const url=document.getElementById('fb-url').value.trim();
  document.getElementById('fb-preview').textContent=url?`Loop ${loopLabel} → YouTube ${forLabel} → repeat`:'Set a YouTube URL to enable';
}
async function saveFallback(){
  if(!activePid)return;
  const url=document.getElementById('fb-url').value.trim();
  const lh=parseInt(document.getElementById('fb-loop-h').value)||0;
  const lm=parseInt(document.getElementById('fb-loop-m').value)||0;
  const fm=parseInt(document.getElementById('fb-for-m').value)||0;
  const fs=parseInt(document.getElementById('fb-for-s').value)||0;
  const loop_duration=lh*3600+lm*60;
  const fallback_duration=fm*60+fs;
  if(!url){toast('Enter a YouTube URL first','error');return;}
  if(loop_duration<60){toast('Loop duration must be at least 1 minute','error');return;}
  if(fallback_duration<10){toast('Fallback duration must be at least 10 seconds','error');return;}
  await authFetch(`/api/playlists/${activePid}/fallback`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({fallback_url:url,loop_duration,fallback_duration})});
  toast('Fallback saved — TVs updated','success');
}
async function clearFallback(){
  if(!activePid)return;
  await authFetch(`/api/playlists/${activePid}/fallback`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({fallback_url:null,loop_duration:1800,fallback_duration:300})});
  document.getElementById('fb-url').value='';
  toast('Fallback removed','success');
}
function updateDurPreview(){document.getElementById('dur-preview').textContent='= '+fmtDur(getDurSecs());}
async function addSlide(){
  if(!activePid){toast('Select a playlist first','error');return;}
  if(formType==='upload'){toast('Please use the upload button above','error');return;}
  const url=document.getElementById('f-url').value.trim();
  if(!url){toast('Enter a URL','error');return;}
  const days=[...document.querySelectorAll('.day-btn.sel')].map(b=>b.dataset.d).join(',');
  const body={type:formType,url,title:document.getElementById('f-title').value.trim(),duration:getDurSecs(),
    sched_start:document.getElementById('f-sched-start').value||null,sched_end:document.getElementById('f-sched-end').value||null,
    days_of_week:days||null,time_start:document.getElementById('f-time-start').value||null,time_end:document.getElementById('f-time-end').value||null,
    interrupt_every:formType==='youtube'&&document.getElementById('interrupt-enabled')?.checked?getInterruptEvery():0,
    interrupt_for:formType==='youtube'&&document.getElementById('interrupt-enabled')?.checked?getInterruptFor():300};
  await authFetch(`/api/playlists/${activePid}/slides`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
  document.getElementById('f-url').value='';document.getElementById('f-title').value='';
  toast('Slide added','success');
}
async function deleteSlide(id){if(!confirm('Delete this slide?'))return;await authFetch(`/api/slides/${id}`,{method:'DELETE'});toast('Deleted','success');}
async function toggleSlide(id){await authFetch(`/api/slides/${id}/toggle`,{method:'PUT'});}
async function moveSlide(from,to){
  const ids=slides.map(s=>s.id);const[m]=ids.splice(from,1);ids.splice(to,0,m);
  await authFetch(`/api/playlists/${activePid}/reorder`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({ids})});
}
function setType(t){
  formType=t;
  document.querySelectorAll('.type-btn').forEach(b=>b.className='type-btn');
  ['youtube','image','video','upload'].forEach((x,i)=>{if(x===t)document.querySelectorAll('.type-btn')[i].className=`type-btn act-${t}`;});
  const ph={youtube:'https://youtube.com/watch?v=...',image:'https://example.com/image.jpg',video:'https://example.com/video.mp4'};
  document.getElementById('url-label').textContent={youtube:'YouTube URL',image:'Image URL',video:'Video URL'}[t]||'URL';
  if(ph[t])document.getElementById('f-url').placeholder=ph[t];
  document.getElementById('url-section').style.display=t==='upload'?'none':'block';
  document.getElementById('upload-section').style.display=t==='upload'?'block':'none';
  document.getElementById('interrupt-section').style.display=t==='youtube'?'block':'none';
  if(t==='youtube'){const cb=document.getElementById('interrupt-enabled');if(cb){cb.checked=false;toggleInterruptFields(false);}}
}
function toggleSched(){schedOpen=!schedOpen;document.getElementById('sched-panel').className='sched-panel'+(schedOpen?' open':'');document.querySelector('.sched-toggle').textContent=schedOpen?'⏰ Hide schedule':'⏰ Add schedule';}
function toggleDay(btn){btn.classList.toggle('sel');}
const dropZone=document.getElementById('drop-zone');
['dragover','dragenter'].forEach(ev=>dropZone.addEventListener(ev,e=>{e.preventDefault();dropZone.classList.add('drag');}));
['dragleave','drop'].forEach(ev=>dropZone.addEventListener(ev,e=>{e.preventDefault();dropZone.classList.remove('drag');}));
dropZone.addEventListener('drop',e=>{const f=e.dataTransfer.files[0];if(f)uploadFile(f);});
function handleFileSelect(input){if(input.files[0])uploadFile(input.files[0]);}
async function uploadFile(file){
  const prog=document.getElementById('upload-progress');const bar=document.getElementById('upload-bar');
  prog.style.display='block';bar.style.width='20%';
  const fd=new FormData();fd.append('file',file);
  try{
    bar.style.width='60%';
    const r=await authFetch('/api/upload',{method:'POST',body:fd});
    bar.style.width='100%';
    if(!r.ok)throw new Error(await r.text());
    const data=await r.json();
    const body={type:data.type,url:data.url,title:file.name.replace(/\.[^.]+$/,''),duration:15};
    await authFetch(`/api/playlists/${activePid}/slides`,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});
    toast(`Uploaded: ${data.filename}`,'success');
    setTimeout(()=>{prog.style.display='none';bar.style.width='0%';},1000);
  }catch(err){toast('Upload failed: '+err.message,'error');prog.style.display='none';}
}
function updateTVGrid(){
  const onlineCount=screens.filter(s=>s.status==='online').length;
  document.getElementById('online-count').textContent=`${onlineCount} screen${onlineCount!==1?'s':''} online`;
  const total=Math.max(10,screens.length);
  const curSlide=slides[tvIdx%Math.max(slides.length,1)];
  const t=curSlide?thumb(curSlide):null;
  document.getElementById('tv-grid').innerHTML=Array.from({length:total},(_,i)=>{
    const s=screens[i];const isOnline=s&&s.status==='online';
    return `<div class="tv-box" title="${s?s.name:'Empty slot'}">
      ${t?`<img src="${t}" alt="">`:'<div class="tv-ph">▶</div>'}
      <div class="tv-grad"></div>
      <div class="tv-lbl">
        <span class="tv-num">${s?s.name:`TV ${i+1}`}</span>
        <span class="tv-status ${isOnline?'tv-online':'tv-offline'}">${isOnline?'● LIVE':'○ off'}</span>
      </div>
    </div>`;
  }).join('');
}
function cycleTVPreview(){
  clearTimeout(tvTimer);if(!slides.length)return;
  const dur=(slides[tvIdx%slides.length]?.duration||10)*1000;
  tvTimer=setTimeout(()=>{tvIdx=(tvIdx+1)%slides.length;updateTVGrid();updateNowBar();cycleTVPreview();},dur);
}
function renderScreens(){
  const el=document.getElementById('screens-list');
  if(!screens.length){el.innerHTML='<div style="color:var(--muted);font-size:13px;padding:32px;text-align:center">No screens registered yet.<br><span style="font-size:11px">Open /display on a TV browser to register it.</span></div>';return;}
  el.innerHTML=screens.map(s=>`
    <div class="screen-item" style="flex-wrap:wrap;gap:8px">
      <div class="screen-dot ${s.status==='online'?'dot-online':'dot-offline'}"></div>
      <div class="screen-info">
        <div class="screen-name">${s.name}</div>
        <div class="screen-sub">${s.ip_address||'—'} · Last seen: ${s.last_seen?new Date(s.last_seen).toLocaleTimeString():'never'} · Group: ${s.group_name||'none'} · Playlist: ${s.playlist_name||'default'}</div>
      </div>
      <div class="screen-actions" style="flex-wrap:wrap">
        <select class="inp" style="width:130px;padding:5px 6px;font-size:11px" onchange="assignPlaylist('${s.id}',this.value)">
          <option value="">Default playlist</option>
          ${playlists.map(p=>`<option value="${p.id}" ${s.playlist_id==p.id?'selected':''}>${p.name}</option>`).join('')}
        </select>
        <select class="inp" style="width:120px;padding:5px 6px;font-size:11px" onchange="assignGroup('${s.id}',this.value)">
          <option value="">No group</option>
          ${groups.map(g=>`<option value="${g.id}" ${s.group_id==g.id?'selected':''}>${g.name}</option>`).join('')}
        </select>
        <div style="display:flex;gap:4px;align-items:center">
          <span style="font-size:10px;color:var(--muted)">Orientation:</span>
          <button onclick="setOrientation('${s.id}','landscape',90)" style="padding:4px 8px;border-radius:5px;border:1px solid var(--border2);background:${s.orientation==='landscape'?'var(--accent-dim)':'none'};color:${s.orientation==='landscape'?'var(--accent)':'var(--muted)'};font-size:10px;cursor:pointer">▬ Land</button>
          <button onclick="pickPortrait('${s.id}')" style="padding:4px 8px;border-radius:5px;border:1px solid var(--border2);background:${s.orientation==='portrait'?'var(--accent-dim)':'none'};color:${s.orientation==='portrait'?'var(--accent)':'var(--muted)'};font-size:10px;cursor:pointer">▮ Port ${s.orientation==='portrait'?(s.rotation_dir===90?'↻':'↺'):''}</button>
        </div>
        <button class="btn btn-danger btn-sm" onclick="deleteScreen('${s.id}')">Remove</button>
      </div>
    </div>`).join('');
}
async function setOrientation(sid,orientation,rotation_dir){await authFetch(`/api/screens/${sid}/orientation`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({orientation,rotation_dir})});toast('Orientation updated','success');}
function pickPortrait(sid){const dir=confirm('Rotate 90° clockwise?\nClick Cancel for counter-clockwise.')?90:-90;setOrientation(sid,'portrait',dir);}
async function assignPlaylist(sid,pid){await authFetch(`/api/screens/${sid}`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({playlist_id:parseInt(pid)||null})});toast('Playlist assigned','success');}
async function assignGroup(sid,gid){await authFetch(`/api/screens/${sid}`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({group_id:parseInt(gid)||null})});toast('Group assigned','success');}
async function deleteScreen(sid){if(!confirm('Remove this screen?'))return;await authFetch(`/api/screens/${sid}`,{method:'DELETE'});await loadScreens();}
async function approveAllAutoplay(){
  const r=await authFetch('/api/screens/approve-autoplay',{method:'POST'});
  const d=await r.json();
  toast(`YouTube approved on ${d.screens} screen${d.screens!==1?'s':''}`, 'success');
}
async function cleanupGhostScreens(){
  if(!confirm('Remove all screens offline for 24+ hours?'))return;
  const r=await authFetch('/api/screens',{method:'DELETE'});
  const d=await r.json();
  toast(`Removed ${d.deleted} ghost screen${d.deleted!==1?'s':''}`, 'success');
  await loadScreens();
}
function renderGroups(){
  const el=document.getElementById('groups-list');
  if(!groups.length){el.innerHTML='<div style="color:var(--muted);font-size:12px;padding:20px 0">No groups yet.</div>';return;}
  el.innerHTML=groups.map(g=>`
    <div class="group-card">
      <div class="group-hdr">
        <div><div class="group-name">${g.name}</div><div class="group-meta">${g.screen_count} screen${g.screen_count!=1?'s':''}</div></div>
        <button class="btn btn-danger btn-sm" onclick="deleteGroup(${g.id})">Delete</button>
      </div>
      <div style="display:flex;gap:8px;align-items:center">
        <select class="inp" style="flex:1;padding:6px 8px;font-size:12px" id="grp-pl-${g.id}">
          ${playlists.map(p=>`<option value="${p.id}">${p.name}</option>`).join('')}
        </select>
        <button class="btn btn-ghost btn-sm" onclick="assignGroupPlaylist(${g.id})">Assign Playlist to Group</button>
      </div>
    </div>`).join('');
}
async function createGroup(){const name=document.getElementById('new-group-name').value.trim();if(!name)return;await authFetch('/api/groups',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});document.getElementById('new-group-name').value='';await loadGroups();}
async function deleteGroup(id){if(!confirm('Delete group?'))return;await authFetch(`/api/groups/${id}`,{method:'DELETE'});await loadGroups();}
let admins=[];
async function loadAdmins(){
  const r=await authFetch('/api/admins').then(r=>r.json());
  admins=r.admins;
  await Promise.all(admins.filter(a=>a.role!=='superadmin').map(async a=>{
    const r2=await authFetch(`/api/admins/${a.id}/screens`).then(r=>r.json()).catch(()=>({screen_ids:[]}));
    a.screen_ids=r2.screen_ids||[];
  }));
  renderAdmins();
}
async function createAdmin(){
  const username=document.getElementById('new-admin-user').value.trim();
  const password=document.getElementById('new-admin-pass').value;
  const role=document.getElementById('new-admin-role').value;
  if(!username||!password){toast('Enter username and password','error');return;}
  const r=await authFetch('/api/admins',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username,password,role})});
  if(!r.ok){const d=await r.json();toast(d.detail||'Error','error');return;}
  document.getElementById('new-admin-user').value='';
  document.getElementById('new-admin-pass').value='';
  toast('Admin created','success');
  await loadAdmins();
}
async function deleteAdmin(id){if(!confirm('Delete this admin?'))return;await authFetch(`/api/admins/${id}`,{method:'DELETE'});await loadAdmins();toast('Admin deleted','success');}
async function saveAdminScreens(aid){
  const checkboxes=[...document.querySelectorAll(`.screen-cb-${aid}:checked`)];
  const screen_ids=checkboxes.map(c=>c.value);
  await authFetch(`/api/admins/${aid}/screens`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({screen_ids})});
  toast('Screen access updated','success');
}
function renderAdmins(){
  const el=document.getElementById('admins-list');
  if(!admins.length){el.innerHTML='<div style="color:var(--muted);font-size:12px">No admins yet.</div>';return;}
  el.innerHTML=admins.map(a=>`
    <div class="group-card">
      <div class="group-hdr">
        <div>
          <div class="group-name">${a.username} ${a.username===ME?'<span style="font-size:9px;color:var(--accent)">(you)</span>':''}</div>
          <div class="group-meta">${a.role==='superadmin'?'Super Admin':'Sub-admin'}</div>
        </div>
        <div style="display:flex;gap:6px">
          ${a.role!=='superadmin'?`<button class="btn btn-ghost btn-sm" onclick="showResetPassword(${a.id},'${a.username}')">🔑 Reset Password</button>`:''}
          ${a.username!==ME?`<button class="btn btn-danger btn-sm" onclick="deleteAdmin(${a.id})">Delete</button>`:''}
        </div>
      </div>
      ${a.role!=='superadmin'?`
      <div style="margin-top:8px">
        <div style="font-size:10px;color:var(--muted);margin-bottom:6px">SCREEN ACCESS</div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:8px">
          ${screens.map(s=>`<label style="display:flex;align-items:center;gap:4px;font-size:11px;cursor:pointer"><input type="checkbox" class="screen-cb-${a.id}" value="${s.id}" ${(a.screen_ids||[]).includes(s.id)?'checked':''}/><span style="color:${s.status==='online'?'var(--green)':'var(--muted)'}">${s.name}</span></label>`).join('')}
          ${!screens.length?'<span style="font-size:11px;color:var(--muted)">No screens registered yet</span>':''}
        </div>
        <button class="btn btn-ghost btn-sm" onclick="saveAdminScreens(${a.id})">Save Screen Access</button>
      </div>`:'<div style="font-size:11px;color:var(--muted);margin-top:6px">Has access to all screens</div>'}
    </div>`).join('');
}
async function assignGroupPlaylist(gid){const pid=parseInt(document.getElementById(`grp-pl-${gid}`).value);await authFetch(`/api/groups/${gid}/assign`,{method:'PUT',headers:{'Content-Type':'application/json'},body:JSON.stringify({playlist_id:pid})});toast('Playlist pushed to all screens in group','success');await loadScreens();}
function toast(msg,type='success'){const el=document.createElement('div');el.className=`toast ${type}`;el.textContent=msg;document.getElementById('toast').appendChild(el);setTimeout(()=>el.remove(),3000);}
connectWS();
setInterval(cycleTVPreview,100);
</script>
</body>
</html>"""

DISPLAY_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1.0"/>
<meta http-equiv="Cache-Control" content="no-cache, no-store, must-revalidate"/>
<meta http-equiv="Pragma" content="no-cache"/>
<title>SignageOS Display</title>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html,body{width:100%;height:100%;overflow:hidden;background:#000;font-family:'Segoe UI',system-ui,sans-serif}
#wrapper{position:fixed;top:0;left:0;right:0;bottom:0;overflow:hidden;transform-origin:center center}
#stage{position:absolute;top:0;left:0;right:0;bottom:0}
.layer{position:absolute;top:0;left:0;right:0;bottom:0;transition:opacity .9s ease}
.layer.hidden{opacity:0;pointer-events:none}

#yt-frame{width:100%;height:100%;border:none;pointer-events:none;}
#img-el{width:100%;height:100%;object-fit:cover;display:block}
#vid-el{width:100%;height:100%;object-fit:cover;display:block}
#overlay{position:absolute;top:0;left:0;right:0;bottom:0;pointer-events:none;background:linear-gradient(to top,rgba(0,0,0,.78) 0%,transparent 42%);z-index:10}
#bottom{position:absolute;bottom:0;left:0;right:0;padding:26px 32px 40px;display:flex;align-items:flex-end;justify-content:space-between;z-index:20}
.type-lbl{font-size:10px;font-weight:600;color:rgba(255,255,255,.45);letter-spacing:2px;text-transform:uppercase;margin-bottom:6px}
.slide-title{font-size:clamp(18px,3vw,34px);font-weight:700;color:#fff;line-height:1.2;max-width:60vw;text-shadow:0 2px 10px rgba(0,0,0,.6)}
.clock{text-align:right}
.clock-time{font-size:clamp(22px,3vw,38px);font-weight:700;color:#fff;font-family:monospace;line-height:1}
.clock-date{font-size:12px;color:rgba(255,255,255,.45);margin-top:4px}
#dots{position:absolute;bottom:16px;left:50%;transform:translateX(-50%);display:flex;gap:6px;z-index:30}
.dot{height:6px;border-radius:3px;background:rgba(255,255,255,.25);cursor:pointer;transition:all .3s;flex-shrink:0}
.dot.active{background:#f59e0b}
#pbar{position:absolute;bottom:0;left:0;height:3px;background:#f59e0b;z-index:40;transition:width .12s linear}
#empty{position:absolute;top:0;left:0;right:0;bottom:0;display:none;flex-direction:column;align-items:center;justify-content:center;color:rgba(255,255,255,.15);font-size:13px;letter-spacing:1px;text-transform:uppercase;gap:10px}
#yt-click-overlay{display:none;position:absolute;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.82);flex-direction:column;align-items:center;justify-content:center;z-index:50;cursor:pointer}

/* --- THE FAKE IN-APP POPUP WINDOW --- */
#yt-modal {
  display: none;
  position: absolute;
  top: 50%;
  left: 50%;
  transform: translate(-50%, -50%);
  width: 80%;
  height: 80%;
  max-width: 1000px;
  max-height: 562px;
  background: #000;
  border: 4px solid #f59e0b;
  border-radius: 12px;
  box-shadow: 0 25px 60px rgba(0,0,0,0.9);
  z-index: 99999;
  overflow: hidden;
}
#yt-modal iframe {
  width: 100%;
  height: 100%;
  border: none;
  display: block;
  pointer-events: none; 
}
/* ------------------------------------ */

#badge{position:fixed;top:14px;right:16px;font-size:10px;font-family:monospace;padding:4px 10px;border-radius:5px;z-index:999999;transition:opacity .5s}
.badge-ok{background:rgba(34,197,94,.18);color:#22c55e;border:1px solid rgba(34,197,94,.3)}
.badge-bad{background:rgba(239,68,68,.18);color:#ef4444;border:1px solid rgba(239,68,68,.3)}
#sname{position:fixed;top:14px;left:16px;font-size:10px;font-family:monospace;padding:4px 10px;border-radius:5px;background:rgba(0,0,0,.45);color:rgba(255,255,255,.4);z-index:999999}
#splash{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.93);display:flex;flex-direction:column;align-items:center;justify-content:center;z-index:999998;cursor:pointer}
</style>
</head>
<body>

<div id="wrapper">
  <div id="stage">
    <div id="yt-layer" class="layer hidden">
      <iframe id="yt-frame" allow="autoplay; fullscreen; encrypted-media; picture-in-picture" allowfullscreen></iframe>
      <div id="yt-click-overlay">
        <div style="width:72px;height:72px;background:#ff0000;border-radius:16px;display:flex;align-items:center;justify-content:center;margin-bottom:16px;font-size:32px">▶</div>
        <div style="color:#fff;font-size:20px;font-weight:700;font-family:sans-serif;margin-bottom:8px">Tap to play</div>
        <div style="color:rgba(255,255,255,.45);font-size:12px;font-family:sans-serif;margin-bottom:24px" id="yt-overlay-title"></div>
      </div>
    </div>
    <div id="img-layer" class="layer hidden"><img id="img-el" src="" alt=""/></div>
    <div id="vid-layer" class="layer hidden"><video id="vid-el" autoplay muted loop playsinline></video></div>
  </div>
  <div id="overlay"></div>

  <div id="yt-modal">
    <iframe id="yt-modal-frame" allow="autoplay; fullscreen; encrypted-media" allowfullscreen></iframe>
  </div>

  <div id="bottom">
    <div><div class="type-lbl" id="type-lbl">—</div><div class="slide-title" id="slide-title">—</div></div>
    <div class="clock"><div class="clock-time" id="clock-t">00:00</div><div class="clock-date" id="clock-d">—</div></div>
  </div>
  <div id="dots"></div>
  <div id="pbar" style="width:0%"></div>
  <div id="empty"><div style="font-size:40px">📺</div><div>Waiting for content...</div></div>
</div>

<div id="orient-btn" onclick="toggleOrientationLocal()"
  style="position:fixed;top:12px;right:12px;z-index:999999;background:rgba(0,0,0,.55);border:1px solid rgba(255,255,255,.2);border-radius:8px;padding:8px 12px;cursor:pointer;font-family:monospace;font-size:12px;color:rgba(255,255,255,.7);user-select:none">⟳</div>
<div id="badge" class="badge-bad">⬤ connecting...</div>
<div id="sname"></div>

<div id="splash" onclick="dismissSplash()">
  <div style="font-size:48px;margin-bottom:16px">📺</div>
  <div style="color:#fff;font-size:28px;font-weight:700;font-family:sans-serif;margin-bottom:8px">SignageOS</div>
  <div style="color:rgba(255,255,255,.5);font-size:14px;font-family:sans-serif;margin-bottom:32px">Tap anywhere to start</div>
  <div style="background:#f59e0b;color:#000;font-size:15px;font-weight:700;font-family:sans-serif;padding:13px 38px;border-radius:30px">▶ START</div>
  <div style="color:rgba(255,255,255,.25);font-size:10px;font-family:monospace;margin-top:20px" id="splash-id"></div>
</div>

<div id="debug" style="position:fixed;bottom:60px;left:10px;background:rgba(0,0,0,.8);color:#0f0;font-family:monospace;font-size:10px;padding:8px;border-radius:6px;z-index:999999;max-width:400px;display:none;word-break:break-all"></div>
<button onclick="document.getElementById('debug').style.display=document.getElementById('debug').style.display==='none'?'block':'none'"
  style="position:fixed;bottom:10px;left:10px;z-index:999999;padding:6px 10px;background:rgba(0,0,0,.6);color:#fff;border:1px solid #555;border-radius:5px;font-size:10px;cursor:pointer">Debug</button>

<script>
window.onerror = function(msg, url, line) {
  document.getElementById('debug').style.display = 'block';
  document.getElementById('debug').innerHTML += '<span style="color:red">ERROR: ' + msg + ' (Line ' + line + ')</span><br>';
  return false;
};

function dbg(msg){const el=document.getElementById('debug');el.innerHTML+=msg+'<br>';el.scrollTop=el.scrollHeight;}

function getScreenId(){
  const urlParam=new URLSearchParams(location.search).get('screen');
  if(urlParam)return urlParam.trim().toLowerCase().replace(/[^a-z0-9-]/g,'');
  let id=localStorage.getItem('signage_screen_id');
  if(!id){id='screen-'+Math.random().toString(36).slice(2,10);localStorage.setItem('signage_screen_id',id);}
  return id;
}
const PREVIEW_PID=new URLSearchParams(location.search).get('preview');
const SCREEN_ID=getScreenId();
const IS_PREVIEW=!!PREVIEW_PID;
document.getElementById('sname').textContent=IS_PREVIEW?`PREVIEW — playlist ${PREVIEW_PID}`:SCREEN_ID;
document.getElementById('sname').style.color=IS_PREVIEW?'#f59e0b':'rgba(255,255,255,.4)';
document.getElementById('splash-id').textContent=IS_PREVIEW?'preview mode':SCREEN_ID;

function tickClock(){
  const n=new Date();
  document.getElementById('clock-t').textContent=n.toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
  document.getElementById('clock-d').textContent=n.toLocaleDateString([],{weekday:'long',month:'long',day:'numeric'});
}
setInterval(tickClock,1000);tickClock();

function ytId(url){const m=url.match(/(?:youtube\.com\/watch\?v=|youtu\.be\/)([^&\n?#]+)/);return m?m[1]:null;}
function ytEmbed(url){
  const id=ytId(url);if(!id)return null;
  const origin = window.location.origin;
  return `https://www.youtube.com/embed/${id}?autoplay=1&mute=1&rel=0&modestbranding=1&playsinline=1&origin=${origin}`;
}

let playlist=[],idx=0;
let autoplayUnlocked=false;
let pendingYTSlide=null;

// ── NEW UNIFIED TIMER ENGINE ──
let currentTimerCancel = () => {};

function startTimer(durMs, onComplete) {
  const startTime = performance.now();
  const bar = document.getElementById('pbar');
  let active = true;

  const tick = () => {
    if (!active) return;
    const elapsed = performance.now() - startTime;
    bar.style.width = Math.min((elapsed / durMs) * 100, 100) + '%';

    if (elapsed >= durMs) {
      active = false;
      onComplete(); // Timer finished! Run the specific action.
    } else {
      setTimeout(tick, 200); // 200ms guarantees it runs in background tabs
    }
  };
  tick();

  return () => { active = false; }; // Allows us to cancel the timer instantly
}
// ------------------------------

function showInAppPopup(src) {
  const modal = document.getElementById('yt-modal');
  const frame = document.getElementById('yt-modal-frame');
  frame.src = src;
  modal.style.display = 'block';
  dbg('Popup OPENED');
}

function hideInAppPopup() {
  const modal = document.getElementById('yt-modal');
  document.getElementById('yt-modal-frame').src = 'about:blank'; // Kill video/audio instantly
  modal.style.display = 'none';
  dbg('Popup CLOSED');
}

function dismissSplash(){
  if(autoplayUnlocked)return;
  autoplayUnlocked=true;
  const splash=document.getElementById('splash');
  splash.style.transition='opacity 0.35s';
  splash.style.opacity='0';
  setTimeout(()=>{splash.style.display='none';},380);
  dbg('Splash dismissed');
  if(pendingYTSlide){
    const s=pendingYTSlide;
    pendingYTSlide=null;
    playYouTubeNow(s); 
  }
}

function playYouTubeNow(s){
  const src=ytEmbed(s.url);
  if(!src){dbg('Bad YouTube URL: '+s.url);showSlide(idx+1);return;}
  const frame=document.getElementById('yt-frame');
  const overlay=document.getElementById('yt-click-overlay');
  overlay.style.display='none';

  if(frame._errTimer){clearTimeout(frame._errTimer);frame._errTimer=null;}
  frame.src=src;
  document.getElementById('yt-layer').classList.remove('hidden');

  frame._errTimer=setTimeout(()=>{
    if(!document.getElementById('yt-layer').classList.contains('hidden')){
      dbg('YT autoplay blocked — showing tap overlay');
      showYTClickOverlay(s);
    }
  },8000);
}

function showYTClickOverlay(s){
  const overlay=document.getElementById('yt-click-overlay');
  const titleEl=document.getElementById('yt-overlay-title');
  titleEl.textContent=s.title||'';
  overlay.style.display='flex';

  overlay.onclick=function() {
    overlay.style.display='none';
    const frame=document.getElementById('yt-frame');
    frame.src=ytEmbed(s.url);
    dbg('Overlay tapped — reloading iframe');
  };
}

function showSlide(i){
  hideInAppPopup(); // Always force clean the popup
  currentTimerCancel(); // Kill any previous timers

  if(!playlist.length){document.getElementById('empty').style.display='flex';return;}
  document.getElementById('empty').style.display='none';
  idx=((i%playlist.length)+playlist.length)%playlist.length;
  const s=playlist[idx];

  ['yt','img','vid'].forEach(k=>document.getElementById(k+'-layer').classList.add('hidden'));
  document.getElementById('yt-click-overlay').style.display='none';

  if(s.type==='youtube'){
    const src=ytEmbed(s.url);
    if(src){
      if(autoplayUnlocked){
        playYouTubeNow(s); 
      } else {
        pendingYTSlide=s;
        dbg('YT queued — waiting for splash tap');
        document.getElementById('yt-layer').classList.remove('hidden');
      }
    }
  } else if(s.type==='image'){
    document.getElementById('img-el').src=s.url;
    document.getElementById('img-layer').classList.remove('hidden');
  } else if(s.type==='video'){
    const v=document.getElementById('vid-el');v.src=s.url;v.play();
    document.getElementById('vid-layer').classList.remove('hidden');
  }

  const labels={youtube:'Live Stream',image:'Poster',video:'Video'};
  document.getElementById('type-lbl').textContent=`${labels[s.type]||s.type}  ·  ${idx+1} / ${playlist.length}`;
  document.getElementById('slide-title').textContent=s.title||'Untitled';
  document.getElementById('dots').innerHTML=playlist.map((_,di)=>
    `<div class="dot ${di===idx?'active':''}" style="${di===idx?'width:22px':'width:7px'}" onclick="jumpTo(${di})"></div>`
  ).join('');

  // Start the slide timer
  const durMs = (Number(s.duration) || 10) * 1000;
  currentTimerCancel = startTimer(durMs, () => {
    showSlide(idx + 1); // Go to next slide when done
  });
}

function jumpTo(i){
  currentTimerCancel();
  showSlide(i);
}

let interruptTimers=[],savedIdx=0,isInterrupting=false;
function setupInterrupts(slides){
  interruptTimers.forEach(t=>clearInterval(t));interruptTimers=[];
  slides.forEach(s=>{
    if(s.interrupt_every>0){
      interruptTimers.push(setInterval(()=>triggerInterrupt(s),s.interrupt_every*1000));
    }
  });
}

function triggerInterrupt(s){
  if(isInterrupting)return;
  isInterrupting=true;
  savedIdx=idx;
  currentTimerCancel(); // Pause standard playlist

  if(s.type==='youtube'){
    const src=ytEmbed(s.url);
    if(src) showInAppPopup(src);
  } else {
    // Standard full-screen interrupt
    ['yt','img','vid'].forEach(k=>document.getElementById(k+'-layer').classList.add('hidden'));
    if(s.type==='image'){
      document.getElementById('img-el').src=s.url;
      document.getElementById('img-layer').classList.remove('hidden');
    } else if(s.type==='video'){
      const v=document.getElementById('vid-el');v.src=s.url;v.play();
      document.getElementById('vid-layer').classList.remove('hidden');
    }
  }

  const labels={youtube:'Live Stream ⚡',image:'Poster ⚡',video:'Video ⚡'};
  document.getElementById('type-lbl').textContent=`${labels[s.type]||s.type} INTERRUPT · ends in ${fmtDur(s.interrupt_for)}`;
  document.getElementById('slide-title').textContent=s.title||'Untitled';

  // Start the interrupt timer
  const durMs = (Number(s.interrupt_for) || 15) * 1000;
  currentTimerCancel = startTimer(durMs, () => {
    isInterrupting = false;
    hideInAppPopup(); // SHUT FAKE POPUP
    showSlide(savedIdx); // Resume main playlist
  });
}

let fallbackTimer=null,isFallback=false,currentFallbackUrl=null;
function setupFallback(url,loopSecs,fallbackSecs){
  clearTimeout(fallbackTimer);
  currentFallbackUrl=url;
  if(!url||loopSecs<1)return;
  fallbackTimer=setTimeout(()=>triggerFallback(url,loopSecs,fallbackSecs),loopSecs*1000);
  showFallbackIndicator(loopSecs);
}

function triggerFallback(url,loopSecs,fallbackSecs){
  if(isInterrupting){fallbackTimer=setTimeout(()=>triggerFallback(url,loopSecs,fallbackSecs),30000);return;}
  isFallback=true;
  savedIdx=idx;
  currentTimerCancel(); // Pause standard playlist

  const src=ytEmbed(url);
  if(src) showInAppPopup(src); 

  document.getElementById('type-lbl').textContent=`YouTube Live  ·  returns in ${fmtDur(fallbackSecs)}`;
  document.getElementById('slide-title').textContent='Live Stream';
  document.getElementById('dots').innerHTML='';

  // Start the fallback timer
  const durMs = (Number(fallbackSecs) || 300) * 1000;
  currentTimerCancel = startTimer(durMs, () => {
    isFallback = false;
    hideInAppPopup(); // SHUT FAKE POPUP
    showSlide(savedIdx); // Resume main playlist

    // Schedule the next fallback loop
    fallbackTimer=setTimeout(()=>triggerFallback(url,loopSecs,fallbackSecs),loopSecs*1000);
    showFallbackIndicator(loopSecs);
  });
}

function showFallbackIndicator(loopSecs){
  const badge=document.getElementById('badge');let remaining=loopSecs;
  const tick=()=>{
    if(isFallback||!currentFallbackUrl)return;remaining--;
    if(remaining<=0)return;
    if(remaining<=120){badge.textContent=`⚡ YouTube in ${fmtDur(remaining)}`;badge.className='badge-ok';badge.style.opacity='1';}
    setTimeout(tick,1000);
  };
  setTimeout(tick,1000);
}

function applyOrientation(orientation,rotDir){
  dbg('applyOrientation: '+orientation+' rot='+rotDir);
  const w=document.getElementById('wrapper');if(!w)return;
  if(orientation==='portrait'){
    const deg=rotDir||90;
    w.style.cssText='position:fixed;top:50%;left:50%;right:auto;bottom:auto;width:100vh;height:100vw;overflow:hidden;';
    w.style.transformOrigin='center center';
    w.style.transform=`translate(-50%,-50%) rotate(${deg}deg)`;
  } else {
    w.style.cssText='position:fixed;top:0;left:0;right:0;bottom:0;overflow:hidden;';
    const frame=document.getElementById('yt-frame');
    if(frame&&frame.src&&frame.src.includes('youtube')){const src=frame.src;frame.src='about:blank';setTimeout(()=>{frame.src=src;},150);}
  }
}

let currentOrientation='landscape',currentRotDir=90;
function syncOrientationState(o,r){currentOrientation=o||'landscape';currentRotDir=r||90;}

function toggleOrientationLocal(){
  if(currentOrientation==='landscape'){currentOrientation='portrait';currentRotDir=90;showOsdMsg('Portrait ▮');}
  else if(currentOrientation==='portrait'&&currentRotDir===90){currentRotDir=-90;showOsdMsg('Portrait ↺');}
  else{currentOrientation='landscape';currentRotDir=90;showOsdMsg('Landscape ▬');}
  applyOrientation(currentOrientation,currentRotDir);
  if(!IS_PREVIEW){
    fetch('/api/screens/'+SCREEN_ID+'/orientation',{method:'PUT',headers:{'Content-Type':'application/json'},
      body:JSON.stringify({orientation:currentOrientation,rotation_dir:currentRotDir})});
  }
}

function showOsdMsg(msg){
  let osd=document.getElementById('osd-msg');
  if(!osd){osd=document.createElement('div');osd.id='osd-msg';
    osd.style.cssText='position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:rgba(0,0,0,.75);color:#f59e0b;font-family:monospace;font-size:28px;font-weight:bold;padding:16px 32px;border-radius:12px;z-index:99999;pointer-events:none;transition:opacity .5s';
    document.body.appendChild(osd);}
  osd.textContent=msg;osd.style.opacity='1';clearTimeout(osd._t);osd._t=setTimeout(()=>osd.style.opacity='0',1500);
}

function connect(){
  const proto=location.protocol==='https:'?'wss':'ws';
  const wsPath=IS_PREVIEW?`/ws/preview/${PREVIEW_PID}`:`/ws/screen/${SCREEN_ID}`;
  const ws=new WebSocket(`${proto}://${location.host}${wsPath}`);
  ws.onopen=()=>{
    const b=document.getElementById('badge');
    b.textContent='⬤ live';b.className='badge-ok';
    setTimeout(()=>b.style.opacity='0',3000);
    setTimeout(()=>b.style.opacity='1',30000);
    dbg('WS connected');
  };
  ws.onmessage=e=>{
    if(e.data==='pong')return;
    let msg;
    try{msg=JSON.parse(e.data);}
    catch(err){dbg('WS parse error: '+e.data);return;}

    if(msg.event==='playlist_updated'){
      dbg('playlist_updated — slides:'+msg.slides.length);
      const wasEmpty=!playlist.length;
      const prevId=playlist[idx]?.id;
      playlist=msg.slides.filter(s=>!s.interrupt_every||s.interrupt_every===0);
      const interrupts=msg.slides.filter(s=>s.interrupt_every>0);
      setupInterrupts(interrupts);
      setupFallback(msg.fallback_url||null,msg.loop_duration||1800,msg.fallback_duration||300);

      if(msg.orientation){
        syncOrientationState(msg.orientation,msg.rotation_dir||90);
        if(msg.orientation==='portrait')applyOrientation(msg.orientation,msg.rotation_dir||90);
      }
      if(!playlist.length){showSlide(0);return;}
      const ni=playlist.findIndex(s=>s.id===prevId);
      showSlide(wasEmpty?0:ni>=0?ni:0);
    }

    if(msg.event==='orientation_updated'){
      dbg('orientation_updated: '+msg.orientation);
      syncOrientationState(msg.orientation,msg.rotation_dir);
      applyOrientation(msg.orientation,msg.rotation_dir);
    }

    if(msg.event==='approve_autoplay'){
      dbg('approve_autoplay received — dismissing splash');
      dismissSplash();
    }
  };

  ws.onclose=()=>{
    const b=document.getElementById('badge');
    b.textContent='⬤ reconnecting...';b.className='badge-bad';b.style.opacity='1';
    setTimeout(connect,3000);
  };
  setInterval(()=>{if(ws.readyState===1)ws.send('ping');},20000);
}

function fmtDur(s){
  if(!s)return'0s';
  const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sec=s%60;
  if(h)return`${h}h ${m}m`;if(m)return`${m}m ${sec}s`;return`${sec}s`;
}

connect();
</script>
</body>
</html>"""

db = Database("signage.db")

async def auto_approve_task():
    import datetime
    if AUTO_APPROVE_HOUR < 0:
        print("[SignageOS] Auto-approve disabled")
        return
    print(f"[SignageOS] Auto-approve scheduled daily at {AUTO_APPROVE_HOUR:02d}:00 local time")
    while True:
        now = datetime.datetime.now()
        target = now.replace(hour=AUTO_APPROVE_HOUR, minute=0, second=0, microsecond=0)
        if now >= target:
            target += datetime.timedelta(days=1)
        wait = (target - now).total_seconds()
        print(f"[SignageOS] Next auto-approve in {wait/3600:.1f}h ({target.strftime('%H:%M')})")
        await asyncio.sleep(wait)
        count = 0
        for sid in list(manager.online_ids):
            await manager.push_to_screen(sid, {"event": "approve_autoplay"})
            count += 1
        print(f"[SignageOS] Auto-approve sent to {count} screen(s)")

@asynccontextmanager
async def lifespan(app: FastAPI):
    db.init()
    asyncio.create_task(health_monitor())
    asyncio.create_task(auto_approve_task())
    yield

app = FastAPI(title="SignageOS", lifespan=lifespan)
app.mount("/static", StaticFiles(directory="static"), name="static")
if not CLOUDINARY_CONFIGURED and Path("uploads").exists():
    app.mount("/uploads", StaticFiles(directory="uploads"), name="uploads")


class ConnManager:
    def __init__(self):
        self.screens: Dict[str, WebSocket] = {}
        self.admins: Dict[WebSocket, dict] = {}

    async def connect_screen(self, ws, sid):
        await ws.accept(); self.screens[sid] = ws

    async def connect_admin(self, ws, admin_id: int, role: str):
        await ws.accept()
        self.admins[ws] = {"admin_id": admin_id, "role": role}

    def disconnect_screen(self, sid): self.screens.pop(sid, None)
    def disconnect_admin(self, ws): self.admins.pop(ws, None)

    async def push_to_screen(self, sid, payload):
        ws = self.screens.get(sid)
        if ws:
            try: await ws.send_text(json.dumps(payload))
            except: self.screens.pop(sid, None)

    async def broadcast_admins(self, payload):
        dead = []
        for ws in list(self.admins):
            try: await ws.send_text(json.dumps(payload))
            except: dead.append(ws)
        for ws in dead: self.disconnect_admin(ws)

    async def broadcast_screens_update(self):
        dead = []
        all_screens = get_screens_with_status()
        for ws, info in list(self.admins.items()):
            try:
                if info["role"] == "superadmin":
                    filtered = all_screens
                else:
                    assigned = db.get_admin_screen_ids(info["admin_id"])
                    filtered = [s for s in all_screens if s["id"] in assigned]
                await ws.send_text(json.dumps({"event": "screens_updated", "screens": filtered}))
            except:
                dead.append(ws)
        for ws in dead: self.disconnect_admin(ws)

    @property
    def online_ids(self): return list(self.screens.keys())

manager = ConnManager()

async def health_monitor():
    while True:
        await asyncio.sleep(15)
        db.mark_screens_offline(timeout=30)
        await manager.broadcast_screens_update()

async def push_playlist_to_screen(sid):
    pid = db.resolve_playlist(sid)
    if not pid: return
    slides = db.get_active_slides(pid)
    conn = db._conn()
    try:
        pl_rows = db._execute(conn, "SELECT fallback_url, loop_duration, fallback_duration FROM playlists WHERE id=?", (pid,))
        sc_rows = db._execute(conn, "SELECT orientation, rotation_dir FROM screens WHERE id=?", (sid,))
    finally:
        conn.close()
    fallback = pl_rows[0] if pl_rows else {"fallback_url": None, "loop_duration": 1800, "fallback_duration": 300}
    screen = sc_rows[0] if sc_rows else {"orientation": "landscape", "rotation_dir": 90}
    await manager.push_to_screen(sid, {
        "event": "playlist_updated", "slides": slides,
        "fallback_url": fallback["fallback_url"], "loop_duration": fallback["loop_duration"],
        "fallback_duration": fallback["fallback_duration"],
        "orientation": screen["orientation"], "rotation_dir": screen["rotation_dir"]
    })

async def push_playlist_to_all():
    for sid in manager.online_ids:
        await push_playlist_to_screen(sid)

def get_screens_with_status():
    screens = db.get_screens()
    for s in screens:
        s["is_connected"] = s["id"] in manager.online_ids
        s["status"] = "online" if s["is_connected"] else s.get("status", "offline")
    return screens


class SlideCreate(BaseModel):
    type: str; url: str; title: str = ""; duration: int = 15
    sched_start: Optional[str] = None; sched_end: Optional[str] = None
    days_of_week: Optional[str] = None; time_start: Optional[str] = None; time_end: Optional[str] = None
    interrupt_every: int = 0; interrupt_for: int = 300

class ReorderBody(BaseModel): ids: List[int]
class PlaylistCreate(BaseModel): name: str
class ScreenUpdate(BaseModel):
    name: Optional[str] = None; group_id: Optional[int] = None; playlist_id: Optional[int] = None
class GroupCreate(BaseModel): name: str
class GroupAssign(BaseModel): playlist_id: int
class PlaylistFallback(BaseModel):
    fallback_url: Optional[str] = None; loop_duration: int = 1800; fallback_duration: int = 300
class LoginBody(BaseModel): username: str; password: str
class AdminCreate(BaseModel): username: str; password: str; role: str = "subadmin"
class ScreenAssign(BaseModel): screen_ids: List[str]
class PasswordChange(BaseModel): current_password: str; new_password: str
class PasswordReset(BaseModel): new_password: str
class OrientationUpdate(BaseModel): orientation: str; rotation_dir: int = 90


@app.get("/api/auth/test")
def api_auth_test(): return {"status": "ok", "admins": len(db.get_all_admins())}

@app.post("/api/auth/login")
def api_login(body: LoginBody):
    from fastapi.responses import JSONResponse
    admin = db.get_admin_by_username(body.username)
    if not admin or not verify_password(body.password, admin["password_hash"], admin["salt"]):
        raise HTTPException(401, "Invalid credentials")
    token = db.create_session(admin["id"])
    resp = JSONResponse({"token": token, "role": admin["role"], "username": admin["username"]})
    resp.set_cookie("session_token", token, httponly=True, max_age=604800)
    return resp

@app.post("/api/auth/logout")
def api_logout(request: Request):
    from fastapi.responses import JSONResponse
    token = get_token(request)
    if token: db.delete_session(token)
    resp = JSONResponse({"ok": True})
    resp.delete_cookie("session_token")
    return resp

@app.get("/api/auth/me")
def api_me(request: Request):
    token = get_token(request)
    if not token: raise HTTPException(401, "Not authenticated")
    session = db.verify_session(token)
    if not session: raise HTTPException(401, "Session expired")
    return {"username": session["username"], "role": session["role"], "admin_id": session["admin_id"]}

@app.put("/api/auth/password")
def api_change_my_password(request: Request, body: PasswordChange):
    session = require_auth(request)
    admin = db.get_admin_by_id(session["admin_id"])
    if not admin or not verify_password(body.current_password, admin["password_hash"], admin["salt"]):
        raise HTTPException(400, "Current password is incorrect")
    if len(body.new_password) < 6: raise HTTPException(400, "Password must be at least 6 characters")
    db.update_admin_password(session["admin_id"], body.new_password)
    return {"ok": True}

@app.get("/api/admins")
def api_get_admins(request: Request):
    require_superadmin(request)
    return {"admins": db.get_all_admins()}

@app.post("/api/admins")
async def api_create_admin(request: Request, body: AdminCreate):
    require_superadmin(request)
    if db.get_admin_by_username(body.username): raise HTTPException(400, "Username already exists")
    admin = db.create_admin(body.username, body.password, body.role)
    await manager.broadcast_admins({"event": "admins_updated", "admins": db.get_all_admins()})
    return {"admin": admin}

@app.get("/api/admins/{aid}/screens")
def api_get_admin_screens(request: Request, aid: int):
    require_superadmin(request)
    return {"screen_ids": db.get_admin_screen_ids(aid)}

@app.put("/api/admins/{aid}/password")
def api_reset_admin_password(request: Request, aid: int, body: PasswordReset):
    require_superadmin(request)
    if len(body.new_password) < 6: raise HTTPException(400, "Password must be at least 6 characters")
    db.update_admin_password(aid, body.new_password)
    return {"ok": True}

@app.delete("/api/admins/{aid}")
async def api_delete_admin(request: Request, aid: int):
    session = require_superadmin(request)
    if aid == session["admin_id"]: raise HTTPException(400, "Cannot delete yourself")
    db.delete_admin(aid)
    await manager.broadcast_admins({"event": "admins_updated", "admins": db.get_all_admins()})
    return {"ok": True}

@app.put("/api/admins/{aid}/screens")
async def api_assign_screens(request: Request, aid: int, body: ScreenAssign):
    require_superadmin(request)
    conn = db._conn()
    try:
        db._execute(conn, "DELETE FROM admin_screens WHERE admin_id=?", (aid,))
        for sid in body.screen_ids:
            if USE_PG:
                db._execute(conn, "INSERT INTO admin_screens (admin_id, screen_id) VALUES (?,?) ON CONFLICT DO NOTHING", (aid, sid))
            else:
                db._execute(conn, "INSERT OR IGNORE INTO admin_screens (admin_id, screen_id) VALUES (?,?)", (aid, sid))
        conn.commit()
    finally:
        conn.close()
    return {"ok": True}

@app.post("/api/screens/approve-autoplay")
async def api_approve_autoplay(request: Request):
    require_auth(request)
    for sid in manager.online_ids:
        await manager.push_to_screen(sid, {"event": "approve_autoplay"})
    return {"ok": True, "screens": len(manager.online_ids)}

@app.put("/api/screens/{sid}/orientation")
async def api_screen_orientation(request: Request, sid: str, body: OrientationUpdate):
    token = get_token(request)
    if token: require_auth(request)
    db.update_screen_orientation(sid, body.orientation, body.rotation_dir)
    await manager.push_to_screen(sid, {"event": "orientation_updated", "orientation": body.orientation, "rotation_dir": body.rotation_dir})
    await manager.broadcast_screens_update()
    return {"ok": True}

@app.get("/api/playlists")
def api_get_playlists(): return {"playlists": db.get_playlists()}

@app.post("/api/playlists")
async def api_add_playlist(body: PlaylistCreate):
    p = db.add_playlist(body.name.strip())
    await manager.broadcast_admins({"event": "playlists_updated", "playlists": db.get_playlists()})
    return {"playlist": p}

@app.put("/api/playlists/{pid}/fallback")
async def api_set_fallback(pid: int, body: PlaylistFallback):
    db.update_playlist_fallback(pid, body.fallback_url, body.loop_duration, body.fallback_duration)
    await manager.broadcast_admins({"event": "playlists_updated", "playlists": db.get_playlists()})
    await push_playlist_to_all()
    return {"ok": True}

@app.delete("/api/playlists/{pid}")
async def api_del_playlist(pid: int):
    db.delete_playlist(pid)
    await manager.broadcast_admins({"event": "playlists_updated", "playlists": db.get_playlists()})
    return {"ok": True}

@app.put("/api/playlists/{pid}/rename")
async def api_rename_playlist(pid: int, body: PlaylistCreate):
    db.rename_playlist(pid, body.name.strip())
    await manager.broadcast_admins({"event": "playlists_updated", "playlists": db.get_playlists()})
    return {"ok": True}

@app.get("/api/playlists/{pid}/slides")
def api_get_slides(pid: int): return {"slides": db.get_slides(pid)}

@app.post("/api/playlists/{pid}/slides")
async def api_add_slide(pid: int, slide: SlideCreate):
    if not slide.url.strip(): raise HTTPException(400, "URL required")
    s = db.add_slide(pid, slide.type, slide.url.strip(), slide.title.strip(), slide.duration,
                     slide.sched_start, slide.sched_end, slide.days_of_week, slide.time_start, slide.time_end,
                     slide.interrupt_every, slide.interrupt_for)
    await push_playlist_to_all()
    await manager.broadcast_admins({"event": "slides_updated", "playlist_id": pid, "slides": db.get_slides(pid)})
    return {"slide": s}

@app.delete("/api/slides/{sid}")
async def api_del_slide(sid: int):
    pid = db.get_slide_playlist(sid)
    db.delete_slide(sid)
    await push_playlist_to_all()
    if pid: await manager.broadcast_admins({"event": "slides_updated", "playlist_id": pid, "slides": db.get_slides(pid)})
    return {"ok": True}

@app.put("/api/slides/{sid}/toggle")
async def api_toggle_slide(sid: int):
    pid = db.get_slide_playlist(sid)
    db.toggle_slide(sid)
    await push_playlist_to_all()
    if pid: await manager.broadcast_admins({"event": "slides_updated", "playlist_id": pid, "slides": db.get_slides(pid)})
    return {"ok": True}

@app.put("/api/playlists/{pid}/reorder")
async def api_reorder(pid: int, body: ReorderBody):
    db.reorder_slides(body.ids)
    await push_playlist_to_all()
    await manager.broadcast_admins({"event": "slides_updated", "playlist_id": pid, "slides": db.get_slides(pid)})
    return {"ok": True}

ALLOWED = {"image/jpeg","image/png","image/gif","image/webp","image/svg+xml","video/mp4","video/webm","video/ogg"}

@app.post("/api/upload")
async def api_upload(file: UploadFile = File(...)):
    if file.content_type not in ALLOWED: raise HTTPException(400, f"File type not allowed: {file.content_type}")
    slide_type = "image" if file.content_type.startswith("image") else "video"
    if CLOUDINARY_CONFIGURED:
        contents = await file.read()
        result = cloudinary.uploader.upload(contents, resource_type=slide_type,
            folder="signageos", public_id=uuid.uuid4().hex, overwrite=False)
        url = result["secure_url"]
    else:
        ext = Path(file.filename).suffix
        filename = f"{uuid.uuid4().hex}{ext}"
        dest = Path("uploads") / filename
        with open(dest, "wb") as f: shutil.copyfileobj(file.file, f)
        url = f"/uploads/{filename}"
    return {"url": url, "type": slide_type, "filename": file.filename}

@app.get("/api/screens")
def api_get_screens(request: Request):
    session = require_auth(request)
    db.mark_screens_offline(timeout=30)
    screens = db.get_screens_for_admin(session["admin_id"], session["role"])
    for s in screens:
        s["is_connected"] = s["id"] in manager.online_ids
        s["status"] = "online" if s["is_connected"] else s.get("status","offline")
    return {"screens": screens}

@app.put("/api/screens/{sid}")
async def api_update_screen(sid: str, body: ScreenUpdate):
    db.update_screen(sid, body.name, body.group_id, body.playlist_id)
    if body.playlist_id is not None: await push_playlist_to_screen(sid)
    await manager.broadcast_screens_update()
    return {"ok": True}

@app.delete("/api/screens/{sid}")
async def api_del_screen(sid: str):
    db.delete_screen(sid)
    await manager.broadcast_screens_update()
    return {"ok": True}

@app.delete("/api/screens")
async def api_del_offline_screens(request: Request):
    require_superadmin(request)
    conn = db._conn()
    try:
        rows = db._execute(conn, """SELECT id FROM screens WHERE status='offline'
            AND (last_seen < datetime('now','-1 day') OR last_seen IS NULL)""")
        for r in rows:
            db._execute(conn, "DELETE FROM admin_screens WHERE screen_id=?", (r["id"],))
            db._execute(conn, "DELETE FROM screens WHERE id=?", (r["id"],))
        conn.commit(); count = len(rows)
    finally:
        conn.close()
    await manager.broadcast_screens_update()
    return {"ok": True, "deleted": count}

@app.get("/api/groups")
def api_get_groups(): return {"groups": db.get_groups()}

@app.post("/api/groups")
async def api_add_group(body: GroupCreate):
    g = db.add_group(body.name.strip())
    await manager.broadcast_admins({"event": "groups_updated", "groups": db.get_groups()})
    return {"group": g}

@app.delete("/api/groups/{gid}")
async def api_del_group(gid: int):
    db.delete_group(gid)
    await manager.broadcast_admins({"event": "groups_updated", "groups": db.get_groups()})
    return {"ok": True}

@app.put("/api/groups/{gid}/rename")
async def api_rename_group(gid: int, body: GroupCreate):
    db.rename_group(gid, body.name.strip())
    await manager.broadcast_admins({"event": "groups_updated", "groups": db.get_groups()})
    return {"ok": True}

@app.put("/api/groups/{gid}/assign")
async def api_group_assign(gid: int, body: GroupAssign):
    db.assign_playlist_to_group(gid, body.playlist_id)
    for s in db.get_screens():
        if s["group_id"] == gid and s["id"] in manager.online_ids:
            await push_playlist_to_screen(s["id"])
    await manager.broadcast_screens_update()
    return {"ok": True}

@app.websocket("/ws/screen/{screen_id}")
async def ws_screen(ws: WebSocket, screen_id: str):
    ip = ws.client.host if ws.client else None
    db.upsert_screen(screen_id, ip, ws.headers.get("user-agent", ""))
    await manager.connect_screen(ws, screen_id)
    await manager.broadcast_screens_update()
    await push_playlist_to_screen(screen_id)
    try:
        while True:
            data = await ws.receive_text()
            if data == "ping":
                db.heartbeat_screen(screen_id)
                await ws.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect_screen(screen_id)
        db.mark_screens_offline(timeout=5)
        await manager.broadcast_screens_update()

@app.websocket("/ws/preview/{playlist_id}")
async def ws_preview(ws: WebSocket, playlist_id: int):
    await ws.accept()
    try:
        slides = db.get_active_slides(playlist_id)
        conn = db._conn()
        try:
            rows = db._execute(conn, "SELECT fallback_url, loop_duration, fallback_duration FROM playlists WHERE id=?", (playlist_id,))
        finally:
            conn.close()
        fallback = rows[0] if rows else {"fallback_url": None, "loop_duration": 1800, "fallback_duration": 300}
        await ws.send_text(json.dumps({
            "event": "playlist_updated", "slides": slides,
            "fallback_url": fallback["fallback_url"], "loop_duration": fallback["loop_duration"],
            "fallback_duration": fallback["fallback_duration"],
            "orientation": "landscape", "rotation_dir": 90
        }))
        while True:
            data = await ws.receive_text()
            if data == "ping": await ws.send_text("pong")
    except WebSocketDisconnect:
        pass

@app.websocket("/ws/admin")
async def ws_admin(ws: WebSocket, token: str = ""):
    session = db.verify_session(token) if token else None
    if not session:
        await ws.accept(); await ws.close(code=4001); return
    await manager.connect_admin(ws, session["admin_id"], session["role"])
    await manager.broadcast_screens_update()
    try:
        while True:
            if await ws.receive_text() == "ping":
                await ws.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect_admin(ws)

@app.get("/login", response_class=HTMLResponse)
async def login_page(request: Request):
    return HTMLResponse(content=LOGIN_HTML)

@app.get("/", response_class=HTMLResponse)
async def admin_page(request: Request):
    return HTMLResponse(content=ADMIN_HTML)

@app.get("/display", response_class=HTMLResponse)
async def display_page(request: Request):
    resp = HTMLResponse(content=DISPLAY_HTML)
    resp.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    resp.headers["Expires"] = "0"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.get("/yt-wrapper", response_class=HTMLResponse)
async def yt_wrapper_page(url: str, duration: int):
    html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <title>Live Stream</title>
    <style>
        body, html {{ margin: 0; padding: 0; width: 100%; height: 100%; overflow: hidden; background: #000; color: white; font-family: sans-serif; }}
        iframe {{ width: 100%; height: 100%; border: none; }}
        #timer {{ position: absolute; top: 15px; right: 15px; background: rgba(0,0,0,0.8); padding: 8px 14px; border-radius: 8px; font-size: 14px; font-weight: bold; z-index: 9999; border: 1px solid #333; pointer-events: none; }}
    </style>
</head>
<body>
    <div id="timer">Closing in {duration}s</div>
    <iframe src="{url}" allow="autoplay; fullscreen; encrypted-media"></iframe>
    <script>
        let timeLeft = {duration};
        const timerEl = document.getElementById('timer');
        const countdown = setInterval(() => {{
            timeLeft--;
            if(timeLeft >= 0) timerEl.innerText = `Closing in ${{timeLeft}}s`;
        }}, 1000);

        // Add 100ms - 900ms of random jitter to bypass YouTube bot detection
        const jitter = Math.floor(Math.random() * 800) + 100;
        setTimeout(() => {{
            clearInterval(countdown);
            timerEl.innerText = "Closing...";
            window.close();
        }}, ({duration} * 1000) + jitter);
    </script>
</body>
</html>"""
    return HTMLResponse(content=html_content)

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("main2:app", host="0.0.0.0", port=port, reload=False)