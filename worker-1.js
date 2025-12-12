// Cloudflare Workers 节点管理系统 v10.8 (界面现代化版)
// ==========================================
// 更新日志 v10.8:
// 1. [优化] 全面现代化界面设计，采用更现代的配色和布局
// 2. [调整] 将"包含自定义 IP 池"选项移到提取测试的反选按钮旁边
// 3. [调整] 将"包含自定义IP"和"自动更新"选项移到文件生成的反选按钮旁边
// 4. [增强] 添加更多微交互效果和动画
// 5. [优化] 改进响应式设计，提升移动端体验
// ==========================================

const KV_BINDING_NAME = "IP_NODES"; 
const R2_BUCKET_NAME = "NODE_FILES"; 
const TG_FILE_LIMIT = 5 * 1024 * 1024;

// ==========================================
// 1. 核心工具模块 (后端用)
// ==========================================
const IPExtractor = {
  COMMON_PORTS: new Set([80, 443, 8080, 8443, 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8880]),
  SMALL_PORT_WHITELIST: new Set([21, 22, 53, 80]),
  
  isValidIP(ip) {
    if (!ip || typeof ip !== 'string') return false;
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipv4Regex.test(ip);
  },
  
  processBatch(text) {
    const lines = Array.isArray(text) ? text : text.split('\n');
    const results = [];
    let ipColIndex = -1;
    let portColIndex = -1;

    if (lines.length > 0) {
        const firstLineParts = lines[0].split(/[,\t|;\s#]+/);
        const hasIPInFirstLine = firstLineParts.some(p => this.isValidIP(p.split(':')[0]));

        if (!hasIPInFirstLine) {
            const lowerCaseParts = firstLineParts.map(p => p.toLowerCase().trim().replace(/"/g, ''));
            const ipHeaders = ['ip', 'address', 'host', '服务器', '地址', 'ip地址'];
            const portHeaders = ['port', '端口'];
            ipColIndex = lowerCaseParts.findIndex(p => ipHeaders.includes(p));
            portColIndex = lowerCaseParts.findIndex(p => portHeaders.includes(p));
        }
    }

    for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line) continue;

        if (line.includes('server=') && (line.startsWith('tg://') || line.includes('t.me/'))) {
            try {
                const serverMatch = line.match(/server=([^&]+)/);
                const portMatch = line.match(/port=([^&]+)/);
                if (serverMatch && this.isValidIP(serverMatch[1])) {
                    results.push({
                        ip: serverMatch[1],
                        port: portMatch ? portMatch[1] : '443',
                        remark: '' 
                    });
                    continue; 
                }
            } catch(e) {}
        }

        const parts = line.split(/[,\t|;\s#]+/).map(p => p.trim().replace(/"/g, ''));
        let ip = '';
        let port = '';
        let extractedRemark = '';
        
        if (ipColIndex !== -1 && parts[ipColIndex] && this.isValidIP(parts[ipColIndex])) {
            ip = parts[ipColIndex];
        }
        if (portColIndex !== -1 && parts[portColIndex]) {
            const val = parseInt(parts[portColIndex], 10);
            if (!isNaN(val) && val > 0 && val <= 65535) port = String(val);
        }

        if (!ip) {
            let ipIndex = parts.findIndex(p => this.isValidIP(p.split(':')[0]));
            if (ipIndex === -1) continue; 
            const ipPart = parts[ipIndex];
            if (ipPart.includes(':')) {
                const [baseIp, basePort] = ipPart.split(':');
                ip = baseIp;
                const pVal = parseInt(basePort);
                if (!isNaN(pVal) && pVal > 0 && pVal <= 65535) {
                    if (pVal < 100 && !this.SMALL_PORT_WHITELIST.has(pVal)) port = '';
                    else port = basePort;
                }
            } else {
                ip = ipPart;
            }
        }

        if (!port) {
            let bestPort = '443';
            let maxScore = -1;
            const ipIndex = parts.findIndex(p => this.isValidIP(p.split(':')[0]));
            parts.forEach((p, idx) => {
                if (idx === ipIndex) return;
                if (!/^\d+$/.test(p)) return;
                const val = parseInt(p, 10);
                if (isNaN(val) || val <= 0 || val > 65535) return;
                if (val > 10000) return;
                let score = 0;
                if (this.COMMON_PORTS.has(val)) score += 100;
                if (val > 100) score += 10;
                const distFromEnd = parts.length - 1 - idx;
                if (distFromEnd <= 1) score += 20;
                if (score > maxScore) { maxScore = score; bestPort = p; }
            });
            if (maxScore > 0) port = bestPort;
        }

        const remarkParts = parts.filter((p, i) => {
            if (this.isValidIP(p.split(':')[0])) return false;
            if (p === port) return false;
            if (/^[\d.]+$/.test(p)) return false; 
            return true;
        });

        if (remarkParts.length > 0) extractedRemark = remarkParts.join(' ').trim(); 

        if (ip) results.push({ ip, port: port || '443', remark: extractedRemark });
    }
    return results;
  },
  
  deduplicateIPs(ipList) {
    const seen = new Set();
    const deduplicated = [];
    for (const item of ipList) {
      const key = `${item.ip}:${item.port || 443}`;
      if (!seen.has(key)) {
        seen.add(key);
        deduplicated.push(item);
      }
    }
    return deduplicated;
  }
};

// ==========================================
// 2. 缓存管理器
// ==========================================
const CacheManager = {
  getCacheKey(type, name) { return `cache_v10_${type}_${name}`; },
  async setCache(env, type, key, data) { await env[KV_BINDING_NAME].put(this.getCacheKey(type, key), JSON.stringify(data), { expirationTtl: 1800 }); },
  async getCache(env, type, key) { return await env[KV_BINDING_NAME].get(this.getCacheKey(type, key), { type: 'json' }); },
  async clearCache(env, type, key) { await env[KV_BINDING_NAME].delete(this.getCacheKey(type, key)); },
  async clearTypeCache(env, type) {
    const list = await env[KV_BINDING_NAME].list({ prefix: `cache_v10_${type}_` });
    for (const key of list.keys) await env[KV_BINDING_NAME].delete(key.name);
  }
};

// ==========================================
// 3. R2存储管理器
// ==========================================
const R2Manager = {
  getPath(type, name) {
    const paths = { upload: `uploads/${name}`, generated: `generated/${name}`, config: `config/${name}.json`, stats: `stats/${name}.json`, editable: `editable/${name}.json` };
    return paths[type] || name;
  },
  async save(env, type, name, content, metadata = {}) {
    const path = this.getPath(type, name);
    try {
      const body = typeof content === 'object' ? JSON.stringify(content) : content;
      const contentType = typeof content === 'object' ? 'application/json' : 'text/plain; charset=utf-8';
      await env[R2_BUCKET_NAME].put(path, body, { httpMetadata: { contentType, ...metadata }, customMetadata: { type, name, updatedAt: new Date().toISOString() } });
      return true;
    } catch (error) { console.error(`R2 save error:`, error); return false; }
  },
  async read(env, type, name) {
    const path = this.getPath(type, name);
    try {
      const object = await env[R2_BUCKET_NAME].get(path);
      if (!object) return null;
      if (type === 'config' || type === 'stats' || type === 'editable') return await object.json();
      return await object.text();
    } catch (error) { return null; }
  },
  async delete(env, type, name) {
    const path = this.getPath(type, name);
    try { await env[R2_BUCKET_NAME].delete(path); return true; } catch (error) { return false; }
  }
};

// ==========================================
// 4. 数据访问层
// ==========================================
const DataAccessLayer = {
  async readFile(env, type, name) {
    const cached = await CacheManager.getCache(env, 'file_content', name);
    if (cached) return cached;
    const content = await R2Manager.read(env, type, name);
    if (content) {
      if (content.length < 10 * 1024 * 1024) await CacheManager.setCache(env, 'file_content', name, content);
    }
    return content;
  },
  async writeFile(env, type, name, content) {
    const saved = await R2Manager.save(env, type, name, content);
    if (saved) {
      if (content.length < 10 * 1024 * 1024) await CacheManager.setCache(env, 'file_content', name, content);
      else await CacheManager.clearCache(env, 'file_content', name);
    }
    return saved;
  },
  async deleteFile(env, type, name) {
    await CacheManager.clearCache(env, 'file_content', name);
    return await R2Manager.delete(env, type, name);
  },
  async readConfig(env, key, defaultValue = [], forceRefresh = false) {
    if (!forceRefresh) { const cached = await CacheManager.getCache(env, 'metadata', key); if (cached) return cached; }
    const data = await R2Manager.read(env, 'config', key);
    const result = data || defaultValue;
    await CacheManager.setCache(env, 'metadata', key, result);
    return result;
  },
  async writeConfig(env, key, data) {
    await R2Manager.save(env, 'config', key, data);
    await CacheManager.setCache(env, 'metadata', key, data);
  },
  async getManifest(env) {
    const cached = await CacheManager.getCache(env, 'manifest', 'all');
    if (cached) return cached;
    const data = await R2Manager.read(env, 'config', 'manifest');
    const result = data || {};
    await CacheManager.setCache(env, 'manifest', 'all', result);
    return result;
  },
  async updateManifest(env, fileName, metaData) {
    const manifest = await this.getManifest(env);
    if (metaData === null) delete manifest[fileName]; else manifest[fileName] = metaData;
    await R2Manager.save(env, 'config', 'manifest', manifest);
    await CacheManager.setCache(env, 'manifest', 'all', manifest);
    return manifest;
  },
  async getStats(env, fileName) {
    let stats = await env[KV_BINDING_NAME].get(`stats_${fileName}`, { type: 'json' });
    if (!stats) stats = await R2Manager.read(env, 'stats', `stats_${fileName}`);
    return stats || { total: 0, today: 0, lastAccess: null };
  },
  async updateStats(env, fileName, statsData) {
    await env[KV_BINDING_NAME].put(`stats_${fileName}`, JSON.stringify(statsData));
  },
  async syncStatsToR2(env) {
    const list = await env[KV_BINDING_NAME].list({ prefix: 'stats_' });
    for (const key of list.keys) {
        try { const data = await env[KV_BINDING_NAME].get(key.name, { type: 'json' }); if (data) await R2Manager.save(env, 'stats', key.name, data); } catch(e) {}
    }
  },
  async getEditableFile(env, fileName) { return await R2Manager.read(env, 'editable', fileName); },
  async saveEditableFile(env, fileName, data) { return await R2Manager.save(env, 'editable', fileName, data); },
  async deleteEditableFile(env, fileName) { return await R2Manager.delete(env, 'editable', fileName); }
};

// ==========================================
// 5. Worker 入口
// ==========================================
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (path === '/api/tg_hook' && request.method === 'POST') return await handleTelegramWebhook(request, env);
    if (!env.ADMIN_PASSWORD) return new Response("配置错误: 请在环境变量中设置 ADMIN_PASSWORD", { status: 500 });
    if (path.startsWith('/r2/')) return await handleR2FileAccess(request, env, ctx, path);
    if ((path.startsWith('/ip/') && path.length > 4) || (path.length > 1 && path !== '/admin' && path !== '/' && !path.startsWith('/api/'))) return await handleIPFile(request, env, ctx, path);
    if (path === '/admin' || path === '/') return await handleAdmin(request, env);
    if (path.startsWith('/api/')) return await handleAPI(request, env, path);
    return Response.redirect(url.origin + '/admin', 302);
  },
  async scheduled(event, env, ctx) { ctx.waitUntil(handleCronJob(env)); }
};

// ==========================================
// 6. 核心处理函数
// ==========================================
async function handleR2FileAccess(request, env, ctx, path) {
  const fileName = path.replace('/r2/', '');
  try {
    const manifest = await DataAccessLayer.getManifest(env);
    const fileMeta = manifest[fileName];
    let content;
    if (fileMeta && fileMeta.editable) {
       const editableData = await DataAccessLayer.getEditableFile(env, fileName);
       if (editableData && editableData.ips) {
        content = editableData.ips.map(ip => ip.port ? `${ip.ip}:${ip.port}${ip.remark ? '#' + ip.remark : ''}` : `${ip.ip}${ip.remark ? '#' + ip.remark : ''}`).join('\n');
       }
    } else {
      const object = await env[R2_BUCKET_NAME].get(`generated/${fileName}`);
      if (!object) return new Response('File not found in R2 (Generated)', { status: 404 });
      content = await object.text();
    }
    if (!content) return new Response('File not found', { status: 404 });
    ctx.waitUntil(updateFileStats(env, fileName));
    return new Response(content, { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0' } });
  } catch (error) { return new Response(`Error: ${error.message}`, { status: 500 }); }
}

async function handleIPFile(request, env, ctx, path) {
  const fileName = path.replace('/ip/', '').replace(/^\//, '');
  try {
    const manifest = await DataAccessLayer.getManifest(env);
    const fileMeta = manifest[fileName];
    let content;
    if (fileMeta && fileMeta.editable) {
      const editableData = await DataAccessLayer.getEditableFile(env, fileName);
      if (editableData && editableData.ips) {
        content = editableData.ips.map(ip => ip.port ? `${ip.ip}:${ip.port}${ip.remark ? '#' + ip.remark : ''}` : `${ip.ip}${ip.remark ? '#' + ip.remark : ''}`).join('\n');
      }
    } else {
      content = await DataAccessLayer.readFile(env, 'generated', fileName);
    }
    if (!content) return new Response('IP file not found', { status: 404 });
    ctx.waitUntil(updateFileStats(env, fileName));
    return new Response(content, { headers: { 'Content-Type': 'text/plain; charset=utf-8', 'Access-Control-Allow-Origin': '*', 'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0' } });
  } catch (error) { return new Response('Error', { status: 500 }); }
}

async function updateFileStats(env, fileName) {
    try {
        let stats = await DataAccessLayer.getStats(env, fileName);
        const now = new Date();
        const beijingTime = new Date(now.toLocaleString("en-US", {timeZone: "Asia/Shanghai"}));
        const todayStr = beijingTime.toISOString().split('T')[0];
        if (stats.date !== todayStr) { stats.date = todayStr; stats.today = 0; }
        stats.total = (stats.total || 0) + 1; 
        stats.today = (stats.today || 0) + 1;
        stats.lastAccess = now.toISOString();
        await DataAccessLayer.updateStats(env, fileName, stats);
    } catch(e) {}
}

async function handleCronJob(env) {
  try {
    await CacheManager.clearTypeCache(env, 'file_content');
    await DataAccessLayer.syncStatsToR2(env);
    const manifest = await DataAccessLayer.getManifest(env);
    let updatedCount = 0;
    for (const [fileName, meta] of Object.entries(manifest)) {
      if (meta && meta.autoUpdate && !meta.editable) {
        const r = await performExtraction(env, meta.sources);
        await DataAccessLayer.writeFile(env, 'generated', fileName, r.join('\n'));
        meta.lastUpdate = new Date().toISOString(); 
        await DataAccessLayer.updateManifest(env, fileName, meta);
        updatedCount++;
      }
    }
    console.log(`Cron job finished. Updated ${updatedCount} files.`);
  } catch (e) { console.error("Cron job failed:", e); }
}

// ==========================================
// 7. API 逻辑
// ==========================================
async function handleAPI(request, env, path) {
  const session = await checkSession(request, env);
  if (!session && path !== '/api/login') return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401 });
  const apiAction = path.replace('/api/', '');
  try {
    switch (apiAction) {
      case 'urls':
      case 'apis':
      case 'custom':
          const key = apiAction === 'custom' ? 'custom_ips' : apiAction;
          if (request.method === 'GET') return new Response(JSON.stringify(await DataAccessLayer.readConfig(env, key)));
          if (request.method === 'POST') return await addItem(request, env, apiAction);
          if (request.method === 'DELETE' && apiAction !== 'custom') return await deleteItem(request, env, apiAction);
          break;
      case 'sites':
          if (request.method === 'GET') return new Response(JSON.stringify(await DataAccessLayer.readConfig(env, 'sites_list')));
          if (request.method === 'POST') return await addSite(request, env);
          if (request.method === 'DELETE') return await deleteSite(request, env);
          break;
      case 'uploaded_files':
          if (request.method === 'GET') return new Response(JSON.stringify(await DataAccessLayer.readConfig(env, 'uploaded_files')));
          if (request.method === 'DELETE') return await deleteUploadedFile(request, env);
          break;
      case 'upload': return await handleUpload(request, env);
      case 'extract': return await extractIPs(request, env);
      case 'ipfiles':
        if (request.method === 'GET') return await getIPFiles(env);
        if (request.method === 'POST') return await saveIPFile(request, env);
        if (request.method === 'DELETE') return await deleteIPFile(request, env);
        if (request.method === 'PUT') return await updateIPFile(request, env);
        if (request.method === 'PATCH') return await editIPFileSources(request, env);
        break;
      case 'editable_files':
        if (request.method === 'GET') return await getEditableFiles(env);
        if (request.method === 'POST') return await saveEditableFileAPI(request, env);
        if (request.method === 'DELETE') return await deleteEditableFileAPI(request, env);
        if (request.method === 'PUT') return await updateEditableFile(request, env);
        break;
      case 'reset-stats': return await resetFileStats(request, env);
      case 'tool_query': return await handleToolQuery(request);
      case 'logout': return await logout(request, env);
    }
  } catch (error) { return new Response(JSON.stringify({ error: error.message }), { status: 500 }); }
  return new Response('Not Found', { status: 404 });
}

async function addItem(req, env, act) {
  const b = await req.json(); 
  const k = act === 'custom' ? 'custom_ips' : act; 
  let list = [];
  if(act === 'custom') list = b.ips || [];
  else list = b.items || [];
  if(act !== 'custom') { 
      let old = await DataAccessLayer.readConfig(env, k);
      old = old.map(x => typeof x === 'string' ? {name:'', url:x} : x);
      list = [...old, ...list];
  }
  await DataAccessLayer.writeConfig(env, k, list);
  return new Response(JSON.stringify({success:true}));
}

async function deleteItem(req, env, key) {
  const b = await req.json(); 
  let l = await DataAccessLayer.readConfig(env, key);
  if (b.index >= 0) { l.splice(b.index, 1); await DataAccessLayer.writeConfig(env, key, l); return new Response(JSON.stringify({ success: true, index: b.index })); }
  return new Response(JSON.stringify({ error: 'Invalid index' }), { status: 400 });
}

async function addSite(req, env) {
    const b = await req.json(); 
    let l = await DataAccessLayer.readConfig(env, 'sites_list');
    l.push(b);
    await DataAccessLayer.writeConfig(env, 'sites_list', l);
    return new Response(JSON.stringify({ success: true }));
}

async function deleteSite(req, env) {
    const b = await req.json(); 
    let l = await DataAccessLayer.readConfig(env, 'sites_list');
    if(b.index >= 0) { l.splice(b.index, 1); await DataAccessLayer.writeConfig(env, 'sites_list', l); return new Response(JSON.stringify({ success: true })); }
    return new Response(JSON.stringify({ error: 'Invalid index' }));
}

// --- 文件管理相关 ---
async function getIPFiles(env) {
  const manifest = await DataAccessLayer.getManifest(env);
  const result = [];
  for (const [name, meta] of Object.entries(manifest)) {
      if(!meta) continue;
      const stats = await DataAccessLayer.getStats(env, name);
      result.push({ ...meta, stats });
  }
  return new Response(JSON.stringify(result));
}

async function saveIPFile(req, env) {
  const b = await req.json(); 
  const r = await performExtraction(env, b.sources, true); 
  const meta = { name: b.fileName, sources: b.sources, autoUpdate: b.autoUpdate, lastUpdate: new Date().toISOString() };
  const saved = await DataAccessLayer.writeFile(env, 'generated', b.fileName, r.join('\n'));
  if (!saved) return new Response(JSON.stringify({ error: 'R2 Write Failed' }), { status: 500 });
  await DataAccessLayer.updateManifest(env, b.fileName, meta);
  await DataAccessLayer.updateStats(env, b.fileName, { total: 0, today: 0, lastAccess: null });
  return new Response(JSON.stringify({ success: true, count: r.length, meta }));
}

async function deleteIPFile(req, env) {
  const n = new URL(req.url).searchParams.get('name');
  if (!n) return new Response(JSON.stringify({ error: 'Missing name' }), { status: 400 });
  const manifest = await DataAccessLayer.getManifest(env);
  const fileMeta = manifest[n];
  await DataAccessLayer.deleteFile(env, 'generated', n);
  if (fileMeta && fileMeta.editable) await DataAccessLayer.deleteEditableFile(env, n);
  await DataAccessLayer.updateManifest(env, n, null); 
  await env[KV_BINDING_NAME].delete(`stats_${n}`);
  return new Response(JSON.stringify({ success: true, fileName: n }));
}

async function updateIPFile(req, env) {
    const b = await req.json();
    const manifest = await DataAccessLayer.getManifest(env);
    const meta = manifest[b.fileName];
    if (!meta) throw new Error('File not found');
    if (meta.editable) return new Response(JSON.stringify({ error: 'Editable files cannot be auto-updated' }), { status: 400 });
    const r = await performExtraction(env, meta.sources, true); 
    await DataAccessLayer.writeFile(env, 'generated', b.fileName, r.join('\n'));
    meta.lastUpdate = new Date().toISOString();
    await DataAccessLayer.updateManifest(env, b.fileName, meta);
    return new Response(JSON.stringify({ success: true, count: r.length, meta }));
}

async function editIPFileSources(req, env) {
    const b = await req.json();
    const manifest = await DataAccessLayer.getManifest(env);
    const meta = manifest[b.fileName];
    if (!meta) throw new Error('File not found');
    if (meta.editable) return new Response(JSON.stringify({ error: 'Editable files cannot change sources' }), { status: 400 });
    const updatedMeta = { ...meta, sources: b.sources, autoUpdate: b.autoUpdate !== undefined ? b.autoUpdate : meta.autoUpdate, lastUpdate: new Date().toISOString() };
    const r = await performExtraction(env, b.sources, true);
    await DataAccessLayer.writeFile(env, 'generated', b.fileName, r.join('\n'));
    await DataAccessLayer.updateManifest(env, b.fileName, updatedMeta);
    return new Response(JSON.stringify({ success: true, count: r.length, meta: updatedMeta }));
}

async function resetFileStats(req, env) {
    const { fileName } = await req.json();
    await DataAccessLayer.updateStats(env, fileName, { total: 0, today: 0, lastAccess: null });
    await R2Manager.save(env, 'stats', `stats_${fileName}`, { total: 0, today: 0, lastAccess: null });
    return new Response(JSON.stringify({ success: true }));
}

// --- 可编辑文件相关 ---
async function getEditableFiles(env) {
  const manifest = await DataAccessLayer.getManifest(env);
  const result = [];
  for (const [name, meta] of Object.entries(manifest)) {
    if (meta.editable) {
      const stats = await DataAccessLayer.getStats(env, name);
      const editableData = await DataAccessLayer.getEditableFile(env, name);
      result.push({ ...meta, stats, ips: editableData ? editableData.ips : [] });
    }
  }
  return new Response(JSON.stringify(result));
}

async function saveEditableFileAPI(req, env) {
  const b = await req.json();
  const { fileName, ips } = b;
  if (!fileName || !ips || !Array.isArray(ips)) return new Response(JSON.stringify({ error: 'Invalid parameters' }), { status: 400 });
  const saved = await DataAccessLayer.saveEditableFile(env, fileName, { ips });
  if (!saved) return new Response(JSON.stringify({ error: 'R2 Write Failed' }), { status: 500 });
  const meta = { name: fileName, editable: true, lastUpdate: new Date().toISOString(), autoUpdate: false };
  await DataAccessLayer.updateManifest(env, fileName, meta);
  await DataAccessLayer.updateStats(env, fileName, { total: 0, today: 0, lastAccess: null });
  return new Response(JSON.stringify({ success: true, count: ips.length, meta }));
}

async function deleteEditableFileAPI(req, env) {
  const b = await req.json();
  const { fileName } = b;
  if (!fileName) return new Response(JSON.stringify({ error: 'Missing fileName' }), { status: 400 });
  await DataAccessLayer.deleteEditableFile(env, fileName);
  await DataAccessLayer.updateManifest(env, fileName, null); 
  await env[KV_BINDING_NAME].delete(`stats_${fileName}`);
  return new Response(JSON.stringify({ success: true, fileName }));
}

async function updateEditableFile(req, env) {
  const b = await req.json();
  const { fileName, ips } = b;
  if (!fileName || !ips || !Array.isArray(ips)) return new Response(JSON.stringify({ error: 'Invalid parameters' }), { status: 400 });
  
  const saved = await DataAccessLayer.saveEditableFile(env, fileName, { ips });
  if (!saved) return new Response(JSON.stringify({ error: 'R2 Write Failed' }), { status: 500 });
  
  const manifest = await DataAccessLayer.getManifest(env);
  let meta = manifest[fileName];
  
  if (!meta) {
      meta = { name: fileName, editable: true, autoUpdate: false, sources: {}, lastUpdate: new Date().toISOString() };
  } else {
      meta.lastUpdate = new Date().toISOString();
  }
  
  await DataAccessLayer.updateManifest(env, fileName, meta);
  return new Response(JSON.stringify({ success: true, count: ips.length }));
}

// --- 上传相关 ---
async function handleUpload(request, env) {
    const formData = await request.formData();
    const file = formData.get('file');
    if (!file) return new Response(JSON.stringify({ error: 'No file' }), { status: 400 });
    let text = await file.text();
    try {
        const buffer = await file.arrayBuffer();
        const decoder = new TextDecoder('gbk');
        const gbkText = decoder.decode(buffer);
        if (/[\u4e00-\u9fa5]/.test(gbkText) && !/[\u4e00-\u9fa5]/.test(text)) text = gbkText;
    } catch (e) {}
    const cleanNodes = IPExtractor.processBatch(text);
    if (cleanNodes.length === 0) return new Response(JSON.stringify({ error: 'No Valid IPs' }), { status: 400 });
    const content = cleanNodes.map(n => (n.port ? `${n.ip}:${n.port}` : n.ip) + (n.remark ? `#${n.remark}`:'')).join('\n');
    let fileName = file.name;
    let fileList = await DataAccessLayer.readConfig(env, 'uploaded_files');
    if (fileList.includes(fileName)) {
        const parts = fileName.split('.');
        const ext = parts.length > 1 ? '.' + parts.pop() : '';
        fileName = `${parts.join('.')}_${Math.floor(1000 + Math.random() * 9000)}${ext}`;
    }
    await DataAccessLayer.writeFile(env, 'upload', fileName, content);
    fileList.push(fileName);
    await DataAccessLayer.writeConfig(env, 'uploaded_files', fileList);
    return new Response(JSON.stringify({ success: true, fileName, count: cleanNodes.length }));
}

async function deleteUploadedFile(req, env) {
    const b = await req.json();
    let fileList = await DataAccessLayer.readConfig(env, 'uploaded_files');
    const idx = fileList.indexOf(b.fileName);
    if (idx !== -1) {
        fileList.splice(idx, 1);
        await DataAccessLayer.writeConfig(env, 'uploaded_files', fileList);
        await DataAccessLayer.deleteFile(env, 'upload', b.fileName);
        return new Response(JSON.stringify({ success: true }));
    }
    return new Response(JSON.stringify({ error: 'File not found' }), { status: 404 });
}

// --- TG Bot ---
async function handleTelegramWebhook(req, env) {
    if (!env.TG_BOT_TOKEN) return new Response('No Token', { status: 200 });
    try {
        const update = await req.json();
        if (!update.message || !update.message.document) return new Response('OK', { status: 200 });
        const msg = update.message;
        const chatId = msg.chat.id;
        if (env.TG_WHITELIST_ID && String(chatId) !== String(env.TG_WHITELIST_ID)) { await sendTgMsg(env, chatId, "🚫 无权访问"); return new Response('Unauthorized', { status: 200 }); }
        const doc = msg.document;
        const fileName = doc.file_name;
        if (doc.file_size && doc.file_size > TG_FILE_LIMIT) { await sendTgMsg(env, chatId, "⚠️ 文件过大 (超过5MB)，请分割后上传"); return new Response('OK', { status: 200 }); }
        if (!fileName.match(/\.(csv|txt)$/i)) { await sendTgMsg(env, chatId, "⚠️ 仅支持 .csv 或 .txt 文件"); return new Response('OK', { status: 200 }); }
        await sendTgMsg(env, chatId, "⏳ 正在接收并处理文件: " + fileName);
        const fileRes = await fetch(`https://api.telegram.org/bot${env.TG_BOT_TOKEN}/getFile?file_id=${doc.file_id}`);
        const fileData = await fileRes.json();
        if (!fileData.ok) throw new Error('GetFile Failed');
        const contentUrl = `https://api.telegram.org/file/bot${env.TG_BOT_TOKEN}/${fileData.result.file_path}`;
        const contentRes = await fetch(contentUrl);
        const arrayBuffer = await contentRes.arrayBuffer();
        let text = new TextDecoder('utf-8').decode(arrayBuffer);
        try {
            const decoder = new TextDecoder('gbk');
            const gbkText = decoder.decode(arrayBuffer);
            if (/[\u4e00-\u9fa5]/.test(gbkText) && !/[\u4e00-\u9fa5]/.test(text)) text = gbkText;
        } catch (e) {}
        const cleanNodes = IPExtractor.processBatch(text);
        if (cleanNodes.length === 0) { await sendTgMsg(env, chatId, "❌ 文件中未找到有效的IP节点"); return new Response('OK', { status: 200 }); }
        const content = cleanNodes.map(n => {
            const base = n.port ? `${n.ip}:${n.port}` : n.ip;
            return n.remark ? `${base}#${n.remark}` : base; 
        }).join('\n');
        let saveName = fileName;
        let fileList = await DataAccessLayer.readConfig(env, 'uploaded_files') || [];
        if (fileList.includes(saveName)) {
            const parts = saveName.split('.');
            const ext = parts.length > 1 ? '.' + parts.pop() : '';
            saveName = `${parts.join('.')}_${Math.floor(1000 + Math.random() * 9000)}${ext}`;
        }
        await DataAccessLayer.writeFile(env, 'upload', saveName, content);
        fileList.push(saveName);
        await DataAccessLayer.writeConfig(env, 'uploaded_files', fileList);
        await sendTgMsg(env, chatId, `✅ 上传成功!\n文件名: ${saveName}\n包含节点: ${cleanNodes.length} 个`);
    } catch (e) { 
        console.error('TG upload error:', e);
        await sendTgMsg(env, chatId, `❌ 上传失败: ${e.message}`);
    }
    return new Response('OK', { status: 200 });
}

async function sendTgMsg(env, chatId, text) {
    if(env.TG_BOT_TOKEN) {
        await fetch(`https://api.telegram.org/bot${env.TG_BOT_TOKEN}/sendMessage`, { method: 'POST', headers: {'Content-Type': 'application/json'}, body: JSON.stringify({ chat_id: chatId, text: text }) });
    }
}

// ==========================================
// 8. 修复版提取逻辑 (支持可编辑文件+Base64增强)
// ==========================================
async function performExtraction(env, sources, forceRefresh = false) {
  let nodeMap = new Map();
  const [urls, apis, custom, uploadedFiles] = await Promise.all([
      DataAccessLayer.readConfig(env, 'urls', [], forceRefresh),
      DataAccessLayer.readConfig(env, 'apis', [], forceRefresh),
      DataAccessLayer.readConfig(env, 'custom_ips', [], forceRefresh),
      DataAccessLayer.readConfig(env, 'uploaded_files', [], forceRefresh)
  ]);
  let allCandidates = [];
  if (sources.includeCustom) IPExtractor.processBatch(custom).forEach(r => allCandidates.push({...r, source: 'custom'}));
  
  if (sources.files && Array.isArray(sources.files)) {
      const filePromises = sources.files.map(async (fileName) => {
          if (uploadedFiles.includes(fileName)) {
              const content = await DataAccessLayer.readFile(env, 'upload', fileName);
              if (content) return IPExtractor.processBatch(content).map(r => ({...r, source: 'file'}));
          } 
          else {
              try {
                  const editableData = await DataAccessLayer.getEditableFile(env, fileName);
                  if (editableData && editableData.ips && Array.isArray(editableData.ips)) {
                      return editableData.ips.map(r => ({...r, source: 'editable'}));
                  }
              } catch(e) {}
          }
          return [];
      });
      (await Promise.all(filePromises)).forEach(r => allCandidates.push(...r));
  }
  
  const BROWSER_UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
  const apiPromises = (sources.apis || []).map(async (i) => {
      const item = apis[i];
      if(item && item.url) {
          try {
             const c = new AbortController(); const id = setTimeout(() => c.abort(), 15000); 
             const res = await fetch(item.url, { signal: c.signal, headers: { 'Cache-Control': 'no-store', 'User-Agent': BROWSER_UA } }); 
             const txt = await res.text(); clearTimeout(id);
             return IPExtractor.processBatch(txt).map(r => ({...r, source: 'api'})); 
          } catch(e) { return []; }
      }
      return [];
  });
  (await Promise.all(apiPromises)).forEach(r => r.forEach(x => allCandidates.push(x)));
  const urlPromises = (sources.urls || []).map(async (i) => {
      const item = urls[i];
      if(item && item.url) {
         try {
            const c = new AbortController(); const id = setTimeout(() => c.abort(), 15000); 
            const res = await fetch(item.url, { headers: { 'User-Agent': BROWSER_UA, 'Cache-Control': 'no-store', 'Accept': 'text/plain,application/json,text/html,*/*' }, signal: c.signal }); 
            const txt = await res.text(); clearTimeout(id);
            return parseSubscription(txt).map(r => ({...r, source: 'sub'})); 
         } catch(e) { return []; }
      }
      return [];
  });
  (await Promise.all(urlPromises)).forEach(r => r.forEach(x => allCandidates.push(x)));

  for (const node of allCandidates) {
      const key = `${node.ip}:${node.port || 443}`;
      if (!nodeMap.has(key)) nodeMap.set(key, node.remark || ''); 
      else { const old = nodeMap.get(key); if (old === 'ERR' || old === 'UN' || old === 'TIMEOUT' || (!old && node.remark)) nodeMap.set(key, node.remark || ''); }
  }

  const tasks = [];
  for (let [key, remark] of nodeMap) { if (!remark) { const [ip, port] = key.split(':'); tasks.push({ key, ip, port }); } }

  const MAX_QUERY = 200; 
  const BATCH_SIZE = 15; 
  if (tasks.length > 0) {
      const processTasks = tasks.slice(0, MAX_QUERY); 
      for (let i = 0; i < processTasks.length; i += BATCH_SIZE) {
          const batch = processTasks.slice(i, i + BATCH_SIZE);
          await Promise.all(batch.map(async (task) => {
              const code = await queryExternalAPI(task.ip, task.port);
              if (code && code !== 'ERR' && code !== 'TIMEOUT') nodeMap.set(task.key, code);
          }));
      }
  }
  const result = [];
  for (let [key, remark] of nodeMap) result.push(remark ? `${key}#${remark}` : key);
  return result;
}

function parseSubscription(c) {
  const n = []; let d = c;
  try {
      let cleanStr = c.replace(/\s/g, '');
      
      if (cleanStr.length > 20 && !cleanStr.includes('://')) {
          cleanStr = cleanStr.replace(/-/g, '+').replace(/_/g, '/');
          
          while (cleanStr.length % 4) {
              cleanStr += '=';
          }
          
          d = decodeURIComponent(escape(atob(cleanStr)));
      }
  } catch (e) {
      d = c;
  }

  d.split(/[\r\n]+/).forEach(l => {
    const t = l.trim(); if (!t) return;
    
    if (t.startsWith('vmess://')) { 
        try { 
            let base64 = t.substring(8); 
            base64 = base64.replace(/\s/g, '').replace(/-/g, '+').replace(/_/g, '/');
            const jsonStr = decodeURIComponent(escape(atob(base64))); 
            const j = JSON.parse(jsonStr); 
            if (IPExtractor.isValidIP(j.add)) n.push({ ip: j.add, port: j.port, remark: j.ps }); 
            return; 
        } catch (e) {} 
    }
    
    if (t.match(/^(vless|trojan|ss):\/\//)) { 
        try { 
            const u = new URL(t); 
            if (IPExtractor.isValidIP(u.hostname)) n.push({ ip: u.hostname, port: u.port, remark: u.hash ? decodeURIComponent(u.hash.substring(1)) : '' }); 
            return; 
        } catch(e) {} 
    }
    
    const processed = IPExtractor.processBatch([t]);
    if (processed.length > 0) n.push(processed[0]);
  });
  return n;
}

async function queryExternalAPI(ip, port, retry = 0) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);
    try {
        const apiUrl = retry > 0 ? `http://ip-api.com/json/${ip}?fields=countryCode` : `https://ipinfo.io/${ip}/json`;
        const res = await fetch(apiUrl, { headers: { 'User-Agent': 'Mozilla/5.0 (compatible; Node-IP-Checker/1.0)' }, cf: { cacheTtl: 3600, cacheEverything: true }, signal: controller.signal });
        clearTimeout(timeoutId);
        const data = await res.json();
        let code = 'UN';
        if (data.country) code = data.country; else if (data.countryCode) code = data.countryCode; 
        return code;
    } catch (e) { clearTimeout(timeoutId); if (e.name === 'AbortError') return 'TIMEOUT'; if (retry < 1) return await queryExternalAPI(ip, port, retry + 1); return 'ERR'; }
}

async function extractIPs(req, env) { const b = await req.json(); const r = await performExtraction(env, b.sources); return new Response(JSON.stringify({ ips: r, count: r.length })); }

async function handleToolQuery(request) {
    const { ipList, deduplicate } = await request.json();
    if (!ipList || !Array.isArray(ipList)) throw new Error('无效的IP列表');
    let items = IPExtractor.processBatch(ipList);
    if (deduplicate) items = IPExtractor.deduplicateIPs(items);
    if (items.length > 200) throw new Error('一次最多查询200个IP');
    const processedNodes = [];
    const pendingNodes = items; 
    const BATCH_SIZE = 15;
    for (let i = 0; i < pendingNodes.length; i += BATCH_SIZE) {
        const batch = pendingNodes.slice(i, i + BATCH_SIZE);
        const results = await Promise.all(batch.map(async (item) => { const code = await queryExternalAPI(item.ip, item.port); return { ...item, remark: code }; }));
        processedNodes.push(...results);
    }
    const finalResults = processedNodes.map(item => { const fmt = item.port ? `${item.ip}:${item.port}#${item.remark}` : `${item.ip}#${item.remark}`; return { formatted: fmt, success: item.remark !== 'ERR' && item.remark !== 'TIMEOUT' }; });
    return new Response(JSON.stringify({ results: finalResults }), { headers: { 'Content-Type': 'application/json' } });
}

async function logout(req, env) { const c = req.headers.get('Cookie'); if(c) { const id = c.split('session=')[1]?.split(';')[0]; if(id) await env[KV_BINDING_NAME].delete(`session_${id}`); } return new Response(null, { status: 302, headers: { 'Set-Cookie': 'session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0', 'Location': '/admin' } }); }

async function checkSession(req, env) { const c = req.headers.get('Cookie'); if(!c) return false; const id = c.match(/session=([^;]+)/)?.[1]; if(!id) return false; return await env[KV_BINDING_NAME].get(`session_${id}`) === 'valid'; }

// ==========================================
// 10. 管理页面 (现代化界面版)
// ==========================================
async function handleAdmin(req, env) {
  const url = new URL(req.url); 
  const sess = await checkSession(req, env);
  if (!sess && url.searchParams.get('action') !== 'login') return new Response(getLoginPage(), { headers: { 'Content-Type': 'text/html; charset=utf-8' }});
  if (url.searchParams.get('action') === 'login') {
    const fd = await req.formData();
    if (fd.get('password') === env.ADMIN_PASSWORD) {
      const id = crypto.randomUUID(); 
      await env[KV_BINDING_NAME].put(`session_${id}`, 'valid', { expirationTtl: 86400 });
      return new Response('', { status: 302, headers: { 'Set-Cookie': `session=${id}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400`, 'Location': '/admin' } });
    }
    return new Response(getLoginPage('密码错误'), { headers: { 'Content-Type': 'text/html; charset=utf-8' }});
  }
  const [urls, apis, customIPs, uploadedFiles, sitesList, manifest] = await Promise.all([
      DataAccessLayer.readConfig(env, 'urls'),
      DataAccessLayer.readConfig(env, 'apis'),
      DataAccessLayer.readConfig(env, 'custom_ips'),
      DataAccessLayer.readConfig(env, 'uploaded_files'),
      DataAccessLayer.readConfig(env, 'sites_list'),
      DataAccessLayer.getManifest(env)
  ]);
  const ipFiles = [];
  const editableFiles = [];
  for (const [name, meta] of Object.entries(manifest)) {
      if(!meta) continue;
      const stats = await DataAccessLayer.getStats(env, name);
      if (meta.editable) {
        try {
            const editableData = await DataAccessLayer.getEditableFile(env, name);
            editableFiles.push({ ...meta, stats, ips: editableData ? editableData.ips : [] });
        } catch(e) {
            editableFiles.push({ ...meta, stats, ips: [] });
        }
      } else { ipFiles.push({ ...meta, stats }); }
  }
  const jsonStr = JSON.stringify({ urls, apis, customIPs, uploadedFiles, ipFiles, editableFiles, sitesList });
  const base64Data = btoa(unescape(encodeURIComponent(jsonStr)));
  
  return new Response(getAdminPage(base64Data, url.origin), { 
      headers: { 
          'Content-Type': 'text/html; charset=utf-8',
          'Cache-Control': 'no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0',
          'Pragma': 'no-cache',
          'Expires': '0',
          'Surrogate-Control': 'no-store',
          'Last-Modified': new Date().toUTCString()
      } 
  });
}

function getLoginPage(error = '') {
    return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>系统登录</title><style>:root{--primary:#6366f1;--bg:#f3f4f6;--surface:#ffffff;--text:#1f2937}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.login-box{background:var(--surface);padding:2.5rem;border-radius:1rem;box-shadow:0 20px 25px -5px rgba(0,0,0,0.1),0 10px 10px -5px rgba(0,0,0,0.04);width:100%;max-width:360px;text-align:center;backdrop-filter:blur(10px);background:rgba(255,255,255,0.95)}h2{margin-bottom:1.5rem;color:var(--text);font-weight:700;font-size:1.5rem}input{width:100%;padding:.75rem 1rem;margin-bottom:1rem;border:1px solid #e5e7eb;border-radius:.5rem;font-size:1rem;box-sizing:border-box;outline:none;transition:all .2s;background:rgba(255,255,255,0.9)}input:focus{border-color:var(--primary);box-shadow:0 0 0 3px rgba(99,102,241,0.2)}button{width:100%;padding:.75rem;background:var(--primary);color:white;border:none;border-radius:.5rem;font-size:1rem;font-weight:600;cursor:pointer;transition:all .2s;box-shadow:0 4px 6px -1px rgba(0,0,0,0.1)}button:hover{background:#4f46e5;transform:translateY(-2px);box-shadow:0 10px 15px -3px rgba(0,0,0,0.1)}.error{background:#fee2e2;color:#991b1b;padding:.75rem;border-radius:.5rem;margin-top:1rem;font-size:.875rem}</style></head><body><div class="login-box"><h2>🔒 节点管理系统 v10.8</h2><form method="POST" action="?action=login"><input type="password" name="password" placeholder="请输入访问密码" required autofocus><button type="submit">立即登录</button>${error?`<div class="error">${error}</div>`:''}</form></div></body></html>`;
}

function getAdminPage(base64Data, origin) {
    const originVar = origin;
    const base64Var = base64Data;
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>节点 IP 管理控制台 v10.8 (现代化界面)</title>
<style>
    :root { 
        --primary: #6366f1; 
        --primary-hover: #4f46e5; 
        --primary-light: #e0e7ff;
        --danger: #ef4444; 
        --danger-hover: #dc2626; 
        --danger-light: #fee2e2;
        --success: #10b981; 
        --success-light: #d1fae5;
        --warning: #f59e0b; 
        --warning-light: #fef3c7;
        --bg: #f8fafc; 
        --surface: #ffffff; 
        --text-main: #1e293b; 
        --text-sub: #64748b; 
        --border: #e2e8f0; 
        --radius: 0.75rem; 
        --shadow: 0 1px 3px 0 rgba(0, 0, 0, 0.1), 0 1px 2px 0 rgba(0, 0, 0, 0.06);
        --shadow-lg: 0 10px 15px -3px rgba(0, 0, 0, 0.1), 0 4px 6px -2px rgba(0, 0, 0, 0.05);
        --gradient: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { 
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif; 
        background: var(--bg); 
        color: var(--text-main); 
        line-height: 1.6; 
        min-height: 100vh;
        background-image: 
            radial-gradient(circle at 20% 80%, rgba(99, 102, 241, 0.1) 0%, transparent 50%),
            radial-gradient(circle at 80% 20%, rgba(139, 92, 246, 0.1) 0%, transparent 50%),
            radial-gradient(circle at 40% 40%, rgba(236, 72, 153, 0.05) 0%, transparent 50%);
    }
    .container { max-width: 1200px; margin: 0 auto; padding: 0 1rem; }
    header { 
        display: flex; 
        justify-content: space-between; 
        align-items: center; 
        padding: 2rem 0; 
        margin-bottom: 2rem; 
        border-bottom: 1px solid var(--border);
    }
    h1 { 
        font-size: 1.875rem; 
        font-weight: 800; 
        background: var(--gradient); 
        -webkit-background-clip: text; 
        -webkit-text-fill-color: transparent;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    .logout { 
        font-size: 0.875rem; 
        color: var(--text-sub); 
        text-decoration: none; 
        cursor: pointer; 
        display: flex; 
        align-items: center; 
        gap: 0.5rem;
        padding: 0.5rem 1rem;
        border-radius: 0.5rem;
        transition: all 0.2s;
    }
    .logout:hover { 
        color: var(--danger); 
        background: var(--danger-light);
    }
    .message { 
        position: fixed; 
        top: 20px; 
        right: 20px; 
        padding: 1rem 1.5rem; 
        border-radius: var(--radius); 
        background: var(--surface); 
        box-shadow: var(--shadow-lg); 
        display: none; 
        z-index: 1000; 
        border-left: 4px solid var(--primary); 
        font-weight: 500;
        animation: slideIn 0.3s ease;
    }
    @keyframes slideIn {
        from { transform: translateX(100%); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    .message.success { border-color: var(--success); color: #065f46; background: var(--success-light); }
    .message.error { border-color: var(--danger); color: #991b1b; background: var(--danger-light); }
    .tabs { 
        display: flex; 
        gap: 0.5rem; 
        margin-bottom: 2rem; 
        overflow-x: auto; 
        padding: 0.25rem;
        background: var(--surface);
        border-radius: var(--radius);
        box-shadow: var(--shadow);
        flex-wrap: wrap;
    }
    .tab { 
        padding: 0.75rem 1.5rem; 
        background: transparent; 
        border: none; 
        border-radius: 0.5rem; 
        cursor: pointer; 
        color: var(--text-sub); 
        font-weight: 600; 
        font-size: 0.95rem; 
        white-space: nowrap; 
        transition: all 0.2s; 
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    .tab:hover { 
        background: var(--primary-light); 
        color: var(--primary); 
        transform: translateY(-1px);
    }
    .tab.active { 
        background: var(--primary); 
        color: white; 
        box-shadow: var(--shadow);
    }
    .tab-content { 
        display: none; 
        background: var(--surface); 
        border-radius: var(--radius); 
        padding: 2rem; 
        box-shadow: var(--shadow-lg); 
        animation: fadeIn 0.3s ease; 
    }
    .tab-content.active { display: block; }
    @keyframes fadeIn { 
        from { opacity: 0; transform: translateY(10px); } 
        to { opacity: 1; transform: translateY(0); } 
    }
    h2 { 
        font-size: 1.5rem; 
        margin-bottom: 1.5rem; 
        color: var(--text-main); 
        font-weight: 700; 
        border-left: 4px solid var(--primary); 
        padding-left: 1rem;
        display: flex;
        align-items: center;
        gap: 0.5rem;
    }
    .form-group { margin-bottom: 1.5rem; }
    textarea, input[type="text"] { 
        width: 100%; 
        padding: 0.875rem; 
        border: 1px solid var(--border); 
        border-radius: 0.5rem; 
        background: #f8fafc; 
        outline: none; 
        font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
        font-size: 0.875rem;
        transition: all 0.2s;
    }
    textarea:focus, input[type="text"]:focus { 
        border-color: var(--primary); 
        background: white; 
        box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1); 
    }
    button { 
        padding: 0.75rem 1.5rem; 
        border: none; 
        border-radius: 0.5rem; 
        cursor: pointer; 
        font-weight: 600; 
        font-size: 0.9rem; 
        transition: all 0.2s; 
        display: inline-flex; 
        align-items: center; 
        justify-content: center; 
        gap: 0.5rem;
        box-shadow: var(--shadow);
    }
    button:hover {
        transform: translateY(-2px);
        box-shadow: var(--shadow-lg);
    }
    button:active {
        transform: translateY(0);
    }
    button:disabled { 
        opacity: 0.6; 
        cursor: not-allowed; 
        filter: grayscale(100%); 
        transform: none !important;
    }
    .btn-primary, .btn-success { 
        background: var(--primary); 
        color: white; 
    }
    .btn-primary:hover, .btn-success:hover { 
        background: var(--primary-hover); 
    }
    .btn-danger { 
        background: var(--danger); 
        color: white; 
    }
    .btn-danger:hover { 
        background: var(--danger-hover); 
    }
    .btn-warning { 
        background: var(--warning); 
        color: white; 
    }
    .btn-warning:hover { 
        background: #d97706; 
    }
    .btn-secondary { 
        background: var(--text-sub); 
        color: white; 
    }
    .btn-secondary:hover { 
        background: #475569; 
    }
    .item-list { 
        margin-top: 1.5rem; 
        display: flex; 
        flex-direction: column; 
        gap: 1rem; 
    }
    .item { 
        display: flex; 
        justify-content: space-between; 
        align-items: center; 
        padding: 1.25rem; 
        background: #f8fafc; 
        border: 1px solid var(--border); 
        border-radius: 0.75rem; 
        transition: all 0.2s; 
        box-shadow: var(--shadow);
    }
    .item:hover {
        transform: translateY(-2px);
        box-shadow: var(--shadow-lg);
        border-color: var(--primary);
    }
    .item-content { 
        flex: 1; 
        word-break: break-all; 
        margin-right: 1rem; 
        font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
        font-size: 0.875rem; 
        color: var(--text-main); 
    }
    .item-meta { 
        font-size: 0.75rem; 
        color: var(--text-sub); 
        margin-top: 0.5rem; 
        display: flex; 
        gap: 1rem; 
        align-items: center;
        flex-wrap: wrap;
    }
    .badge { 
        padding: 0.25rem 0.75rem; 
        border-radius: 9999px; 
        background: var(--primary-light); 
        font-size: 0.75rem; 
        font-weight: 600; 
        color: var(--primary);
        display: inline-flex;
        align-items: center;
        gap: 0.25rem;
    }
    .badge.auto { background: var(--success-light); color: #065f46; }
    .badge.editable { background: #e9d5ff; color: #6b21a8; }
    .src-badge { 
        display: inline-block; 
        padding: 0.25rem 0.5rem; 
        margin: 0.25rem; 
        border-radius: 0.375rem; 
        font-size: 0.75rem; 
        background: var(--primary-light); 
        color: var(--primary); 
        border: 1px solid var(--primary);
        font-weight: 500;
    }
    .src-badge.custom { background: var(--danger-light); color: var(--danger); border-color: var(--danger); }
    .src-badge.file { background: #dbeafe; color: #1e40af; border-color: #3b82f6; }
    .src-badge.sub { background: var(--success-light); color: #065f46; border-color: var(--success); }
    .src-badge.api { background: var(--warning-light); color: #92400e; border-color: var(--warning); }
    .checkbox-group { 
        display: grid; 
        grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); 
        gap: 1rem; 
        margin-top: 1rem; 
        padding: 1.5rem; 
        background: #f8fafc; 
        border-radius: 0.75rem; 
        border: 1px solid var(--border);
        max-height: 300px;
        overflow-y: auto;
    }
    .checkbox-group label { 
        margin: 0; 
        display: flex; 
        align-items: center; 
        cursor: pointer; 
        padding: 0.75rem; 
        border-radius: 0.5rem; 
        font-size: 0.875rem;
        transition: all 0.2s;
    }
    .checkbox-group label:hover { 
        background: var(--primary-light); 
        transform: translateX(4px);
    }
    .checkbox-group input { 
        margin-right: 0.75rem; 
        accent-color: var(--primary); 
        width: 1.25rem; 
        height: 1.25rem; 
    }
    .upload-area { 
        border: 2px dashed #cbd5e1; 
        border-radius: 0.75rem; 
        padding: 3rem; 
        text-align: center; 
        background: #f8fafc; 
        cursor: pointer; 
        transition: all 0.2s;
    }
    .upload-area:hover { 
        border-color: var(--primary); 
        background: var(--primary-light); 
        transform: scale(1.02);
    }
    pre { 
        background: #1e293b; 
        color: #e2e8f0; 
        padding: 1.5rem; 
        border-radius: 0.75rem; 
        font-size: 0.875rem; 
        max-height: 400px; 
        overflow-y: auto; 
        margin-top: 1rem; 
        border: 1px solid #334155; 
        white-space: pre-wrap; 
        word-wrap: break-word;
        box-shadow: var(--shadow);
    }
    .sub-tabs { 
        display: flex; 
        gap: 0.5rem; 
        margin-bottom: 1.5rem; 
        border-bottom: 2px solid var(--border); 
        padding-bottom: 0;
    }
    .sub-tab { 
        padding: 0.75rem 1.5rem; 
        background: transparent; 
        border: none; 
        border-bottom: 3px solid transparent; 
        cursor: pointer; 
        color: var(--text-sub); 
        font-weight: 600; 
        font-size: 0.9rem; 
        transition: all 0.2s; 
        border-radius: 0.5rem 0.5rem 0 0;
    }
    .sub-tab:hover { 
        color: var(--primary); 
        background: var(--primary-light);
    }
    .sub-tab.active { 
        color: var(--primary); 
        border-bottom-color: var(--primary); 
        background: var(--primary-light);
    }
    .sub-tab-content { display: none; }
    .sub-tab-content.active { display: block; }
    .tools-layout { 
        display: grid; 
        grid-template-columns: 1fr 320px; 
        gap: 2rem; 
    }
    .tools-sidebar { 
        background: #f8fafc; 
        padding: 1.5rem; 
        border-radius: var(--radius); 
        border: 1px solid var(--border);
        box-shadow: var(--shadow);
        height: fit-content;
    }
    .link-card { 
        display: block; 
        padding: 0.75rem 1rem; 
        margin-bottom: 0.75rem; 
        background: white; 
        border: 1px solid var(--border); 
        border-radius: 0.5rem; 
        text-decoration: none; 
        color: var(--text-main); 
        font-size: 0.9rem; 
        display: flex; 
        align-items: center; 
        transition: all 0.2s; 
        box-shadow: var(--shadow);
    }
    .link-card:hover { 
        border-color: var(--primary); 
        color: var(--primary); 
        transform: translateX(4px);
        box-shadow: var(--shadow-lg);
    }
    .modal { 
        display: none; 
        position: fixed; 
        top: 0; 
        left: 0; 
        width: 100%; 
        height: 100%; 
        background-color: rgba(0,0,0,0.5); 
        z-index: 1000; 
        backdrop-filter: blur(4px);
    }
    .modal-content { 
        background-color: var(--surface); 
        margin: 5% auto; 
        padding: 2rem; 
        border-radius: var(--radius); 
        width: 90%; 
        max-width: 800px; 
        max-height: 80vh; 
        overflow-y: auto; 
        box-shadow: var(--shadow-lg);
        animation: modalFadeIn 0.3s ease;
    }
    @keyframes modalFadeIn {
        from { opacity: 0; transform: scale(0.95); }
        to { opacity: 1; transform: scale(1); }
    }
    .modal-header { 
        display: flex; 
        justify-content: space-between; 
        align-items: center; 
        margin-bottom: 1.5rem; 
        padding-bottom: 1rem;
        border-bottom: 1px solid var(--border);
    }
    .modal-title { 
        font-size: 1.25rem; 
        font-weight: 700; 
        color: var(--text-main); 
    }
    .close { 
        color: var(--text-sub); 
        font-size: 1.5rem; 
        font-weight: bold; 
        cursor: pointer; 
        width: 2rem;
        height: 2rem;
        display: flex;
        align-items: center;
        justify-content: center;
        border-radius: 0.5rem;
        transition: all 0.2s;
    }
    .close:hover { 
        color: var(--danger); 
        background: var(--danger-light);
    }
    .modal-body { 
        margin-bottom: 1.5rem; 
    }
    .modal-footer { 
        display: flex; 
        justify-content: flex-end; 
        gap: 1rem; 
        padding-top: 1.5rem;
        border-top: 1px solid var(--border);
    }
    .edit-section { 
        margin-bottom: 1.5rem; 
    }
    .edit-section h3 { 
        font-size: 1rem; 
        margin-bottom: 1rem; 
        color: var(--text-main); 
        border-left: 3px solid var(--primary); 
        padding-left: 0.75rem;
    }
    .stats-info { 
        display: flex; 
        gap: 1.5rem; 
        align-items: center; 
        font-size: 0.875rem; 
        color: var(--text-sub);
        flex-wrap: wrap;
    }
    .stats-info span { 
        display: flex; 
        align-items: center; 
        gap: 0.5rem;
        padding: 0.25rem 0.5rem;
        background: #f1f5f9;
        border-radius: 0.375rem;
    }
    .editable-ip-list { 
        max-height: 300px; 
        overflow-y: auto; 
        border: 1px solid var(--border); 
        border-radius: 0.5rem; 
        padding: 0.5rem; 
        margin-bottom: 1rem;
        background: #f8fafc;
    }
    .editable-ip-item { 
        display: flex; 
        justify-content: space-between; 
        align-items: center; 
        padding: 0.75rem; 
        margin-bottom: 0.5rem; 
        background: white; 
        border-radius: 0.5rem;
        border: 1px solid var(--border);
        transition: all 0.2s;
    }
    .editable-ip-item:hover {
        background: var(--primary-light);
        transform: translateX(4px);
    }
    .editable-ip-text { 
        font-family: 'SF Mono', Monaco, 'Cascadia Code', 'Roboto Mono', Consolas, 'Courier New', monospace;
        font-size: 0.875rem; 
        flex: 1; 
        margin-right: 0.75rem; 
    }
    .editable-ip-actions { 
        display: flex; 
        gap: 0.5rem; 
    }
    .btn-small { 
        padding: 0.375rem 0.75rem; 
        font-size: 0.75rem; 
    }
    .ip-add-form { 
        display: flex; 
        flex-direction: column; 
        gap: 0.75rem; 
        margin-bottom: 1rem; 
    }
    .ip-add-actions { 
        display: flex; 
        gap: 0.75rem; 
        margin-top: 0.75rem; 
    }
    .control-buttons {
        display: flex;
        gap: 0.75rem;
        margin-bottom: 1rem;
        align-items: center;
        flex-wrap: wrap;
    }
    .checkbox-control {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        margin-left: auto;
    }
    @media (max-width: 800px) { 
        .tools-layout { 
            grid-template-columns: 1fr; 
        } 
    }
    @media (max-width: 640px) { 
        .container { 
            padding: 0 0.5rem; 
        } 
        .tab { 
            padding: 0.5rem 1rem; 
            font-size: 0.875rem; 
        } 
        .tab-content { 
            padding: 1.5rem 1rem; 
        } 
        .item { 
            flex-direction: column; 
            align-items: flex-start; 
            gap: 1rem; 
        } 
        .item button { 
            width: 100%; 
        }
        .checkbox-group {
            grid-template-columns: 1fr;
        }
        .control-buttons {
            flex-direction: column;
            align-items: stretch;
        }
        .checkbox-control {
            margin-left: 0;
            margin-top: 0.75rem;
        }
    }
</style>
</head>
<body>
<div class="container">
    <header>
        <h1>⚡️ 节点管理控制台 v10.8</h1>
        <a href="/api/logout" class="logout">
            <svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path>
            </svg> 
            退出登录
        </a>
    </header>
    <div id="message" class="message"></div>

    <nav class="tabs">
        <button class="tab active" data-tab="sources">🌐 IP来源</button>
        <button class="tab" data-tab="extract">🧪 提取测试</button>
        <button class="tab" data-tab="files">📂 文件生成</button>
        <button class="tab" data-tab="editable">✏️ 可编辑文件</button>
        <button class="tab" data-tab="tools">🛠️ 查询工具</button>
    </nav>

    <div id="sources-tab" class="tab-content active">
        <nav class="sub-tabs">
            <button class="sub-tab active" data-sub-tab="upload">📂 上传管理</button>
            <button class="sub-tab" data-sub-tab="urls">📡 订阅源</button>
            <button class="sub-tab" data-sub-tab="apis">🔗 API源</button>
            <button class="sub-tab" data-sub-tab="custom">📝 自定义IP</button>
            <button class="sub-tab" data-sub-tab="sites-ip">🌐 找资源</button>
        </nav>
        
        <div id="upload-sub-tab" class="sub-tab-content active">
            <h2>📂 上传本地 IP 文件 (CSV/TXT)</h2>
            <div class="upload-area" id="upload-box">
                <svg width="48" height="48" fill="none" stroke="#94a3b8" stroke-width="2" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path>
                </svg>
                <p style="margin-top: 1rem; font-size: 1.125rem; font-weight: 600;">点击或拖拽文件到此处</p>
                <p style="margin-top: 0.5rem; font-size: 0.875rem; color: var(--text-sub);">也支持直接发文件给 TG 机器人</p>
                <input type="file" id="file-input" style="display:none">
            </div>
            <div style="background: var(--primary-light); padding: 1rem; border-radius: 0.75rem; margin: 1.5rem 0; font-size: 0.875rem; color: var(--primary); border-left: 4px solid var(--primary);">
                <strong>💡 提示：</strong> 上传后系统会自动去重和标准化。如果配置了 TG 机器人，可以直接转发 CSV 文件给机器人自动上传。
            </div>
            <div class="item-list" id="uploaded-list"></div>
        </div>

        <div id="urls-sub-tab" class="sub-tab-content">
            <h2>📡 订阅链接管理</h2>
            <div class="form-group" style="display:flex; gap:0.75rem">
                <input type="text" id="new-url-name" placeholder="名称 (选填)" style="flex:1">
                <input type="text" id="new-url-link" placeholder="订阅链接 (必填)" style="flex:2">
            </div>
            <button id="btn-add-url" class="btn-success">➕ 添加订阅链接</button>
            <div class="item-list" id="url-list"></div>
        </div>

        <div id="apis-sub-tab" class="sub-tab-content">
            <h2>🔗 API 接口管理</h2>
            <div class="form-group" style="display:flex; gap:0.75rem">
                <input type="text" id="new-api-name" placeholder="名称 (选填)" style="flex:1">
                <input type="text" id="new-api-link" placeholder="API 链接 (必填)" style="flex:2">
            </div>
            <button id="btn-add-api" class="btn-success">➕ 添加 API</button>
            <div class="item-list" id="api-list"></div>
        </div>

        <div id="custom-sub-tab" class="sub-tab-content">
            <h2>📝 自定义 IP 池</h2>
            <div style="margin-bottom:1rem; color:var(--text-sub); font-size: 0.875rem;">
                当前数量: <strong id="ip-count" style="color:var(--primary); font-size: 1.125rem;">0</strong> 个 IP
            </div>
            <div class="form-group">
                <textarea id="custom-ips" rows="12" placeholder="每行一个IP，格式: 1.1.1.1:443#备注&#10;或: 1.1.1.1&#10;或: 1.1.1.1:8080"></textarea>
            </div>
            <div style="display:flex; gap:0.75rem">
                <button id="btn-save-custom" class="btn-success">💾 保存更改</button>
                <button id="btn-clear-custom" class="btn-danger">🗑️ 清空全部</button>
            </div>
        </div>

        <div id="sites-ip-sub-tab" class="sub-tab-content">
            <h2>🌐 IP 资源网站收藏</h2>
            <div style="display:flex; gap:0.75rem; margin-bottom:1.5rem">
                <input type="text" id="site-name-ip" placeholder="网站名称" style="flex:1">
                <input type="text" id="site-url-ip" placeholder="网址 (http://...)" style="flex:2">
                <button id="btn-add-site-ip" class="btn-success">➕ 添加</button>
            </div>
            <div class="item-list" id="site-list-ip"></div>
        </div>
    </div>

    <div id="extract-tab" class="tab-content">
        <h2>🧪 IP 提取预览</h2>
        <div class="control-buttons">
            <button id="ext-select-all" class="btn-primary">✅ 全选</button>
            <button id="ext-deselect-all" class="btn-danger">❌ 反选</button>
            <div class="checkbox-control">
                <label style="display:flex;align-items:center;gap:0.5rem;cursor:pointer;font-weight: 500;">
                    <input type="checkbox" id="ext-custom" checked style="width:1.25rem;height:1.25rem;"> 
                    包含自定义 IP 池
                </label>
            </div>
        </div>
        <div id="ext-sources" class="checkbox-group"></div>
        <div style="display:flex; gap:0.75rem; margin-top:1.5rem;">
            <button id="btn-extract" class="btn-primary" style="flex:1;">🚀 立即提取</button>
            <button id="btn-copy-extract" class="btn-success" style="display:none;">📋 复制结果</button>
        </div>
        <pre id="extract-result">准备就绪...</pre>
    </div>

    <div id="files-tab" class="tab-content">
        <h2>📂 生成订阅文件</h2>
        <div class="form-group">
            <label style="display:block; margin-bottom: 0.5rem; font-weight: 600;">文件名</label>
            <input type="text" id="file-name" placeholder="例如: best_cf" style="font-size: 1rem;">
        </div>
        <div class="control-buttons">
            <button id="file-select-all" class="btn-primary">✅ 全选</button>
            <button id="file-deselect-all" class="btn-danger">❌ 反选</button>
            <div class="checkbox-control">
                <label style="display:flex;align-items:center;gap:0.5rem;cursor:pointer;font-weight: 500;">
                    <input type="checkbox" id="file-custom" checked style="width:1.25rem;height:1.25rem;"> 
                    包含自定义IP
                </label>
                <label style="display:flex;align-items:center;gap:0.5rem;cursor:pointer;font-weight: 500;">
                    <input type="checkbox" id="file-auto" checked style="width:1.25rem;height:1.25rem;"> 
                    自动更新
                </label>
            </div>
        </div>
        <div id="file-sources" class="checkbox-group"></div>
        <button id="btn-save-file" class="btn-success" style="margin-top:1.5rem; width:100%">💾 生成文件</button>
        <h3 style="margin-top:2.5rem;font-size:1.25rem;padding-left:1rem;border-left:4px solid var(--warning); display: flex; align-items: center; gap: 0.5rem;">📋 已生成文件</h3>
        <div class="item-list" id="file-list"></div>
    </div>

    <div id="editable-tab" class="tab-content">
        <h2>✏️ 可编辑文件管理</h2>
        <div style="background: #f0f9ff; padding: 1rem; border-radius: 0.75rem; margin-bottom: 1.5rem; font-size: 0.875rem; color: #0369a1; border-left: 4px solid #38bdf8;">
            <strong>💡 提示：</strong> 可编辑文件现已作为"内部模块"使用。您可以在"生成订阅文件"中勾选它们作为数据源，组合成最终的订阅链接。
        </div>
        <div class="item-list" id="editable-list"></div>
        <div style="margin-top:2rem; text-align:center;">
            <button id="btn-create-editable" class="btn-primary">➕ 创建新的可编辑文件</button>
        </div>
    </div>

    <div id="tools-tab" class="tab-content">
        <h2>🛠️ IP 智能查询工具</h2>
        <div class="tools-layout">
            <div>
                <div style="background: var(--warning-light); color: #92400e; padding: 1rem; border-radius: 0.75rem; margin-bottom: 1rem; font-size: 0.875rem; border-left: 4px solid var(--warning);">
                    <strong>⚠️ 注意：</strong> 此处查询会忽略已有备注，强制刷新 API 获取最新国家信息。
                </div>
                <div class="form-group">
                    <label style="display:flex;align-items:center;gap:0.75rem;cursor:pointer;font-weight: 500;">
                        <input type="checkbox" id="tool-deduplicate" checked style="width:1.25rem;height:1.25rem;"> 
                        启用去重功能
                    </label>
                </div>
                <div class="form-group">
                    <textarea id="tool-input" rows="12" placeholder="粘贴 IP 列表...&#10;每行一个IP，支持端口和备注"></textarea>
                </div>
                <div style="display:flex; gap:0.75rem; flex-wrap: wrap;">
                    <button id="btn-tool-run" class="btn-primary">🚀 开始查询</button>
                    <button id="btn-tool-copy" class="btn-success" style="display:none;">📋 复制结果</button>
                    <button id="btn-tool-save" class="btn-warning" style="display:none;">💾 保存为可编辑文件</button>
                </div>
                <pre id="tool-output" style="display:none;"></pre>
            </div>
            <div class="tools-sidebar">
            <h3 style="font-size:1.125rem; margin-bottom:1.25rem; border-left:3px solid var(--primary); padding-left:0.75rem; display: flex; align-items: center; gap: 0.5rem;">🔗 友情链接 / 工具</h3>
            <div id="friend-links-list"></div>
            <div style="margin-top:1.5rem; border-top:1px solid var(--border); padding-top:1rem;">
                 <input type="text" id="site-name-friend" placeholder="名称" style="width:100%;margin-bottom:0.75rem;padding:0.75rem;">
                 <input type="text" id="site-url-friend" placeholder="链接" style="width:100%;margin-bottom:0.75rem;padding:0.75rem;">
                 <button id="btn-add-site-friend" class="btn-secondary" style="width:100%;font-size:0.875rem;">➕ 添加链接</button>
            </div>
        </div>
    </div>
</div>
</div>

<div id="edit-file-modal" class="modal">
<div class="modal-content">
    <div class="modal-header">
        <h3 class="modal-title">✏️ 编辑可编辑文件</h3>
        <span class="close">&times;</span>
    </div>
    <div class="modal-body">
        <div class="edit-section">
            <h3>📁 文件名: <span id="edit-file-name" style="color: var(--primary);"></span></h3>
        </div>
        
        <div class="edit-section">
            <h3>📝 批量编辑 / 添加 IP</h3>
            <div class="ip-add-form">
                <textarea id="batch-ip-input" rows="6" placeholder="在此处粘贴 IP 列表 (每行一个，格式: IP:端口#备注)"></textarea>
                <div class="ip-add-actions">
                    <button id="btn-batch-add" class="btn-success btn-small" style="flex:1">➕ 批量追加</button>
                    <button id="btn-batch-replace" class="btn-warning btn-small" style="flex:1">🔄 覆盖导入</button>
                    <button id="btn-clear-all" class="btn-danger btn-small" style="flex:1">🗑️ 一键清空</button>
                </div>
            </div>
            <div style="display:flex;justify-content:space-between;margin-bottom:0.75rem; align-items: center;">
                <h4 style="margin:0;font-size:1rem; font-weight: 600;">📋 当前列表 (<span id="current-ip-count">0</span>)</h4>
                <button id="btn-copy-list" class="btn-secondary btn-small">📋 复制列表</button>
            </div>
            <div class="editable-ip-list" id="editable-ip-list"></div>
        </div>
    </div>
    <div class="modal-footer">
        <button id="btn-cancel-edit" class="btn-secondary">取消</button>
        <button id="btn-save-edit" class="btn-primary">保存更改</button>
    </div>
</div>
</div>

<div id="edit-sources-modal" class="modal">
<div class="modal-content">
    <div class="modal-header">
        <h3 class="modal-title">⚙️ 编辑文件数据源</h3>
        <span class="close">&times;</span>
    </div>
    <div class="modal-body">
        <div class="edit-section">
            <h3>📁 文件名: <span id="edit-file-name" style="color: var(--primary);"></span></h3>
        </div>
        
        <div class="edit-section">
            <h3>🔄 自动更新</h3>
            <label style="display:flex;align-items:center;gap:0.75rem;cursor:pointer;font-weight: 500;">
                <input type="checkbox" id="edit-auto-update" style="width:1.25rem;height:1.25rem;"> 启用自动更新
            </label>
        </div>
        
        <div class="edit-section">
            <h3>📊 数据源配置</h3>
            <div style="display:flex; gap:0.75rem; margin-bottom:1rem;">
                <button id="edit-select-all" class="btn-primary">✅ 全选</button>
                <button id="edit-deselect-all" class="btn-danger">❌ 反选</button>
            </div>
            <div id="edit-sources" class="checkbox-group"></div>
        </div>
        
        <div class="edit-section">
            <h3>📝 自定义IP</h3>
            <label style="display:flex;align-items:center;gap:0.75rem;cursor:pointer;font-weight: 500;">
                <input type="checkbox" id="edit-custom" style="width:1.25rem;height:1.25rem;"> 包含自定义IP池
            </label>
        </div>
    </div>
    <div class="modal-footer">
        <button id="btn-cancel-edit" class="btn-secondary">取消</button>
        <button id="btn-save-edit-sources" class="btn-primary">保存并重新生成</button>
    </div>
</div>
</div>

<script>
(function(){
let appData = {};
const currentOrigin = '${originVar}';
const base64Var = '${base64Var}';
let lastExtractResult = []; 
let currentEditingFile = null;
let currentEditingIPs = [];

try { 
    const raw = atob(base64Var);
    appData = JSON.parse(decodeURIComponent(escape(raw))); 
    appData.urls = (appData.urls || []).map(u => typeof u === 'string' ? {name:'', url:u} : u);
    appData.apis = (appData.apis || []).map(u => typeof u === 'string' ? {name:'', url:u} : u);
} catch(e) { console.error('Init Error', e); }

function formatBeijingTime(isoString) {
    if (!isoString) return '--';
    const date = new Date(isoString);
    return date.toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false, timeZone: 'Asia/Shanghai' });
}

function getRecipeHtml(sources) {
    if(!sources) return '';
    let html = '';
    if(sources.includeCustom) html += '<span class="src-badge custom">📝 自定义IP</span>';
    if(sources.files && sources.files.length) sources.files.forEach(f => {
        if(appData.uploadedFiles.includes(f)) html += '<span class="src-badge file">📄 ' + escapeHtml(f) + '</span>';
        else html += '<span class="src-badge editable">✏️ ' + escapeHtml(f) + '</span>';
    });
    if(sources.urls && sources.urls.length) {
        sources.urls.forEach(idx => {
            const item = appData.urls[idx];
            const name = item ? (item.name || '订阅#'+(idx+1)) : '未知';
            html += '<span class="src-badge sub">📡 ' + escapeHtml(name) + '</span>';
        });
    }
    if(sources.apis && sources.apis.length) {
        sources.apis.forEach(idx => {
            const item = appData.apis[idx];
            const name = item ? (item.name || 'API#'+(idx+1)) : '未知';
            html += '<span class="src-badge api">🔗 ' + escapeHtml(name) + '</span>';
        });
    }
    return html;
}

function render() {
    const renderSourceList = (id, list, type) => {
        document.getElementById(id).innerHTML = list.map((item, i) => 
            '<div class="item"><div class="item-content"><div style="font-weight:700;color:var(--text-main); font-size: 1rem;">' + (item.name ? escapeHtml(item.name) : '<span style="color:#94a3b8;font-style:italic">未命名</span>') + '</div><div style="font-size:0.875rem;color:var(--text-sub);margin-top:0.25rem;word-break:break-all">' + escapeHtml(item.url) + '</div></div><button class="btn-danger" data-action="delete" data-type="' + type + '" data-val="' + i + '" style="padding:0.5rem 1rem;font-size:0.875rem;">🗑️ 删除</button></div>'
        ).join('');
    };
    renderSourceList('url-list', appData.urls, 'urls');
    renderSourceList('api-list', appData.apis, 'apis');
    
    document.getElementById('uploaded-list').innerHTML = appData.uploadedFiles.map(t => 
        '<div class="item"><div class="item-content">📄 <strong style="font-size: 1rem;">' + escapeHtml(t) + '</strong></div><div style="display:flex; gap:0.75rem;"><button class="btn-secondary preview-btn" data-filename="' + escapeHtml(t) + '" style="padding:0.5rem 1rem;font-size:0.875rem;">👁️ 预览</button><button class="btn-danger" data-action="delete-file" data-val="' + escapeHtml(t) + '" style="padding:0.5rem 1rem;font-size:0.875rem;">🗑️ 删除</button></div></div>'
    ).join('');

    document.getElementById('custom-ips').value = appData.customIPs.join('\\n');
    document.getElementById('ip-count').innerText = appData.customIPs.length;

    const ipSitesHtml = [];
    const friendSitesHtml = [];
    (appData.sitesList || []).forEach((s, realIdx) => {
        if(s.type === 'ip') {
           ipSitesHtml.push('<div class="item"><div class="item-content"><a href="' + escapeHtml(s.url) + '" target="_blank" style="font-weight:700;color:var(--primary);text-decoration:none;font-size: 1rem;">🔗 ' + escapeHtml(s.name) + '</a><div style="color:var(--text-sub);font-size:0.875rem;margin-top:0.25rem">' + escapeHtml(s.url) + '</div></div><button class="btn-danger" data-action="del-site" data-val="' + realIdx + '" style="padding:0.5rem 1rem;font-size:0.875rem;">🗑️ 删除</button></div>');
        } else if(s.type === 'friend') {
           friendSitesHtml.push('<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:0.75rem;"><a href="' + escapeHtml(s.url) + '" target="_blank" class="link-card" style="flex:1;margin-bottom:0">👉 ' + escapeHtml(s.name) + '</a><span data-action="del-site" data-val="' + realIdx + '" style="cursor:pointer;color:var(--text-sub);font-size:0.875rem;padding:0.25rem 0.5rem; border-radius: 0.25rem; transition: all 0.2s;">✕</span></div>');
        }
    });
    document.getElementById('site-list-ip').innerHTML = ipSitesHtml.join('');
    document.getElementById('friend-links-list').innerHTML = friendSitesHtml.join('');

    const renderChecks = (prefix) => {
        let html = '';
        if(appData.uploadedFiles.length) {
            html += '<div style="grid-column:1/-1;font-weight:700;color:var(--primary);margin-top:0.5rem;margin-bottom:0.75rem;padding-bottom:0.5rem;border-bottom:1px solid var(--border); display: flex; align-items: center; gap: 0.5rem;">📂 上传的文件</div>';
            appData.uploadedFiles.forEach(f => { html += '<label><input type="checkbox" value="' + escapeHtml(f) + '" class="' + prefix + '-file-cb"> ' + escapeHtml(f) + '</label>'; });
        }
        if(appData.editableFiles.length) {
            html += '<div style="grid-column:1/-1;font-weight:700;color:#7c3aed;margin-top:0.5rem;margin-bottom:0.75rem;padding-bottom:0.5rem;border-bottom:1px solid var(--border); display: flex; align-items: center; gap: 0.5rem;">✏️ 可编辑文件</div>';
            appData.editableFiles.forEach(f => { html += '<label><input type="checkbox" value="' + escapeHtml(f.name) + '" class="' + prefix + '-file-cb"> ' + escapeHtml(f.name) + '</label>'; });
        }
        if(appData.urls.length) {
            html += '<div style="grid-column:1/-1;font-weight:700;color:var(--primary);margin-top:1rem;margin-bottom:0.75rem;padding-bottom:0.5rem;border-bottom:1px solid var(--border); display: flex; align-items: center; gap: 0.5rem;">📡 订阅链接</div>';
            appData.urls.forEach((item,i) => { 
                const name = item.name || ('订阅 #' + (i+1));
                html += '<label><input type="checkbox" value="' + i + '" class="' + prefix + '-url-cb"> ' + escapeHtml(name) + '</label>'; 
            });
        }
        if(appData.apis.length) {
            html += '<div style="grid-column:1/-1;font-weight:700;color:var(--primary);margin-top:1rem;margin-bottom:0.75rem;padding-bottom:0.5rem;border-bottom:1px solid var(--border); display: flex; align-items: center; gap: 0.5rem;">🔗 API</div>';
            appData.apis.forEach((item,i) => { 
                const name = item.name || ('API #' + (i+1));
                html += '<label><input type="checkbox" value="' + i + '" class="' + prefix + '-api-cb"> ' + escapeHtml(name) + '</label>'; 
            });
        }
        return html || '<div style="color:var(--text-sub);padding:1rem;text-align:center;">⚠️ 暂无数据源</div>';
    };
    document.getElementById('ext-sources').innerHTML = renderChecks('ext');
    document.getElementById('file-sources').innerHTML = renderChecks('file');

    document.getElementById('file-list').innerHTML = appData.ipFiles.map(f => {
        const stats = f.stats || { total: 0, today: 0, lastAccess: null };
        const lastAccessStr = stats.lastAccess ? formatBeijingTime(stats.lastAccess) : '--';
        return '<div class="item"><div class="item-content" style="display:flex;flex-direction:column;gap:0.75rem"><div style="font-weight:700;color:var(--primary); font-size: 1.125rem;">' + escapeHtml(f.name) + ' ' + (f.autoUpdate?'<span class="badge auto">🔄 自动更新</span>':'<span class="badge">⚪️ 手动更新</span>') + '</div><div style="margin-top:0.25rem;display:flex;flex-wrap:wrap;gap:0.5rem">' + getRecipeHtml(f.sources) + '</div><div class="stats-info"><span>🔥 总访问: ' + (stats.total||0) + '</span><span>📅 今日: ' + (stats.today||0) + '</span><span>🕒 最后: ' + lastAccessStr + '</span></div><div style="display:flex;gap:0.75rem;margin-top:0.75rem"><a href="' + currentOrigin + '/ip/' + f.name + '" target="_blank" style="color:var(--primary);text-decoration:none;font-weight:600;padding:0.375rem 0.75rem;background: var(--primary-light); border-radius: 0.375rem; font-size: 0.875rem;">🔗 Workers链接</a><a href="' + currentOrigin + '/r2/' + f.name + '" target="_blank" style="color:var(--success);text-decoration:none;font-weight:600;padding:0.375rem 0.75rem;background: var(--success-light); border-radius: 0.375rem; font-size: 0.875rem;">🚀 R2直链</a></div></div><div style="display:flex;flex-direction:column;gap:0.5rem"><button class="btn-warning" data-action="update-file" data-val="' + escapeHtml(f.name) + '" style="padding:0.5rem 1rem;font-size:0.875rem;">⚡️ 立即更新</button><button class="btn-secondary" data-action="edit-sources" data-val="' + escapeHtml(f.name) + '" style="padding:0.5rem 1rem;font-size:0.875rem;">✏️ 编辑源</button><button class="btn-secondary" data-action="reset-stats" data-val="' + escapeHtml(f.name) + '" style="padding:0.5rem 1rem;font-size:0.875rem;">🔄 重置统计</button><button class="btn-danger" data-action="delete-file-gen" data-val="' + escapeHtml(f.name) + '" style="padding:0.5rem 1rem;font-size:0.875rem;">🗑️ 删除</button></div></div>';
    }).join('');

    document.getElementById('editable-list').innerHTML = (appData.editableFiles || []).map(f => {
        const stats = f.stats || { total: 0, today: 0, lastAccess: null };
        const lastAccessStr = stats.lastAccess ? formatBeijingTime(stats.lastAccess) : '--';
        const ipCount = f.ips ? f.ips.length : 0;
        return '<div class="item"><div class="item-content" style="display:flex;flex-direction:column;gap:0.75rem"><div style="font-weight:700;color:#7c3aed; font-size: 1.125rem;">' + escapeHtml(f.name) + ' <span class="badge editable">✏️ 可编辑</span></div><div class="stats-info"><span>📊 IP数量: ' + ipCount + '</span><span>📅 更新: ' + formatBeijingTime(f.lastUpdate) + '</span><span>🔥 访问: ' + (stats.total||0) + '</span></div></div><div style="display:flex;flex-direction:column;gap:0.5rem"><button class="btn-primary" data-action="edit-file" data-val="' + escapeHtml(f.name) + '" style="padding:0.5rem 1rem;font-size:0.875rem;">✏️ 编辑</button><button class="btn-danger" data-action="delete-editable" data-val="' + escapeHtml(f.name) + '" style="padding:0.5rem 1rem;font-size:0.875rem;">🗑️ 删除</button></div></div>';
    }).join('');
}

document.addEventListener('click', async e => {
    const t = e.target;
    if (t.classList.contains('tab')) {
        document.querySelectorAll('.tab').forEach(x=>x.classList.remove('active'));
        document.querySelectorAll('.tab-content').forEach(x=>x.classList.remove('active'));
        t.classList.add('active');
        document.getElementById(t.dataset.tab + '-tab').classList.add('active');
        return;
    }
    if (t.classList.contains('sub-tab')) {
        const parent = t.closest('.tab-content');
        parent.querySelectorAll('.sub-tab').forEach(x=>x.classList.remove('active'));
        parent.querySelectorAll('.sub-tab-content').forEach(x=>x.classList.remove('active'));
        t.classList.add('active');
        document.getElementById(t.dataset.subTab + '-sub-tab').classList.add('active');
        return;
    }
    if(t.closest('#upload-box')) { document.getElementById('file-input').click(); return; }
    
    if(t.classList.contains('preview-btn')) {
        const fileName = t.dataset.filename;
        t.disabled = true; t.innerText = '...';
        try {
            const res = await apiCall('/api/extract', 'POST', { sources: { files: [fileName], urls: [], apis: [], includeCustom: false } });
            alert('文件 "' + fileName + '" 可提取 ' + res.count + ' 个IP:\\n\\n' + res.ips.slice(0, 5).join('\\n') + (res.count > 5 ? '\\n...' : ''));
        } catch(e) { showMsg(e.message, 'error'); }
        t.disabled = false; t.innerText = '👁️ 预览';
    }

    if(t.id === 'ext-select-all') { document.querySelectorAll('#ext-sources input[type="checkbox"]').forEach(cb => cb.checked = true); }
    if(t.id === 'ext-deselect-all') { document.querySelectorAll('#ext-sources input[type="checkbox"]').forEach(cb => cb.checked = false); }
    if(t.id === 'file-select-all') { document.querySelectorAll('#file-sources input[type="checkbox"]').forEach(cb => cb.checked = true); }
    if(t.id === 'file-deselect-all') { document.querySelectorAll('#file-sources input[type="checkbox"]').forEach(cb => cb.checked = false); }

    const action = t.dataset.action;
    const val = t.dataset.val;
    
    if(action === 'delete') {
        if(confirm('确认删除?')) { 
            const type = t.dataset.type;
            const idx = parseInt(val);
            try {
                const res = await apiCall('/api/' + type, 'DELETE', {index: idx});
                if(res.success) {
                    if(type === 'urls') appData.urls.splice(idx, 1);
                    else if(type === 'apis') appData.apis.splice(idx, 1);
                    render();
                    showMsg('已删除'); 
                } else { showMsg(res.error || '删除失败', 'error'); }
            } catch(e) { showMsg(e.message, 'error'); }
        }
    } 
    else if(action === 'delete-file') {
        if(confirm('确认删除文件 ' + val + '?')) { 
            try {
                const res = await apiCall('/api/uploaded_files', 'DELETE', {fileName: val});
                if(res.success) {
                    const idx = appData.uploadedFiles.indexOf(val);
                    if(idx !== -1) { appData.uploadedFiles.splice(idx, 1); render(); }
                    showMsg('已删除');
                } else { showMsg(res.error || '删除失败', 'error'); }
            } catch(e) { showMsg(e.message, 'error'); }
        }
    } 
    else if(action === 'delete-file-gen') {
        if(confirm('删除生成的文件?')) { 
            try {
                const res = await fetch('/api/ipfiles?name=' + val, {method:'DELETE'});
                const result = await res.json();
                if(result.success) {
                    const idx = appData.ipFiles.findIndex(f => f.name === val);
                    if(idx !== -1) { appData.ipFiles.splice(idx, 1); render(); }
                    showMsg('已删除');
                } else { showMsg(result.error || '删除失败', 'error'); }
            } catch(e) { showMsg(e.message, 'error'); }
        }
    } 
    else if(action === 'delete-editable') {
        if(confirm('删除可编辑文件?')) { 
            try {
                const res = await apiCall('/api/editable_files', 'DELETE', {fileName: val});
                if(res.success) {
                    const idx = appData.editableFiles.findIndex(f => f.name === val);
                    if(idx !== -1) { appData.editableFiles.splice(idx, 1); render(); }
                    showMsg('已删除');
                } else { showMsg(res.error || '删除失败', 'error'); }
            } catch(e) { showMsg(e.message, 'error'); }
        }
    }
    else if(action === 'update-file') {
        if(confirm('立即更新?')) { 
            const res = await apiCall('/api/ipfiles', 'PUT', {fileName: val}); 
            const idx = appData.ipFiles.findIndex(f => f.name === val);
            if(idx !== -1 && res.meta) { appData.ipFiles[idx] = {...appData.ipFiles[idx], ...res.meta}; render(); }
            showMsg('更新成功'); 
        }
    } 
    else if(action === 'edit-file') {
        currentEditingFile = val;
        const fileData = appData.editableFiles.find(f => f.name === val);
        if(fileData) {
            currentEditingIPs = [...(fileData.ips || [])];
            openEditModal();
        }
    }
    else if(action === 'reset-stats') {
        if(confirm('确认重置文件 "' + val + '" 的访问统计?')) { 
            try {
                await apiCall('/api/reset-stats', 'POST', {fileName: val});
                const idx = [...appData.ipFiles, ...appData.editableFiles].findIndex(f => f.name === val);
                if(idx !== -1) {
                    if(idx < appData.ipFiles.length) appData.ipFiles[idx].stats = { total: 0, today: 0, lastAccess: null };
                    else appData.editableFiles[idx - appData.ipFiles.length].stats = { total: 0, today: 0, lastAccess: null };
                    render();
                }
                showMsg('统计已重置'); 
            } catch(e) { showMsg(e.message, 'error'); }
        }
    }
    else if(action === 'edit-sources') {
        const fileName = val;
        currentEditingFile = fileName;
        const fileMeta = appData.ipFiles.find(f => f.name === fileName);
        if(!fileMeta) { showMsg('文件不存在', 'error'); return; }
        document.getElementById('edit-file-name').textContent = fileName;
        document.getElementById('edit-auto-update').checked = fileMeta.autoUpdate || false;
        const renderEditChecks = () => {
            let html = '';
            if(appData.uploadedFiles.length) {
                html += '<div style="grid-column:1/-1;font-weight:700;color:var(--primary);margin-top:0.5rem;margin-bottom:0.75rem;padding-bottom:0.5rem;border-bottom:1px solid var(--border);">📂 上传的文件</div>';
                appData.uploadedFiles.forEach(f => { 
                    const checked = fileMeta.sources.files && fileMeta.sources.files.includes(f) ? 'checked' : '';
                    html += '<label><input type="checkbox" value="' + escapeHtml(f) + '" class="edit-file-cb" ' + checked + '> ' + escapeHtml(f) + '</label>'; 
                });
            }
            if(appData.editableFiles.length) {
                html += '<div style="grid-column:1/-1;font-weight:700;color:#7c3aed;margin-top:0.5rem;margin-bottom:0.75rem;padding-bottom:0.5rem;border-bottom:1px solid var(--border);">✏️ 可编辑文件</div>';
                appData.editableFiles.forEach(f => { 
                    const checked = fileMeta.sources.files && fileMeta.sources.files.includes(f.name) ? 'checked' : '';
                    html += '<label><input type="checkbox" value="' + escapeHtml(f.name) + '" class="edit-file-cb" ' + checked + '> ' + escapeHtml(f.name) + '</label>'; 
                });
            }
            if(appData.urls.length) {
                html += '<div style="grid-column:1/-1;font-weight:700;color:var(--primary);margin-top:1rem;margin-bottom:0.75rem;padding-bottom:0.5rem;border-bottom:1px solid var(--border);">📡 订阅链接</div>';
                appData.urls.forEach((item,i) => { 
                    const name = item.name || ('订阅 #' + (i+1));
                    const checked = fileMeta.sources.urls && fileMeta.sources.urls.includes(i) ? 'checked' : '';
                    html += '<label><input type="checkbox" value="' + i + '" class="edit-url-cb" ' + checked + '> ' + escapeHtml(name) + '</label>'; 
                });
            }
            if(appData.apis.length) {
                html += '<div style="grid-column:1/-1;font-weight:700;color:var(--primary);margin-top:1rem;margin-bottom:0.75rem;padding-bottom:0.5rem;border-bottom:1px solid var(--border);">🔗 API</div>';
                appData.apis.forEach((item,i) => { 
                    const name = item.name || ('API #' + (i+1));
                    const checked = fileMeta.sources.apis && fileMeta.sources.apis.includes(i) ? 'checked' : '';
                    html += '<label><input type="checkbox" value="' + i + '" class="edit-api-cb" ' + checked + '> ' + escapeHtml(name) + '</label>'; 
                });
            }
            return html || '<div style="color:var(--text-sub);padding:1rem;text-align:center;">⚠️ 暂无数据源</div>';
        };
        document.getElementById('edit-sources').innerHTML = renderEditChecks();
        document.getElementById('edit-custom').checked = fileMeta.sources.includeCustom || false;
        document.getElementById('edit-sources-modal').style.display = 'block';
    }
    else if(action === 'del-site') {
        if(confirm('删除此链接?')) { 
            try {
                const res = await apiCall('/api/sites', 'DELETE', {index: parseInt(val)});
                if(res.success) { appData.sitesList.splice(parseInt(val), 1); render(); showMsg('已删除'); } else { showMsg(res.error || '删除失败', 'error'); }
            } catch(e) { showMsg(e.message, 'error'); }
        }
    }
    
    if(t.id === 'btn-add-url') {
        const name = document.getElementById('new-url-name').value;
        const url = document.getElementById('new-url-link').value;
        if(url) {
            const item = {name, url}; appData.urls.push(item);
            document.getElementById('new-url-name').value=''; document.getElementById('new-url-link').value='';
            render(); apiCall('/api/urls', 'POST', {items:[item]}); showMsg('已添加');
        }
    }
    if(t.id === 'btn-add-api') {
        const name = document.getElementById('new-api-name').value;
        const url = document.getElementById('new-api-link').value;
        if(url) {
            const item = {name, url}; appData.apis.push(item);
            document.getElementById('new-api-name').value=''; document.getElementById('new-api-link').value='';
            render(); apiCall('/api/apis', 'POST', {items:[item]}); showMsg('已添加');
        }
    }
    if(t.id === 'btn-save-custom') { const v=getLines('custom-ips'); appData.customIPs = v; render(); apiCall('/api/custom','POST',{ips:v}); showMsg('保存成功'); }
    if(t.id === 'btn-clear-custom') { if(confirm('清空?')) { document.getElementById('custom-ips').value=''; document.getElementById('btn-save-custom').click(); } }
    
    if(t.id === 'btn-add-site-ip') addSite('site-name-ip', 'site-url-ip', 'ip');
    if(t.id === 'btn-add-site-friend') addSite('site-name-friend', 'site-url-friend', 'friend');

    if(t.id === 'btn-extract') doExtract(t);
    if(t.id === 'btn-copy-extract') {
        if(lastExtractResult.length > 0) {
            navigator.clipboard.writeText(lastExtractResult.join('\\n'));
            showMsg('已复制 ' + lastExtractResult.length + ' 个IP');
        }
    }
    if(t.id === 'btn-save-file') doSaveFile(t);
    if(t.id === 'btn-tool-run') doTool(t);
    if(t.id === 'btn-tool-copy') { navigator.clipboard.writeText(document.getElementById('tool-output').innerText); showMsg('已复制'); }
    if(t.id === 'btn-tool-save') { saveToolResultAsEditable(); }
    
    if(t.id === 'btn-create-editable') {
        const fileName = prompt('请输入文件名:');
        if(fileName) {
            currentEditingFile = fileName;
            currentEditingIPs = [];
            openEditModal();
        }
    }
    
    if(t.id === 'btn-batch-add') {
        const text = document.getElementById('batch-ip-input').value;
        const parsed = parseBatchInput(text);
        if(parsed.length) {
            currentEditingIPs.push(...parsed);
            renderEditableIPList();
            document.getElementById('batch-ip-input').value = '';
            showMsg('已追加 ' + parsed.length + ' 个IP');
        } else { showMsg('未识别到有效IP', 'error'); }
    }
    
    if(t.id === 'btn-batch-replace') {
        if(!confirm('确定要覆盖现有列表吗？此操作不可撤销。')) return;
        const text = document.getElementById('batch-ip-input').value;
        const parsed = parseBatchInput(text);
        if(parsed.length) {
            currentEditingIPs = parsed;
            renderEditableIPList();
            document.getElementById('batch-ip-input').value = '';
            showMsg('已覆盖导入 ' + parsed.length + ' 个IP');
        } else { showMsg('未识别到有效IP', 'error'); }
    }
    
    if(t.id === 'btn-clear-all') {
        if(confirm('确定要清空所有IP吗？')) {
            currentEditingIPs = [];
            renderEditableIPList();
        }
    }
    
    if(t.id === 'btn-copy-list') {
        const text = currentEditingIPs.map(ip => ip.port ? \`\${ip.ip}:\${ip.port}\${ip.remark ? '#' + ip.remark : ''}\` : \`\${ip.ip}\${ip.remark ? '#' + ip.remark : ''}\`).join('\\n');
        navigator.clipboard.writeText(text);
        showMsg('已复制 ' + currentEditingIPs.length + ' 个IP');
    }
    
    if(t.id === 'btn-save-edit') {
        saveEditableFile();
    }
    
    if(t.id === 'btn-cancel-edit' || t.classList.contains('close')) {
        document.getElementById('edit-file-modal').style.display = 'none';
        currentEditingFile = null;
        currentEditingIPs = [];
    }
    
    if(t.id === 'btn-save-edit-sources') {
        const sources = {
            urls: Array.from(document.querySelectorAll('.edit-url-cb:checked')).map(cb => parseInt(cb.value)),
            apis: Array.from(document.querySelectorAll('.edit-api-cb:checked')).map(cb => parseInt(cb.value)),
            files: Array.from(document.querySelectorAll('.edit-file-cb:checked')).map(cb => cb.value),
            includeCustom: document.getElementById('edit-custom').checked
        };
        const autoUpdate = document.getElementById('edit-auto-update').checked;
        t.disabled = true; t.innerText = '保存中...';
        try {
            const res = await apiCall('/api/ipfiles', 'PATCH', { fileName: currentEditingFile, sources: sources, autoUpdate: autoUpdate });
            if(res.success) {
                showMsg('数据源已更新，文件已重新生成');
                document.getElementById('edit-sources-modal').style.display = 'none';
                const idx = appData.ipFiles.findIndex(f => f.name === currentEditingFile);
                if(idx !== -1 && res.meta) { appData.ipFiles[idx] = {...appData.ipFiles[idx], ...res.meta}; render(); }
            }
        } catch(e) { showMsg(e.message, 'error'); } finally { t.disabled = false; t.innerText = '保存并重新生成'; }
    }
    
    if(t.classList.contains('delete-ip-btn')) {
        const index = parseInt(t.dataset.index);
        currentEditingIPs.splice(index, 1);
        renderEditableIPList();
    }
});

document.getElementById('file-input').addEventListener('change', async function() {
    if(!this.files.length) return;
    const fd = new FormData(); fd.append('file', this.files[0]);
    showMsg('上传中...', 'success');
    try {
        const res = await fetch('/api/upload', {method:'POST', body:fd});
        const j = await res.json();
        if(!res.ok) throw new Error(j.error || '上传失败');
        if(!appData.uploadedFiles.includes(j.fileName)) { appData.uploadedFiles.push(j.fileName); render(); }
        showMsg('上传成功: ' + j.fileName);
    } catch(e) { showMsg(e.message, 'error'); }
    this.value = '';
});

function escapeHtml(s) { return s ? s.toString().replace(/&/g,"&amp;").replace(/</g,"&lt;") : ''; }
function getLines(id) { return document.getElementById(id).value.split('\\n').map(x=>x.trim()).filter(x=>x); }
function showMsg(txt, type) {
    if(!type) type = 'success';
    const m = document.getElementById('message'); m.innerText=txt; m.className='message '+type; m.style.display='block';
    setTimeout(()=>{ m.style.display='none'; }, 3000);
}
async function apiCall(u, m, d) {
    const r = await fetch(u, {method:m, headers:{'Content-Type':'application/json'}, body:JSON.stringify(d)});
    if(!r.ok) { const err = await r.json(); throw new Error(err.error || '请求失败'); }
    return r.json();
}

function addSite(nameId, urlId, type) {
    const n = document.getElementById(nameId).value;
    const u = document.getElementById(urlId).value;
    if(!n || !u) return alert('请填写完整');
    appData.sitesList.push({name:n, url:u, type:type});
    document.getElementById(nameId).value=''; document.getElementById(urlId).value='';
    render();
    apiCall('/api/sites', 'POST', {name:n, url:u, type:type});
    showMsg('已添加链接');
}

function getSources(p) {
    return {
        urls: Array.from(document.querySelectorAll('.'+p+'-url-cb:checked')).map(x=>+x.value),
        apis: Array.from(document.querySelectorAll('.'+p+'-api-cb:checked')).map(x=>+x.value),
        files: Array.from(document.querySelectorAll('.'+p+'-file-cb:checked')).map(x=>x.value),
        includeCustom: document.getElementById(p+'-custom').checked
    };
}

async function doExtract(btn) {
    btn.disabled=true; btn.innerText='⏳...';
    document.getElementById('btn-copy-extract').style.display = 'none';
    try {
        const res = await apiCall('/api/extract', 'POST', {sources: getSources('ext')});
        lastExtractResult = res.ips; 
        const resultEl = document.getElementById('extract-result');
        resultEl.innerText = '✅ 提取 ' + res.count + ' 个:\\n---\\n' + res.ips.join('\\n');
        if(res.count > 0) document.getElementById('btn-copy-extract').style.display = 'inline-flex';
    } catch(e) { showMsg(e.message, 'error'); }
    btn.disabled=false; btn.innerText='🚀 立即提取';
}

async function doSaveFile(btn) {
    const name = document.getElementById('file-name').value; if(!name) return alert('请输入文件名');
    btn.disabled=true; btn.innerText='⏳...';
    try {
        const res = await apiCall('/api/ipfiles', 'POST', {fileName:name, sources:getSources('file'), autoUpdate:document.getElementById('file-auto').checked});
        if(res.meta) { appData.ipFiles.push({...res.meta, stats: {total:0, today:0, lastAccess: null}}); render(); }
        showMsg('生成成功'); document.getElementById('file-name').value='';
    } catch(e) { alert(e.message); }
    btn.disabled=false; btn.innerText='💾 生成文件';
}

async function doTool(btn) {
    const v = getLines('tool-input'); if(!v.length) return;
    const deduplicate = document.getElementById('tool-deduplicate').checked;
    btn.disabled=true;
    try {
        const res = await apiCall('/api/tool_query', 'POST', {ipList:v, deduplicate: deduplicate});
        const outputEl = document.getElementById('tool-output');
        outputEl.style.display='block';
        outputEl.innerText = res.results.map(x=>x.formatted).join('\\n');
        document.getElementById('btn-tool-copy').style.display='inline-flex';
        document.getElementById('btn-tool-save').style.display='inline-flex';
        lastExtractResult = res.results.filter(x=>x.success).map(x=>x.formatted);
    } catch(e) { showMsg(e.message, 'error'); }
    btn.disabled=false;
}

function parseIPLine(line) {
    const parts = line.split('#');
    const ipPart = parts[0].trim();
    const remark = parts.length > 1 ? parts.slice(1).join('#').trim() : '';
    if (!ipPart) return null;
    const ipPort = ipPart.split(':');
    const ip = ipPort[0];
    const port = ipPort.length > 1 ? ipPort[1] : '443';
    const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (!ipv4Regex.test(ip)) return null;
    return { ip, port, remark };
}

function parseBatchInput(text) {
    const lines = text.split('\\n');
    const results = [];
    for(let line of lines) {
        const p = parseIPLine(line.trim());
        if(p) results.push(p);
    }
    return results;
}

function openEditModal() {
    document.getElementById('edit-file-name').textContent = currentEditingFile;
    document.getElementById('batch-ip-input').value = '';
    renderEditableIPList();
    document.getElementById('edit-file-modal').style.display = 'block';
}

function renderEditableIPList() {
    document.getElementById('current-ip-count').innerText = currentEditingIPs.length;
    const listEl = document.getElementById('editable-ip-list');
    listEl.innerHTML = currentEditingIPs.map((ip, index) => {
        const text = ip.port ? \`\${ip.ip}:\${ip.port}\${ip.remark ? '#' + ip.remark : ''}\` : \`\${ip.ip}\${ip.remark ? '#' + ip.remark : ''}\`;
        return \`<div class="editable-ip-item">
            <div class="editable-ip-text">\${escapeHtml(text)}</div>
            <div class="editable-ip-actions">
                <button class="btn-danger btn-small delete-ip-btn" data-index="\${index}">🗑️</button>
            </div>
        </div>\`;
    }).join('');
}

async function saveEditableFile() {
    if (!currentEditingFile || !currentEditingIPs.length) { showMsg('文件名或IP列表不能为空', 'error'); return; }
    try {
        const res = await apiCall('/api/editable_files', 'PUT', { fileName: currentEditingFile, ips: currentEditingIPs });
        if (res.success) {
            showMsg('文件保存成功');
            document.getElementById('edit-file-modal').style.display = 'none';
            const idx = appData.editableFiles.findIndex(f => f.name === currentEditingFile);
            if (idx !== -1) {
                appData.editableFiles[idx].ips = currentEditingIPs;
                appData.editableFiles[idx].lastUpdate = new Date().toISOString();
            } else {
                appData.editableFiles.push({ name: currentEditingFile, editable: true, ips: currentEditingIPs, lastUpdate: new Date().toISOString(), stats: { total: 0, today: 0, lastAccess: null } });
            }
            render();
        }
    } catch(e) { showMsg(e.message, 'error'); }
}

async function saveToolResultAsEditable() {
    if (!lastExtractResult.length) { showMsg('没有可保存的结果', 'error'); return; }
    const fileName = prompt('请输入文件名:');
    if (!fileName) return;
    const ips = lastExtractResult.map(line => {
        const parts = line.split('#');
        const ipPart = parts[0].trim();
        const remark = parts.length > 1 ? parts.slice(1).join('#').trim() : '';
        const ipPort = ipPart.split(':');
        const ip = ipPort[0];
        const port = ipPort.length > 1 ? ipPort[1] : '443';
        return { ip, port, remark };
    });
    try {
        const res = await apiCall('/api/editable_files', 'POST', { fileName: fileName, ips: ips });
        if (res.success) {
            showMsg('保存成功');
            appData.editableFiles.push({ name: fileName, editable: true, ips: ips, lastUpdate: new Date().toISOString(), stats: { total: 0, today: 0, lastAccess: null } });
            render();
        }
    } catch(e) { showMsg(e.message, 'error'); }
}

render();
})();
</script>
</body>
</html>`;
}
