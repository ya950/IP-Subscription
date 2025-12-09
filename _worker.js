// Cloudflare Workers 节点管理系统 v9.9.4 (自定义命名版)
// ==========================================
// 更新日志 v9.9.4:
// 1. [修复] 修复重置统计API路径错误问题
// 2. [修复] 修复北京时间显示不准确的问题
// 3. [修复] 修复TG上传显示成功但实际未上传的问题
// 4. [修复] 修复删除操作后刷新又回来的问题
// 5. [优化] 改进错误处理和日志记录
// 6. [功能] 包含 v9.9.3 的所有功能
// ==========================================

const KV_BINDING_NAME = "IP_NODES"; 
const TG_FILE_LIMIT = 5 * 1024 * 1024; // 5MB

// ==========================================
// 1. 核心工具模块
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
  }
};

// ==========================================
// 2. Worker 入口
// ==========================================
export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (path === '/api/tg_hook' && request.method === 'POST') return await handleTelegramWebhook(request, env);

    if (!env.ADMIN_PASSWORD) return new Response("配置错误: 请在环境变量中设置 ADMIN_PASSWORD", { status: 500 });

    if ((path.startsWith('/ip/') && path.length > 4) || (path.length > 1 && path !== '/admin' && path !== '/' && !path.startsWith('/api/'))) {
      return await handleIPFile(request, env, ctx, path);
    }
    if (path === '/admin' || path === '/') return await handleAdmin(request, env);
    if (path.startsWith('/api/')) return await handleAPI(request, env, path);

    return Response.redirect(url.origin + '/admin', 302);
  },
  async scheduled(event, env, ctx) {
    ctx.waitUntil(handleCronJob(env));
  }
};

// ==========================================
// 3. API 逻辑
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
         if (request.method === 'GET') return await getList(env, apiAction === 'custom' ? 'custom_ips' : apiAction);
         if (request.method === 'POST') return await addItem(request, env, apiAction);
         if (request.method === 'DELETE' && apiAction !== 'custom') return await deleteItem(request, env, apiAction);
         break;
      case 'sites':
         if (request.method === 'GET') return await getSites(env);
         if (request.method === 'POST') return await addSite(request, env);
         if (request.method === 'DELETE') return await deleteSite(request, env);
         break;
      case 'upload': return await handleUpload(request, env);
      case 'uploaded_files':
         if (request.method === 'GET') return await getList(env, 'uploaded_files');
         if (request.method === 'DELETE') return await deleteUploadedFile(request, env);
         break;
      case 'extract': return await extractIPs(request, env);
      case 'ipfiles':
        if (request.method === 'GET') return await getIPFiles(env);
        if (request.method === 'POST') return await saveIPFile(request, env);
        if (request.method === 'DELETE') return await deleteIPFile(request, env);
        if (request.method === 'PUT') return await updateIPFile(request, env);
        if (request.method === 'PATCH') return await editIPFileSources(request, env);
        break;
      case 'reset-stats': return await resetFileStats(request, env);
      case 'tool_query': return await handleToolQuery(request);
      case 'logout': return await logout(request, env);
    }
  } catch (error) { 
    console.error("API Error:", error);
    return new Response(JSON.stringify({ error: error.message }), { status: 500 }); 
  }
  return new Response('Not Found', { status: 404 });
}

// 修复：TG上传处理函数
async function handleTelegramWebhook(req, env) {
    if (!env.TG_BOT_TOKEN) return new Response('No Token', { status: 200 });
    try {
        const update = await req.json();
        if (!update.message || !update.message.document) return new Response('OK', { status: 200 });

        const msg = update.message;
        const chatId = msg.chat.id;
        if (env.TG_WHITELIST_ID && String(chatId) !== String(env.TG_WHITELIST_ID)) {
             await sendTgMsg(env, chatId, "🚫 无权访问");
             return new Response('Unauthorized', { status: 200 });
        }

        const doc = msg.document;
        const fileName = doc.file_name;
        
        if (doc.file_size && doc.file_size > TG_FILE_LIMIT) {
             await sendTgMsg(env, chatId, "⚠️ 文件过大 (超过5MB)，请分割后上传");
             return new Response('OK', { status: 200 });
        }

        if (!fileName.match(/\.(csv|txt)$/i)) {
             await sendTgMsg(env, chatId, "⚠️ 仅支持 .csv 或 .txt 文件");
             return new Response('OK', { status: 200 });
        }

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
            if (/[\u4e00-\u9fa5]/.test(gbkText) && !/[\u4e00-\u9fa5]/.test(text)) {
                text = gbkText;
            }
        } catch (e) {}

        const cleanNodes = IPExtractor.processBatch(text);
        if (cleanNodes.length === 0) {
            await sendTgMsg(env, chatId, "❌ 文件中未找到有效的IP节点");
            return new Response('OK', { status: 200 });
        }

        const content = cleanNodes.map(n => {
            const base = n.port ? `${n.ip}:${n.port}` : n.ip;
            return n.remark ? `${base}#${n.remark}` : base; 
        }).join('\n');

        let saveName = fileName;
        let fileList = await env[KV_BINDING_NAME].get('uploaded_files', { type: 'json' }) || [];
        if (fileList.includes(saveName)) {
            const parts = saveName.split('.');
            const ext = parts.length > 1 ? '.' + parts.pop() : '';
            saveName = `${parts.join('.')}_${Math.floor(1000 + Math.random() * 9000)}${ext}`;
        }
        
        // 修复：确保先保存文件内容，再更新文件列表
        await env[KV_BINDING_NAME].put(`file_content_${saveName}`, content);
        fileList.push(saveName);
        await env[KV_BINDING_NAME].put('uploaded_files', JSON.stringify(fileList));

        await sendTgMsg(env, chatId, `✅ 上传成功!\n文件名: ${saveName}\n包含节点: ${cleanNodes.length} 个`);

    } catch (e) { 
        console.error('TG upload error:', e);
        await sendTgMsg(env, chatId, `❌ 上传失败: ${e.message}`);
    }
    return new Response('OK', { status: 200 });
}

async function sendTgMsg(env, chatId, text) {
    await fetch(`https://api.telegram.org/bot${env.TG_BOT_TOKEN}/sendMessage`, {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ chat_id: chatId, text: text })
    });
}

async function queryExternalAPI(ip, port, retry = 0) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 3000);

    try {
        const apiUrl = retry > 0 ? `http://ip-api.com/json/${ip}?fields=countryCode` : `https://ipinfo.io/${ip}/json`;
        const res = await fetch(apiUrl, { 
            headers: { 'User-Agent': 'Mozilla/5.0 (compatible; Node-IP-Checker/1.0)' }, 
            cf: { cacheTtl: 3600, cacheEverything: true },
            signal: controller.signal 
        });
        clearTimeout(timeoutId);
        
        const data = await res.json();
        let code = 'UN';
        if (data.country) code = data.country; 
        else if (data.countryCode) code = data.countryCode; 
        return code;
    } catch (e) {
        clearTimeout(timeoutId); 
        if (e.name === 'AbortError') return 'TIMEOUT'; 
        if (retry < 1) return await queryExternalAPI(ip, port, retry + 1); 
        return 'ERR';
    }
}

async function handleUpload(request, env) {
    const formData = await request.formData();
    const file = formData.get('file');
    if (!file || !(file instanceof File)) return new Response(JSON.stringify({ error: '无效文件' }), { status: 400 });
    
    let text = await file.text();
    try {
        const buffer = await file.arrayBuffer();
        const decoder = new TextDecoder('gbk');
        const gbkText = decoder.decode(buffer);
        if (/[\u4e00-\u9fa5]/.test(gbkText) && !/[\u4e00-\u9fa5]/.test(text)) {
            text = gbkText;
        }
    } catch (e) {}

    const cleanNodes = IPExtractor.processBatch(text);
    if (cleanNodes.length === 0) return new Response(JSON.stringify({ error: '文件中未找到有效的IP节点' }), { status: 400 });
    
    const content = cleanNodes.map(n => {
        const base = n.port ? `${n.ip}:${n.port}` : n.ip;
        return n.remark ? `${base}#${n.remark}` : base; 
    }).join('\n');
    
    let fileName = file.name;
    let fileList = await env[KV_BINDING_NAME].get('uploaded_files', { type: 'json' }) || [];
    if (fileList.includes(fileName)) {
        const parts = fileName.split('.');
        const ext = parts.length > 1 ? '.' + parts.pop() : '';
        const base = parts.join('.');
        fileName = `${base}_${Math.floor(1000 + Math.random() * 9000)}${ext}`;
    }
    await env[KV_BINDING_NAME].put(`file_content_${fileName}`, content);
    fileList.push(fileName);
    await env[KV_BINDING_NAME].put('uploaded_files', JSON.stringify(fileList));
    return new Response(JSON.stringify({ success: true, fileName, count: cleanNodes.length }));
}

// 修复：删除上传文件函数
async function deleteUploadedFile(req, env) {
    const b = await req.json();
    let fileList = await env[KV_BINDING_NAME].get('uploaded_files', { type: 'json' }) || [];
    const idx = fileList.indexOf(b.fileName);
    if (idx !== -1) {
        fileList.splice(idx, 1);
        await env[KV_BINDING_NAME].put('uploaded_files', JSON.stringify(fileList));
        await env[KV_BINDING_NAME].delete(`file_content_${b.fileName}`);
        // 修复：确保删除操作完成后返回成功状态
        return new Response(JSON.stringify({ success: true, fileName: b.fileName }));
    }
    return new Response(JSON.stringify({ error: 'File not found' }), { status: 404 });
}

// 【v9.9】源解析逻辑兼容对象
async function performExtraction(env, sources) {
  let nodeMap = new Map();
  // 兼容旧数据（字符串）和新数据（对象）
  const urls = (await env[KV_BINDING_NAME].get('urls', { type: 'json' }) || []).map(x => typeof x === 'string' ? {url:x} : x);
  const apis = (await env[KV_BINDING_NAME].get('apis', { type: 'json' }) || []).map(x => typeof x === 'string' ? {url:x} : x);
  
  const custom = await env[KV_BINDING_NAME].get('custom_ips', { type: 'json' }) || [];
  const uploadedFiles = await env[KV_BINDING_NAME].get('uploaded_files', { type: 'json' }) || [];
  let allCandidates = [];

  if (sources.includeCustom) IPExtractor.processBatch(custom).forEach(r => allCandidates.push({...r, source: 'custom'}));
  
  if (sources.files && Array.isArray(sources.files)) {
      const filePromises = sources.files.map(async (fileName) => {
          if (uploadedFiles.includes(fileName)) {
              const content = await env[KV_BINDING_NAME].get(`file_content_${fileName}`);
              if (content) return IPExtractor.processBatch(content).map(r => ({...r, source: 'file'}));
          }
          return [];
      });
      (await Promise.all(filePromises)).forEach(r => allCandidates.push(...r));
  }
  
  const apiPromises = (sources.apis || []).map(async (i) => {
      const item = apis[i];
      if (item && item.url) try { 
          const c = new AbortController();
          const id = setTimeout(() => c.abort(), 5000);
          const t = await (await fetch(item.url, { signal: c.signal })).text(); 
          clearTimeout(id);
          return IPExtractor.processBatch(t).map(r => ({...r, source: 'api'})); 
      } catch (e) { return []; } return [];
  });
  (await Promise.all(apiPromises)).forEach(r => allCandidates.push(...r));
  
  const urlPromises = (sources.urls || []).map(async (i) => {
      const item = urls[i];
      if (item && item.url) try { 
          const c = new AbortController();
          const id = setTimeout(() => c.abort(), 5000);
          const res = await fetch(item.url, { headers: { 'User-Agent': 'v2rayN/1.0' }, signal: c.signal });
          const txt = await res.text();
          clearTimeout(id);
          return parseSubscription(txt).map(r => ({...r, source: 'sub'})); 
      } catch (e) { return []; } return [];
  });
  (await Promise.all(urlPromises)).forEach(r => allCandidates.push(...r));

  const processedNodes = [];
  const pendingNodes = [];
  
  for (const node of allCandidates) {
      const safePort = node.port || "443";
      if (node.remark && node.remark.trim() !== "") {
          processedNodes.push({ ip: node.ip, port: safePort, remark: node.remark });
      } else {
          pendingNodes.push({ ip: node.ip, port: safePort });
      }
  }

  const BATCH_SIZE = 15;
  for (let i = 0; i < pendingNodes.length; i += BATCH_SIZE) {
      const batch = pendingNodes.slice(i, i + BATCH_SIZE);
      const results = await Promise.all(batch.map(async (node) => {
          const country = await queryExternalAPI(node.ip, node.port);
          return { ip: node.ip, port: node.port, remark: country };
      }));
      processedNodes.push(...results);
  }

  for (const node of processedNodes) {
      const key = `${node.ip}:${node.port}`;
      if (!nodeMap.has(key)) nodeMap.set(key, node.remark);
      else {
          const old = nodeMap.get(key);
          if (old === 'ERR' || old === 'UN' || old === 'TIMEOUT' || (node.remark !== 'ERR' && node.remark.length > old.length)) nodeMap.set(key, node.remark);
      }
  }

  const result = [];
  for (let [key, remark] of nodeMap) result.push(`${key}#${remark}`);
  return result;
}

function parseSubscription(c) {
  const n = []; let d = c;
  try { if (!c.includes(' ') && c.length > 50) d = atob(c.trim().replace(/\s/g, '')); } catch (e) {}
  d.split(/[\r\n]+/).forEach(l => {
    const t = l.trim(); if (!t) return;
    if (t.startsWith('vmess://')) { try { const j = JSON.parse(atob(t.substring(8))); if (IPExtractor.isValidIP(j.add)) n.push({ ip: j.add, port: j.port, remark: j.ps }); return; } catch (e) {} }
    if (t.match(/^(vless|trojan|ss):\/\//)) { try { const u = new URL(t); if (IPExtractor.isValidIP(u.hostname)) n.push({ ip: u.hostname, port: u.port, remark: u.hash ? decodeURIComponent(u.hash.substring(1)) : '' }); return; } catch(e) {} }
    const processed = IPExtractor.processBatch([t]);
    if (processed.length > 0) n.push(processed[0]);
  });
  return n;
}

async function handleToolQuery(request) {
    const { ipList } = await request.json();
    if (!ipList || !Array.isArray(ipList)) throw new Error('无效的IP列表');
    const items = IPExtractor.processBatch(ipList);
    if (items.length > 200) throw new Error('一次最多查询200个IP');
    
    const processedNodes = [];
    const pendingNodes = items; 
    
    const BATCH_SIZE = 15;
    for (let i = 0; i < pendingNodes.length; i += BATCH_SIZE) {
        const batch = pendingNodes.slice(i, i + BATCH_SIZE);
        const results = await Promise.all(batch.map(async (item) => {
            const code = await queryExternalAPI(item.ip, item.port);
            return { ...item, remark: code };
        }));
        processedNodes.push(...results);
    }

    const finalResults = processedNodes.map(item => {
        const fmt = item.port ? `${item.ip}:${item.port}#${item.remark}` : `${item.ip}#${item.remark}`;
        return { formatted: fmt, success: item.remark !== 'ERR' && item.remark !== 'TIMEOUT' };
    });

    return new Response(JSON.stringify({ results: finalResults }), { headers: { 'Content-Type': 'application/json' } });
}

// 站点 CRUD
async function getSites(env) { return new Response(JSON.stringify(await env[KV_BINDING_NAME].get('sites_list', { type: 'json' }) || [])); }
async function addSite(req, env) {
    const b = await req.json(); 
    let l = await env[KV_BINDING_NAME].get('sites_list', { type: 'json' }) || [];
    l.push(b);
    await env[KV_BINDING_NAME].put('sites_list', JSON.stringify(l));
    return new Response(JSON.stringify({ success: true }));
}
// 修复：删除站点函数
async function deleteSite(req, env) {
    const b = await req.json(); 
    let l = await env[KV_BINDING_NAME].get('sites_list', { type: 'json' }) || [];
    if(b.index >= 0) { 
        l.splice(b.index, 1); 
        await env[KV_BINDING_NAME].put('sites_list', JSON.stringify(l)); 
        // 修复：确保删除操作完成后返回成功状态
        return new Response(JSON.stringify({ success: true, index: b.index })); 
    }
    return new Response(JSON.stringify({ error: 'Invalid index' }), { status: 400 });
}

// 通用CRUD
async function getList(env, key) { 
    // 【v9.9】读取时如果不兼容旧数据（纯字符串），不会崩，但前端显示需处理
    return new Response(JSON.stringify(await env[KV_BINDING_NAME].get(key, { type: 'json' }) || [])); 
}
async function addItem(req, env, act) {
  const b = await req.json(); // {name, url} for apis/urls
  const k = act === 'custom' ? 'ips' : act; 
  let list = [];
  if(act === 'custom') list = b.ips || [];
  else list = b.items || []; // items = [{name,url}]

  if(act !== 'custom') { 
      let old = await env[KV_BINDING_NAME].get(act, {type:'json'}) || [];
      // 兼容：如果旧数据是字符串数组，转对象
      old = old.map(x => typeof x === 'string' ? {name:'', url:x} : x);
      list = [...old, ...list];
  }
  await env[KV_BINDING_NAME].put(act === 'custom' ? 'custom_ips' : act, JSON.stringify(list));
  return new Response(JSON.stringify({success:true}));
}
// 修复：删除项目函数
async function deleteItem(req, env, key) {
  const b = await req.json(); 
  let l = await env[KV_BINDING_NAME].get(key, { type: 'json' }) || [];
  if (b.index >= 0) { 
    l.splice(b.index, 1); 
    await env[KV_BINDING_NAME].put(key, JSON.stringify(l)); 
    // 修复：确保删除操作完成后返回成功状态
    return new Response(JSON.stringify({ success: true, index: b.index })); 
  }
  return new Response(JSON.stringify({ error: 'Invalid index' }), { status: 400 });
}
async function getIPFiles(env) {
  const l = await env[KV_BINDING_NAME].list({ prefix: 'ip_file_meta_' }); const f = [];
  for (const k of l.keys) {
    const m = await env[KV_BINDING_NAME].get(k.name, { type: 'json' });
    const s = await env[KV_BINDING_NAME].get(`ip_stats_${m.name}`, { type: 'json' }) || { total: 0, today: 0, lastAccess: null };
    if (m) f.push({...m, stats: s});
  }
  return new Response(JSON.stringify(f));
}
async function saveIPFile(req, env) {
  const b = await req.json(); 
  const r = await performExtraction(env, b.sources);
  const meta = { name: b.fileName, sources: b.sources, autoUpdate: b.autoUpdate, lastUpdate: new Date().toISOString() };
  await env[KV_BINDING_NAME].put(`ip_file_${b.fileName}`, JSON.stringify({ content: r.join('\n'), lastUpdate: new Date().toISOString() }));
  await env[KV_BINDING_NAME].put(`ip_file_meta_${b.fileName}`, JSON.stringify(meta));
  // 初始化统计
  await env[KV_BINDING_NAME].put(`ip_stats_${b.fileName}`, JSON.stringify({ total: 0, today: 0, lastAccess: null }));
  return new Response(JSON.stringify({ success: true, count: r.length, meta: meta }));
}
// 修复：删除IP文件函数
async function deleteIPFile(req, env) {
  const n = new URL(req.url).searchParams.get('name');
  if (!n) {
    return new Response(JSON.stringify({ error: 'File name is required' }), { status: 400 });
  }
  
  await env[KV_BINDING_NAME].delete(`ip_file_${n}`); 
  await env[KV_BINDING_NAME].delete(`ip_file_meta_${n}`); 
  await env[KV_BINDING_NAME].delete(`ip_stats_${n}`);
  // 修复：确保删除操作完成后返回成功状态
  return new Response(JSON.stringify({ success: true, fileName: n }));
}
async function updateIPFile(req, env) {
  const b = await req.json(); 
  const m = await env[KV_BINDING_NAME].get(`ip_file_meta_${b.fileName}`, { type: 'json' }); if(!m) throw new Error('Not found');
  const r = await performExtraction(env, m.sources);
  await env[KV_BINDING_NAME].put(`ip_file_${b.fileName}`, JSON.stringify({ content: r.join('\n'), lastUpdate: new Date().toISOString() }));
  m.lastUpdate = new Date().toISOString(); 
  await env[KV_BINDING_NAME].put(`ip_file_meta_${b.fileName}`, JSON.stringify(m));
  return new Response(JSON.stringify({ success: true, count: r.length, meta: m }));
}

// 新增编辑文件数据源功能
async function editIPFileSources(req, env) {
  const b = await req.json(); 
  const { fileName, sources, autoUpdate } = b;
  
  if (!fileName) throw new Error('文件名不能为空');
  
  const meta = await env[KV_BINDING_NAME].get(`ip_file_meta_${fileName}`, { type: 'json' });
  if (!meta) throw new Error('文件不存在');
  
  // 更新数据源配置和自动更新设置
  const updatedMeta = {
    ...meta,
    sources: sources,
    autoUpdate: autoUpdate !== undefined ? autoUpdate : meta.autoUpdate,
    lastUpdate: new Date().toISOString()
  };
  
  // 重新生成文件内容
  const r = await performExtraction(env, sources);
  await env[KV_BINDING_NAME].put(`ip_file_${fileName}`, JSON.stringify({ 
    content: r.join('\n'), 
    lastUpdate: new Date().toISOString() 
  }));
  
  await env[KV_BINDING_NAME].put(`ip_file_meta_${fileName}`, JSON.stringify(updatedMeta));
  
  return new Response(JSON.stringify({ 
    success: true, 
    count: r.length,
    meta: updatedMeta 
  }));
}

// 修复：重置统计功能
async function resetFileStats(req, env) {
  const { fileName } = await req.json();
  if (!fileName) throw new Error('文件名不能为空');
  
  await env[KV_BINDING_NAME].put(`ip_stats_${fileName}`, JSON.stringify({ 
    total: 0, 
    today: 0, 
    lastAccess: null 
  }));
  
  return new Response(JSON.stringify({ success: true }));
}

async function extractIPs(req, env) { const b = await req.json(); const r = await performExtraction(env, b.sources); return new Response(JSON.stringify({ ips: r, count: r.length })); }
async function logout(req, env) { const c = req.headers.get('Cookie'); if(c) { const id = c.split('session=')[1]?.split(';')[0]; if(id) await env[KV_BINDING_NAME].delete(`session_${id}`); } return new Response(null, { status: 302, headers: { 'Set-Cookie': 'session=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0', 'Location': '/admin' } }); }
async function checkSession(req, env) { const c = req.headers.get('Cookie'); if(!c) return false; const id = c.match(/session=([^;]+)/)?.[1]; if(!id) return false; return await env[KV_BINDING_NAME].get(`session_${id}`) === 'valid'; }

// ==========================================
// 4. 页面处理
// ==========================================
// 修复：格式化时间为北京时间
function formatBeijingTime(isoString) {
    if (!isoString) return '--';
    // 直接解析ISO字符串，然后使用Asia/Shanghai时区格式化
    const date = new Date(isoString);
    return date.toLocaleString('zh-CN', {
        year: 'numeric',
        month: '2-digit',
        day: '2-digit',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        hour12: false,
        timeZone: 'Asia/Shanghai' // 直接使用时区转换，不需要手动偏移
    });
}

async function handleIPFile(request, env, ctx, path) {
  const fileName = path.replace('/ip/', '').replace(/^\//, '');
  const kvKey = `ip_file_${fileName}`;
  const statsKey = `ip_stats_${fileName}`;
  
  try {
    const fileData = await env[KV_BINDING_NAME].get(kvKey, { type: 'json' });
    if (!fileData) return new Response('IP file not found', { status: 404 });
    
    // 修复：每次访问都更新统计，使用北京时间
    ctx.waitUntil((async () => {
        try {
            let stats = await env[KV_BINDING_NAME].get(statsKey, { type: 'json' }) || { total: 0, today: 0, lastAccess: null };
            
            // 获取当前北京时间
            const now = new Date();
            const beijingTime = new Date(now.toLocaleString("en-US", {timeZone: "Asia/Shanghai"}));
            const todayStr = beijingTime.toISOString().split('T')[0];
            
            // 检查是否是新的一天（使用北京时间）
            if (stats.date !== todayStr) {
                stats.date = todayStr;
                stats.today = 0;
            }
            
            // 更新统计
            stats.total = (stats.total || 0) + 1; 
            stats.today = (stats.today || 0) + 1;
            // 修复：存储UTC时间，显示时再转换为北京时间
            stats.lastAccess = now.toISOString(); // 存储标准UTC时间
            
            await env[KV_BINDING_NAME].put(statsKey, JSON.stringify(stats));
        } catch(e) {
            console.error('Stats update error:', e);
        }
    })());
    
    return new Response(fileData.content, { 
      headers: { 
        'Content-Type': 'text/plain; charset=utf-8', 
        'Access-Control-Allow-Origin': '*'
      } 
    });
  } catch (error) { 
    console.error('File serving error:', error);
    return new Response('Error', { status: 500 }); 
  }
}

async function handleCronJob(env) {
  const kv = env[KV_BINDING_NAME];
  try {
    const list = await kv.list({ prefix: 'ip_file_meta_' });
    for (const key of list.keys) {
      const meta = await kv.get(key.name, { type: 'json' });
      if (meta && meta.autoUpdate) {
        const r = await performExtraction(env, meta.sources);
        await kv.put(`ip_file_${meta.name}`, JSON.stringify({ content: r.join('\n'), lastUpdate: new Date().toISOString() }));
        meta.lastUpdate = new Date().toISOString(); await kv.put(key.name, JSON.stringify(meta));
      }
    }
  } catch (e) { console.error("Cron job failed:", e); }
}

async function handleAdmin(req, env) {
  const url = new URL(req.url); const sess = await checkSession(req, env);
  if (!sess && url.searchParams.get('action') !== 'login') return new Response(getLoginPage(), { headers: { 'Content-Type': 'text/html; charset=utf-8' }});
  if (url.searchParams.get('action') === 'login') {
    const fd = await req.formData();
    if (fd.get('password') === env.ADMIN_PASSWORD) {
      const id = crypto.randomUUID(); await env[KV_BINDING_NAME].put(`session_${id}`, 'valid', { expirationTtl: 86400 });
      return new Response('', { status: 302, headers: { 'Set-Cookie': `session=${id}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=86400`, 'Location': '/admin' } });
    }
    return new Response(getLoginPage('密码错误'), { headers: { 'Content-Type': 'text/html; charset=utf-8' }});
  }
  const [urls, apis, customIPs, uploadedFiles, ipFilesRaw, sitesList] = await Promise.all([
      env[KV_BINDING_NAME].get('urls', {type:'json'})||[],
      env[KV_BINDING_NAME].get('apis', {type:'json'})||[],
      env[KV_BINDING_NAME].get('custom_ips', {type:'json'})||[],
      env[KV_BINDING_NAME].get('uploaded_files', {type:'json'})||[],
      env[KV_BINDING_NAME].list({prefix:'ip_file_meta_'}),
      env[KV_BINDING_NAME].get('sites_list', {type:'json'})||[]
  ]);
  const ipFiles = [];
  for (const k of ipFilesRaw.keys) {
      const m = await env[KV_BINDING_NAME].get(k.name, {type:'json'});
      const s = await env[KV_BINDING_NAME].get(`ip_stats_${m.name}`, {type:'json'}) || {total:0, today:0, lastAccess:null};
      if(m) ipFiles.push({...m, stats: s});
  }
  const jsonStr = JSON.stringify({ urls, apis, customIPs, uploadedFiles, ipFiles, sitesList });
  const base64Data = btoa(unescape(encodeURIComponent(jsonStr)));
  return new Response(getAdminPage(base64Data, url.origin), { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

function getLoginPage(error = '') {
    return `<!DOCTYPE html><html lang="zh-CN"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><title>系统登录</title><style>:root{--primary:#6366f1;--bg:#f3f4f6;--surface:#ffffff;--text:#1f2937}body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:var(--bg);display:flex;justify-content:center;align-items:center;height:100vh;margin:0}.login-box{background:var(--surface);padding:2.5rem;border-radius:1rem;box-shadow:0 10px 25px -5px rgba(0,0,0,0.1);width:100%;max-width:360px;text-align:center}h2{margin-bottom:1.5rem;color:var(--text);font-weight:700}input{width:100%;padding:.75rem 1rem;margin-bottom:1rem;border:1px solid #e5e7eb;border-radius:.5rem;font-size:1rem;box-sizing:border-box;outline:none;transition:all .2s}input:focus{border-color:var(--primary);box-shadow:0 0 0 3px rgba(99,102,241,0.2)}button{width:100%;padding:.75rem;background:var(--primary);color:white;border:none;border-radius:.5rem;font-size:1rem;font-weight:600;cursor:pointer;transition:background .2s}button:hover{background:#4f46e5}.error{background:#fee2e2;color:#991b1b;padding:.75rem;border-radius:.5rem;margin-top:1rem;font-size:.875rem}</style></head><body><div class="login-box"><h2>🔒 节点管理系统</h2><form method="POST" action="/admin?action=login"><input type="password" name="password" placeholder="请输入访问密码" required autofocus><button type="submit">立即登录</button>${error?`<div class="error">${error}</div>`:''}</form></div></body></html>`;
}

function getAdminPage(base64Data, origin) {
    return `<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>节点 IP 管理控制台 v9.9.4</title>
<style>
    :root { --primary: #4f46e5; --primary-hover: #4338ca; --danger: #ef4444; --danger-hover: #dc2626; --success: #10b981; --warning: #f59e0b; --bg: #f3f4f6; --surface: #ffffff; --text-main: #111827; --text-sub: #6b7280; --border: #e5e7eb; --radius: 0.75rem; }
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: var(--bg); color: var(--text-main); line-height: 1.5; padding-bottom: 2rem; }
    .container { max-width: 1100px; margin: 0 auto; padding: 0 1rem; }
    header { display: flex; justify-content: space-between; align-items: center; padding: 1.5rem 0; margin-bottom: 1rem; }
    h1 { font-size: 1.5rem; font-weight: 800; background: linear-gradient(to right, #4f46e5, #ec4899); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
    .logout { font-size: 0.875rem; color: var(--text-sub); text-decoration: none; cursor: pointer; display: flex; align-items: center; gap: 4px; }
    .logout:hover { color: var(--danger); }
    .message { position: fixed; top: 20px; right: 20px; padding: 1rem 1.5rem; border-radius: var(--radius); background: var(--surface); box-shadow: 0 10px 15px -3px rgba(0,0,0,0.1); display: none; z-index: 100; border-left: 4px solid var(--primary); font-weight: 500; }
    .message.success { border-color: var(--success); color: #065f46; background: #d1fae5; }
    .message.error { border-color: var(--danger); color: #991b1b; background: #fee2e2; }
    .tabs { display: flex; gap: 0.5rem; margin-bottom: 1.5rem; overflow-x: auto; padding-bottom: 4px; flex-wrap: wrap; }
    .tab { padding: 0.6rem 1.2rem; background: transparent; border: none; border-radius: 2rem; cursor: pointer; color: var(--text-sub); font-weight: 600; font-size: 0.95rem; white-space: nowrap; transition: all 0.2s; }
    .tab:hover { background: #e0e7ff; color: var(--primary); }
    .tab.active { background: var(--primary); color: white; box-shadow: 0 4px 12px rgba(79, 70, 229, 0.3); }
    .tab-content { display: none; background: var(--surface); border-radius: var(--radius); padding: 2rem; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); animation: fadeIn 0.3s ease; }
    .tab-content.active { display: block; }
    @keyframes fadeIn { from { opacity: 0; transform: translateY(10px); } to { opacity: 1; transform: translateY(0); } }
    h2 { font-size: 1.25rem; margin-bottom: 1.5rem; color: var(--text-main); font-weight: 700; border-left: 4px solid var(--primary); padding-left: 12px; }
    .form-group { margin-bottom: 1.2rem; }
    textarea, input[type="text"] { width: 100%; padding: 0.75rem; border: 1px solid var(--border); border-radius: 0.5rem; background: #f9fafb; outline: none; font-family: monospace; }
    textarea:focus, input[type="text"]:focus { border-color: var(--primary); background: #fff; box-shadow: 0 0 0 3px rgba(79, 70, 229, 0.1); }
    button { padding: 0.75rem 1.5rem; border: none; border-radius: 0.5rem; cursor: pointer; font-weight: 600; font-size: 0.9rem; transition: all 0.2s; display: inline-flex; align-items: center; justify-content: center; gap: 6px; }
    button:disabled { opacity: 0.6; cursor: not-allowed; filter: grayscale(100%); }
    .btn-primary, .btn-success { background: var(--primary); color: white; }
    .btn-primary:hover, .btn-success:hover { background: var(--primary-hover); transform: translateY(-1px); }
    .btn-danger { background: #fee2e2; color: var(--danger); }
    .btn-danger:hover { background: #fecaca; }
    .btn-warning { background: #fef3c7; color: #b45309; }
    .btn-warning:hover { background: #fde68a; }
    .btn-secondary { background: #e5e7eb; color: var(--text-main); }
    .btn-secondary:hover { background: #d1d5db; }
    .item-list { margin-top: 1.5rem; display: flex; flex-direction: column; gap: 0.75rem; }
    .item { display: flex; justify-content: space-between; align-items: center; padding: 1rem; background: #f9fafb; border: 1px solid var(--border); border-radius: 0.5rem; transition: all 0.2s; }
    .item-content { flex: 1; word-break: break-all; margin-right: 1rem; font-family: monospace; font-size: 0.85rem; color: #374151; }
    .item-meta { font-size: 0.75rem; color: var(--text-sub); margin-top: 4px; display: flex; gap: 10px; align-items: center;}
    .badge { padding: 2px 8px; border-radius: 10px; background: #e5e7eb; font-size: 0.7rem; font-weight: 600; }
    .badge.auto { background: #d1fae5; color: #065f46; }
    .src-badge { display: inline-block; padding: 2px 6px; margin: 2px; border-radius: 4px; font-size: 0.7rem; background: #e5e7eb; color: #4b5563; border: 1px solid #d1d5db; }
    .src-badge.custom { background: #fee2e2; color: #991b1b; border-color: #fecaca; }
    .src-badge.file { background: #dbeafe; color: #1e40af; border-color: #bfdbfe; }
    .src-badge.sub { background: #d1fae5; color: #065f46; border-color: #a7f3d0; }
    .src-badge.api { background: #fef3c7; color: #b45309; border-color: #fde68a; }
    .checkbox-group { display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 0.8rem; margin-top: 1rem; padding: 1rem; background: #f9fafb; border-radius: 0.5rem; border: 1px solid var(--border); }
    .checkbox-group label { margin: 0; display: flex; align-items: center; cursor: pointer; padding: 0.5rem; border-radius: 0.3rem; font-size: 0.85rem;}
    .checkbox-group label:hover { background: #e0e7ff; }
    .checkbox-group input { margin-right: 0.6rem; accent-color: var(--primary); width: 1.1rem; height: 1.1rem; }
    .upload-area { border: 2px dashed #cbd5e1; border-radius: 0.5rem; padding: 2rem; text-align: center; background: #fff; cursor: pointer; }
    .upload-area:hover { border-color: var(--primary); background: #eff6ff; }
    pre { background: #1f2937; color: #e5e7eb; padding: 1rem; border-radius: 0.5rem; font-size: 0.85rem; max-height: 400px; overflow-y: auto; margin-top: 1rem; border: 1px solid #374151; white-space: pre-wrap; word-wrap: break-word; }
    .sub-tabs { display: flex; gap: 0.5rem; margin-bottom: 1.5rem; border-bottom: 1px solid var(--border); }
    .sub-tab { padding: 0.5rem 1rem; background: transparent; border: none; border-bottom: 2px solid transparent; cursor: pointer; color: var(--text-sub); font-weight: 600; font-size: 0.9rem; transition: all 0.2s; }
    .sub-tab:hover { color: var(--primary); }
    .sub-tab.active { color: var(--primary); border-bottom-color: var(--primary); }
    .sub-tab-content { display: none; }
    .sub-tab-content.active { display: block; }
    .tools-layout { display: grid; grid-template-columns: 1fr 300px; gap: 20px; }
    .tools-sidebar { background: #f9fafb; padding: 1.5rem; border-radius: var(--radius); border: 1px solid var(--border); }
    .link-card { display: block; padding: 10px; margin-bottom: 8px; background: white; border: 1px solid var(--border); border-radius: 6px; text-decoration: none; color: var(--text-main); font-size: 0.9rem; display: flex; align-items: center; transition: all 0.2s; }
    .link-card:hover { border-color: var(--primary); color: var(--primary); transform: translateX(3px); }
    /* 编辑数据源模态框样式 */
    .modal { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background-color: rgba(0,0,0,0.5); z-index: 1000; }
    .modal-content { background-color: var(--surface); margin: 5% auto; padding: 2rem; border-radius: var(--radius); width: 90%; max-width: 800px; max-height: 80vh; overflow-y: auto; }
    .modal-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 1.5rem; }
    .modal-title { font-size: 1.25rem; font-weight: 700; color: var(--text-main); }
    .close { color: var(--text-sub); font-size: 1.5rem; font-weight: bold; cursor: pointer; }
    .close:hover { color: var(--danger); }
    .modal-body { margin-bottom: 1.5rem; }
    .modal-footer { display: flex; justify-content: flex-end; gap: 1rem; }
    .edit-section { margin-bottom: 1.5rem; }
    .edit-section h3 { font-size: 1rem; margin-bottom: 0.8rem; color: var(--text-main); border-left: 3px solid var(--primary); padding-left: 8px; }
    .stats-info { display: flex; gap: 15px; align-items: center; font-size: 0.8rem; color: var(--text-sub); }
    .stats-info span { display: flex; align-items: center; gap: 4px; }
    @media (max-width: 800px) { .tools-layout { grid-template-columns: 1fr; } }
    @media (max-width: 640px) { .container { padding: 0 0.5rem; } .tab { padding: 0.5rem 1rem; font-size: 0.85rem; } .tab-content { padding: 1.5rem 1rem; } .item { flex-direction: column; align-items: flex-start; gap: 10px; } .item button { width: 100%; } }
</style>
</head>
<body>
<div class="container">
    <header>
        <h1>⚡️ 节点管理控制台 v9.9.4</h1>
        <a href="/api/logout" class="logout"><svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1"></path></svg> 退出</a>
    </header>
    <div id="message" class="message"></div>

    <nav class="tabs">
        <button class="tab active" data-tab="sources">🌐 IP来源</button>
        <button class="tab" data-tab="extract">🧪 提取测试</button>
        <button class="tab" data-tab="files">📂 文件生成</button>
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
            <h2>上传本地 IP 文件 (CSV/TXT)</h2>
            <div class="upload-area" id="upload-box">
                <svg width="40" height="40" fill="none" stroke="#9ca3af" stroke-width="2" viewBox="0 0 24 24"><path stroke-linecap="round" stroke-linejoin="round" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"></path></svg>
                <p>点击或拖拽文件到此处<br><span style="font-size:0.8rem">(也支持直接发文件给 TG 机器人)</span></p>
                <input type="file" id="file-input" style="display:none">
            </div>
            <div style="background:#eff6ff; padding:10px; border-radius:5px; margin:15px 0; font-size:0.85rem; color:#1e3a8a; border-left:4px solid #3b82f6;"><strong>提示：</strong> 上传后系统会自动去重和标准化。如果配置了 TG 机器人，可以直接转发 CSV 文件给机器人自动上传。</div>
            <div class="item-list" id="uploaded-list"></div>
        </div>

        <div id="urls-sub-tab" class="sub-tab-content">
            <h2>订阅链接</h2>
            <div class="form-group" style="display:flex; gap:10px">
                <input type="text" id="new-url-name" placeholder="名称 (选填)" style="flex:1">
                <input type="text" id="new-url-link" placeholder="订阅链接 (必填)" style="flex:2">
            </div>
            <button id="btn-add-url" class="btn-success">添加订阅链接</button>
            <div class="item-list" id="url-list"></div>
        </div>

        <div id="apis-sub-tab" class="sub-tab-content">
            <h2>API 接口</h2>
            <div class="form-group" style="display:flex; gap:10px">
                <input type="text" id="new-api-name" placeholder="名称 (选填)" style="flex:1">
                <input type="text" id="new-api-link" placeholder="API 链接 (必填)" style="flex:2">
            </div>
            <button id="btn-add-api" class="btn-success">添加 API</button>
            <div class="item-list" id="api-list"></div>
        </div>

        <div id="custom-sub-tab" class="sub-tab-content">
            <h2>自定义 IP 池</h2>
            <div style="margin-bottom:10px; color:var(--text-sub)">数量: <strong id="ip-count" style="color:var(--primary)">0</strong></div>
            <div class="form-group"><textarea id="custom-ips" rows="12" placeholder="1.1.1.1:443#备注"></textarea></div>
            <div style="display:flex; gap:10px">
                <button id="btn-save-custom" class="btn-success">💾 保存</button>
                <button id="btn-clear-custom" class="btn-danger">🗑️ 清空</button>
            </div>
        </div>

        <div id="sites-ip-sub-tab" class="sub-tab-content">
            <h2>IP 资源网站收藏</h2>
            <div style="display:flex; gap:10px; margin-bottom:15px">
                <input type="text" id="site-name-ip" placeholder="网站名称" style="flex:1">
                <input type="text" id="site-url-ip" placeholder="网址 (http://...)" style="flex:2">
                <button id="btn-add-site-ip" class="btn-success">添加</button>
            </div>
            <div class="item-list" id="site-list-ip"></div>
        </div>
    </div>

    <div id="extract-tab" class="tab-content">
        <h2>提取预览</h2>
        <div class="form-group"><label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="checkbox" id="ext-custom" checked style="width:auto;margin:0"> 包含自定义 IP 池</label></div>
        <label>选择数据源：</label>
        <div style="display:flex; gap:10px; margin-bottom:10px;">
            <button id="ext-select-all" class="btn-primary" style="font-size:0.85rem; padding:0.5rem 1rem;">全选</button>
            <button id="ext-deselect-all" class="btn-danger" style="font-size:0.85rem; padding:0.5rem 1rem;">反选</button>
        </div>
        <div id="ext-sources" class="checkbox-group"></div>
        <div style="display:flex; gap:10px">
            <button id="btn-extract" class="btn-primary" style="margin-top:1.5rem; width:100%">🚀 立即提取</button>
            <button id="btn-copy-extract" class="btn-success" style="margin-top:1.5rem; width:auto; display:none;">📋 复制结果</button>
        </div>
        <pre id="extract-result">准备就绪...</pre>
    </div>

    <div id="files-tab" class="tab-content">
        <h2>生成订阅文件</h2>
        <div class="form-group"><label>文件名</label><input type="text" id="file-name" placeholder="例如: best_cf"></div>
        <div class="form-group">
             <div style="display:flex; gap:20px">
                <label style="display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" id="file-custom" checked style="width:auto;margin:0"> 包含自定义IP</label>
                <label style="display:flex;align-items:center;gap:6px;cursor:pointer"><input type="checkbox" id="file-auto" checked style="width:auto;margin:0"> 自动更新</label>
             </div>
        </div>
        <label>选择数据源：</label>
        <div style="display:flex; gap:10px; margin-bottom:10px;">
            <button id="file-select-all" class="btn-primary" style="font-size:0.85rem; padding:0.5rem 1rem;">全选</button>
            <button id="file-deselect-all" class="btn-danger" style="font-size:0.85rem; padding:0.5rem 1rem;">反选</button>
        </div>
        <div id="file-sources" class="checkbox-group"></div>
        <button id="btn-save-file" class="btn-success" style="margin-top:1.5rem; width:100%">💾 生成文件</button>
        <h3 style="margin-top:2rem;font-size:1.1rem;padding-left:10px;border-left:4px solid var(--warning)">已生成</h3>
        <div class="item-list" id="file-list"></div>
    </div>

    <div id="tools-tab" class="tab-content">
        <h2>IP 智能查询工具</h2>
        <div class="tools-layout">
            <div>
                <div style="background:#fff3cd; color:#856404; padding:10px; border-radius:5px; margin-bottom:10px; font-size:0.85rem; border-left:4px solid #ffeeba;"><strong>提示：</strong> 此处查询会忽略已有备注，强制刷新 API 获取最新国家信息。</div>
                <div class="form-group"><textarea id="tool-input" rows="12" placeholder="粘贴 IP 列表..."></textarea></div>
                <div style="display:flex; gap:10px">
                    <button id="btn-tool-run" class="btn-primary">🚀 开始查询</button>
                    <button id="btn-tool-copy" class="btn-success" style="display:none">📋 复制</button>
                </div>
                <pre id="tool-output" style="display:none;"></pre>
            </div>
            <div class="tools-sidebar">
                <h3 style="font-size:1rem; margin-bottom:1rem; border-left:3px solid var(--primary); padding-left:8px;">🔗 友情链接 / 工具</h3>
                <div id="friend-links-list"></div>
                <div style="margin-top:15px; border-top:1px solid #e5e7eb; padding-top:10px;">
                     <input type="text" id="site-name-friend" placeholder="名称" style="width:100%;margin-bottom:5px;padding:5px;">
                     <input type="text" id="site-url-friend" placeholder="链接" style="width:100%;margin-bottom:5px;padding:5px;">
                     <button id="btn-add-site-friend" class="btn-secondary" style="width:100%;font-size:0.8rem;">+ 添加链接</button>
                </div>
            </div>
        </div>
    </div>
</div>

<!-- 编辑数据源模态框 -->
<div id="edit-sources-modal" class="modal">
    <div class="modal-content">
        <div class="modal-header">
            <h3 class="modal-title">编辑文件数据源</h3>
            <span class="close">&times;</span>
        </div>
        <div class="modal-body">
            <div class="edit-section">
                <h3>文件名: <span id="edit-file-name" style="color: var(--primary);"></span></h3>
            </div>
            
            <div class="edit-section">
                <h3>自动更新</h3>
                <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
                    <input type="checkbox" id="edit-auto-update" style="width:auto;margin:0"> 启用自动更新
                </label>
            </div>
            
            <div class="edit-section">
                <h3>数据源配置</h3>
                <div style="display:flex; gap:10px; margin-bottom:10px;">
                    <button id="edit-select-all" class="btn-primary" style="font-size:0.85rem; padding:0.5rem 1rem;">全选</button>
                    <button id="edit-deselect-all" class="btn-danger" style="font-size:0.85rem; padding:0.5rem 1rem;">反选</button>
                </div>
                <div id="edit-sources" class="checkbox-group"></div>
            </div>
            
            <div class="edit-section">
                <h3>自定义IP</h3>
                <label style="display:flex;align-items:center;gap:8px;cursor:pointer">
                    <input type="checkbox" id="edit-custom" style="width:auto;margin:0"> 包含自定义IP池
                </label>
            </div>
        </div>
        <div class="modal-footer">
            <button id="btn-cancel-edit" class="btn-secondary">取消</button>
            <button id="btn-save-edit-sources" class="btn-success">保存并重新生成</button>
        </div>
    </div>
</div>

<script>
(function(){
    let appData = {};
    const currentOrigin = '${origin}';
    let lastExtractResult = []; 
    let currentEditingFile = null;

    try { 
        const raw = atob('${base64Data}');
        appData = JSON.parse(decodeURIComponent(escape(raw))); 
        
        // 兼容旧数据格式：如果 url/apis 是纯字符串数组，转为对象
        appData.urls = (appData.urls || []).map(u => typeof u === 'string' ? {name:'', url:u} : u);
        appData.apis = (appData.apis || []).map(u => typeof u === 'string' ? {name:'', url:u} : u);
    } catch(e) { console.error('Init Error', e); }

    // 修复：格式化时间为北京时间
    function formatBeijingTime(isoString) {
        if (!isoString) return '--';
        // 直接解析ISO字符串，然后使用Asia/Shanghai时区格式化
        const date = new Date(isoString);
        return date.toLocaleString('zh-CN', {
            year: 'numeric',
            month: '2-digit',
            day: '2-digit',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            hour12: false,
            timeZone: 'Asia/Shanghai' // 直接使用时区转换，不需要手动偏移
        });
    }

    function getRecipeHtml(sources) {
        if(!sources) return '';
        let html = '';
        if(sources.includeCustom) html += '<span class="src-badge custom">📝 自定义IP</span>';
        if(sources.files && sources.files.length) sources.files.forEach(f => html += '<span class="src-badge file">📄 ' + escapeHtml(f) + '</span>');
        
        // 【v9.9】配方显示自定义名称
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
        // 【v9.9】列表显示自定义名称
        const renderSourceList = (id, list, type) => {
            document.getElementById(id).innerHTML = list.map((item, i) => 
                '<div class="item"><div class="item-content"><div style="font-weight:bold;color:var(--text-main)">' + (item.name ? escapeHtml(item.name) : '<span style="color:#9ca3af;font-style:italic">未命名</span>') + '</div><div style="font-size:0.75rem;color:#6b7280;margin-top:2px;word-break:break-all">' + escapeHtml(item.url) + '</div></div><button class="btn-danger" data-action="delete" data-type="' + type + '" data-val="' + i + '" style="padding:0.4rem 0.8rem;font-size:0.8rem">删除</button></div>'
            ).join('');
        };
        
        renderSourceList('url-list', appData.urls, 'urls');
        renderSourceList('api-list', appData.apis, 'apis');
        
        document.getElementById('uploaded-list').innerHTML = appData.uploadedFiles.map(t => 
            '<div class="item"><div class="item-content">📄 <strong>' + escapeHtml(t) + '</strong></div><div style="display:flex; gap:5px;"><button class="btn-secondary preview-btn" data-filename="' + escapeHtml(t) + '" style="padding:0.4rem;font-size:0.8rem">预览</button><button class="btn-danger" data-action="delete-file" data-val="' + escapeHtml(t) + '" style="padding:0.4rem;font-size:0.8rem">删除</button></div></div>'
        ).join('');

        document.getElementById('custom-ips').value = appData.customIPs.join('\\n');
        document.getElementById('ip-count').innerText = appData.customIPs.length;

        const ipSitesHtml = [];
        const friendSitesHtml = [];
        (appData.sitesList || []).forEach((s, realIdx) => {
            if(s.type === 'ip') {
               ipSitesHtml.push('<div class="item"><div class="item-content"><a href="' + escapeHtml(s.url) + '" target="_blank" style="font-weight:bold;color:var(--primary);text-decoration:none">🔗 ' + escapeHtml(s.name) + '</a><div style="color:#666;font-size:0.8rem">' + escapeHtml(s.url) + '</div></div><button class="btn-danger" data-action="del-site" data-val="' + realIdx + '" style="padding:0.4rem;font-size:0.8rem">删除</button></div>');
            } else if(s.type === 'friend') {
               friendSitesHtml.push('<div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:5px;"><a href="' + escapeHtml(s.url) + '" target="_blank" class="link-card" style="flex:1;margin-bottom:0">👉 ' + escapeHtml(s.name) + '</a><span data-action="del-site" data-val="' + realIdx + '" style="cursor:pointer;color:#999;font-size:0.8rem;padding:0 5px;">✕</span></div>');
            }
        });
        document.getElementById('site-list-ip').innerHTML = ipSitesHtml.join('');
        document.getElementById('friend-links-list').innerHTML = friendSitesHtml.join('');

        // 【v9.9】Checkbox 显示自定义名称
        const renderChecks = (prefix) => {
            let html = '';
            if(appData.uploadedFiles.length) {
                html += '<div style="grid-column:1/-1;font-weight:bold;color:var(--primary);margin-top:5px;border-bottom:1px solid #e5e7eb">📂 上传的文件</div>';
                appData.uploadedFiles.forEach(f => { html += '<label><input type="checkbox" value="' + escapeHtml(f) + '" class="' + prefix + '-file-cb"> ' + escapeHtml(f) + '</label>'; });
            }
            if(appData.urls.length) {
                html += '<div style="grid-column:1/-1;font-weight:bold;color:var(--primary);margin-top:10px;border-bottom:1px solid #e5e7eb">📡 订阅链接</div>';
                appData.urls.forEach((item,i) => { 
                    const name = item.name || ('订阅 #' + (i+1));
                    html += '<label><input type="checkbox" value="' + i + '" class="' + prefix + '-url-cb"> ' + escapeHtml(name) + '</label>'; 
                });
            }
            if(appData.apis.length) {
                html += '<div style="grid-column:1/-1;font-weight:bold;color:var(--primary);margin-top:10px;border-bottom:1px solid #e5e7eb">🔗 API</div>';
                appData.apis.forEach((item,i) => { 
                    const name = item.name || ('API #' + (i+1));
                    html += '<label><input type="checkbox" value="' + i + '" class="' + prefix + '-api-cb"> ' + escapeHtml(name) + '</label>'; 
                });
            }
            return html || '<div style="color:#888;padding:10px">⚠️ 暂无数据源</div>';
        };
        document.getElementById('ext-sources').innerHTML = renderChecks('ext');
        document.getElementById('file-sources').innerHTML = renderChecks('file');

        // 修复：统计显示，使用北京时间
        document.getElementById('file-list').innerHTML = appData.ipFiles.map(f => {
            const stats = f.stats || { total: 0, today: 0, lastAccess: null };
            const lastAccessStr = stats.lastAccess ? formatBeijingTime(stats.lastAccess) : '--';
            
            return '<div class="item"><div class="item-content" style="display:flex;flex-direction:column;gap:4px"><div style="font-weight:700;color:var(--primary)">' + escapeHtml(f.name) + ' ' + (f.autoUpdate?'<span class="badge auto">🔄 自动</span>':'<span class="badge">⚪️ 手动</span>') + '</div><div style="margin-top:5px;display:flex;flex-wrap:wrap;gap:4px">' + getRecipeHtml(f.sources) + '</div><div class="stats-info"><span>🔥 ' + (stats.total||0) + '次</span><span>🕒 ' + lastAccessStr + '</span></div><a href="' + currentOrigin + '/ip/' + f.name + '" target="_blank" style="color:var(--primary);text-decoration:none;font-weight:600">🔗 链接地址</a></div><div style="display:flex;flex-direction:column;gap:5px"><button class="btn-warning" data-action="update-file" data-val="' + escapeHtml(f.name) + '" style="padding:0.4rem;font-size:0.8rem">⚡️</button><button class="btn-secondary" data-action="edit-sources" data-val="' + escapeHtml(f.name) + '" style="padding:0.4rem;font-size:0.8rem">✏️</button><button class="btn-secondary" data-action="reset-stats" data-val="' + escapeHtml(f.name) + '" style="padding:0.4rem;font-size:0.8rem">🔄</button><button class="btn-danger" data-action="delete-file-gen" data-val="' + escapeHtml(f.name) + '" style="padding:0.4rem;font-size:0.8rem">🗑️</button></div></div>';
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
            t.disabled = false; t.innerText = '预览';
        }

        if(t.id === 'ext-select-all') { document.querySelectorAll('#ext-sources input[type="checkbox"]').forEach(cb => cb.checked = true); }
        if(t.id === 'ext-deselect-all') { document.querySelectorAll('#ext-sources input[type="checkbox"]').forEach(cb => cb.checked = false); }
        if(t.id === 'file-select-all') { document.querySelectorAll('#file-sources input[type="checkbox"]').forEach(cb => cb.checked = true); }
        if(t.id === 'file-deselect-all') { document.querySelectorAll('#file-sources input[type="checkbox"]').forEach(cb => cb.checked = false); }
        if(t.id === 'edit-select-all') { document.querySelectorAll('#edit-sources input[type="checkbox"]').forEach(cb => cb.checked = true); }
        if(t.id === 'edit-deselect-all') { document.querySelectorAll('#edit-sources input[type="checkbox"]').forEach(cb => cb.checked = false); }

        const action = t.dataset.action;
        const val = t.dataset.val;
        
        // 修复：删除操作处理
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
                    } else {
                        showMsg(res.error || '删除失败', 'error');
                    }
                } catch(e) {
                    showMsg(e.message, 'error');
                }
            }
        } 
        else if(action === 'delete-file') {
            if(confirm('确认删除文件 ' + val + '?')) { 
                try {
                    const res = await apiCall('/api/uploaded_files', 'DELETE', {fileName: val});
                    if(res.success) {
                        const idx = appData.uploadedFiles.indexOf(val);
                        if(idx !== -1) {
                            appData.uploadedFiles.splice(idx, 1);
                            render();
                        }
                        showMsg('已删除');
                    } else {
                        showMsg(res.error || '删除失败', 'error');
                    }
                } catch(e) {
                    showMsg(e.message, 'error');
                }
            }
        } 
        else if(action === 'delete-file-gen') {
            if(confirm('删除生成的文件?')) { 
                try {
                    const res = await fetch('/api/ipfiles?name=' + val, {method:'DELETE'});
                    const result = await res.json();
                    if(result.success) {
                        const idx = appData.ipFiles.findIndex(f => f.name === val);
                        if(idx !== -1) {
                            appData.ipFiles.splice(idx, 1);
                            render();
                        }
                        showMsg('已删除');
                    } else {
                        showMsg(result.error || '删除失败', 'error');
                    }
                } catch(e) {
                    showMsg(e.message, 'error');
                }
            }
        } 
        else if(action === 'update-file') {
            if(confirm('立即更新?')) { 
                const res = await apiCall('/api/ipfiles', 'PUT', {fileName: val}); 
                const idx = appData.ipFiles.findIndex(f => f.name === val);
                if(idx !== -1 && res.meta) {
                    appData.ipFiles[idx] = {...appData.ipFiles[idx], ...res.meta};
                    render();
                }
                showMsg('更新成功'); 
            }
        } 
        // 修复：重置统计功能
        else if(action === 'reset-stats') {
            if(confirm('确认重置文件 "' + val + '" 的访问统计?')) { 
                try {
                    await apiCall('/api/reset-stats', 'POST', {fileName: val});
                    const idx = appData.ipFiles.findIndex(f => f.name === val);
                    if(idx !== -1) {
                        appData.ipFiles[idx].stats = { total: 0, today: 0, lastAccess: null };
                        render();
                    }
                    showMsg('统计已重置'); 
                } catch(e) {
                    showMsg(e.message, 'error');
                }
            }
        }
        // 新增编辑数据源功能
        else if(action === 'edit-sources') {
            const fileName = val;
            currentEditingFile = fileName;
            
            // 获取文件元数据
            const fileMeta = appData.ipFiles.find(f => f.name === fileName);
            if(!fileMeta) {
                showMsg('文件不存在', 'error');
                return;
            }
            
            // 显示文件名和当前配置
            document.getElementById('edit-file-name').textContent = fileName;
            document.getElementById('edit-auto-update').checked = fileMeta.autoUpdate || false;
            
            // 渲染数据源选择框
            const renderEditChecks = () => {
                let html = '';
                if(appData.uploadedFiles.length) {
                    html += '<div style="grid-column:1/-1;font-weight:bold;color:var(--primary);margin-top:5px;border-bottom:1px solid #e5e7eb">📂 上传的文件</div>';
                    appData.uploadedFiles.forEach(f => { 
                        const checked = fileMeta.sources.files && fileMeta.sources.files.includes(f) ? 'checked' : '';
                        html += '<label><input type="checkbox" value="' + escapeHtml(f) + '" class="edit-file-cb" ' + checked + '> ' + escapeHtml(f) + '</label>'; 
                    });
                }
                if(appData.urls.length) {
                    html += '<div style="grid-column:1/-1;font-weight:bold;color:var(--primary);margin-top:10px;border-bottom:1px solid #e5e7eb">📡 订阅链接</div>';
                    appData.urls.forEach((item,i) => { 
                        const name = item.name || ('订阅 #' + (i+1));
                        const checked = fileMeta.sources.urls && fileMeta.sources.urls.includes(i) ? 'checked' : '';
                        html += '<label><input type="checkbox" value="' + i + '" class="edit-url-cb" ' + checked + '> ' + escapeHtml(name) + '</label>'; 
                    });
                }
                if(appData.apis.length) {
                    html += '<div style="grid-column:1/-1;font-weight:bold;color:var(--primary);margin-top:10px;border-bottom:1px solid #e5e7eb">🔗 API</div>';
                    appData.apis.forEach((item,i) => { 
                        const name = item.name || ('API #' + (i+1));
                        const checked = fileMeta.sources.apis && fileMeta.sources.apis.includes(i) ? 'checked' : '';
                        html += '<label><input type="checkbox" value="' + i + '" class="edit-api-cb" ' + checked + '> ' + escapeHtml(name) + '</label>'; 
                    });
                }
                return html || '<div style="color:#888;padding:10px">⚠️ 暂无数据源</div>';
            };
            
            document.getElementById('edit-sources').innerHTML = renderEditChecks();
            document.getElementById('edit-custom').checked = fileMeta.sources.includeCustom || false;
            
            // 显示模态框
            document.getElementById('edit-sources-modal').style.display = 'block';
        }
        else if(action === 'del-site') {
            if(confirm('删除此链接?')) { 
                try {
                    const res = await apiCall('/api/sites', 'DELETE', {index: parseInt(val)});
                    if(res.success) {
                        appData.sitesList.splice(parseInt(val), 1);
                        render();
                        showMsg('已删除'); 
                    } else {
                        showMsg(res.error || '删除失败', 'error');
                    }
                } catch(e) {
                    showMsg(e.message, 'error');
                }
            }
        }
        
        // 【v9.9】添加源支持名称
        if(t.id === 'btn-add-url') {
            const name = document.getElementById('new-url-name').value;
            const url = document.getElementById('new-url-link').value;
            if(url) {
                const item = {name, url};
                appData.urls.push(item);
                document.getElementById('new-url-name').value='';
                document.getElementById('new-url-link').value='';
                render();
                apiCall('/api/urls', 'POST', {items:[item]});
                showMsg('已添加');
            }
        }
        if(t.id === 'btn-add-api') {
            const name = document.getElementById('new-api-name').value;
            const url = document.getElementById('new-api-link').value;
            if(url) {
                const item = {name, url};
                appData.apis.push(item);
                document.getElementById('new-api-name').value='';
                document.getElementById('new-api-link').value='';
                render();
                apiCall('/api/apis', 'POST', {items:[item]});
                showMsg('已添加');
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
        
        // 编辑模态框相关事件
        if(t.id === 'btn-cancel-edit' || t.classList.contains('close')) {
            document.getElementById('edit-sources-modal').style.display = 'none';
            currentEditingFile = null;
        }
        
        if(t.id === 'btn-save-edit-sources') {
            const sources = {
                urls: Array.from(document.querySelectorAll('.edit-url-cb:checked')).map(cb => parseInt(cb.value)),
                apis: Array.from(document.querySelectorAll('.edit-api-cb:checked')).map(cb => parseInt(cb.value)),
                files: Array.from(document.querySelectorAll('.edit-file-cb:checked')).map(cb => cb.value),
                includeCustom: document.getElementById('edit-custom').checked
            };
            
            const autoUpdate = document.getElementById('edit-auto-update').checked;
            
            t.disabled = true;
            t.innerText = '保存中...';
            
            try {
                const res = await apiCall('/api/ipfiles', 'PATCH', { 
                    fileName: currentEditingFile, 
                    sources: sources,
                    autoUpdate: autoUpdate
                });
                
                if(res.success) {
                    showMsg('数据源已更新，文件已重新生成');
                    document.getElementById('edit-sources-modal').style.display = 'none';
                    
                    // 更新文件元数据
                    const idx = appData.ipFiles.findIndex(f => f.name === currentEditingFile);
                    if(idx !== -1 && res.meta) {
                        appData.ipFiles[idx] = {...appData.ipFiles[idx], ...res.meta};
                        render();
                    }
                }
            } catch(e) {
                showMsg(e.message, 'error');
            } finally {
                t.disabled = false;
                t.innerText = '保存并重新生成';
            }
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
            if(!appData.uploadedFiles.includes(j.fileName)) {
                appData.uploadedFiles.push(j.fileName);
                render();
            }
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
    async function refresh() {
        try {
            const [u,a,c,up,f,s] = await Promise.all([
                fetch('/api/urls').then(x=>x.json()),
                fetch('/api/apis').then(x=>x.json()),
                fetch('/api/custom').then(x=>x.json()),
                fetch('/api/uploaded_files').then(x=>x.json()),
                fetch('/api/ipfiles').then(x=>x.json()),
                fetch('/api/sites').then(x=>x.json())
            ]);
            appData = {urls:u, apis:a, customIPs:c.ips||[], uploadedFiles:up, ipFiles:f, sitesList:s};
            render();
        } catch(e) { console.error(e); }
    }
  
    async function addSite(nameId, urlId, type) {
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
            if(res.count > 0) document.getElementById('btn-copy-extract').style.display = 'block';
        } catch(e) { showMsg(e.message, 'error'); }
        btn.disabled=false; btn.innerText='🚀 立即提取';
    }
    async function doSaveFile(btn) {
        const name = document.getElementById('file-name').value; if(!name) return alert('请输入文件名');
        btn.disabled=true; btn.innerText='⏳...';
        try {
            const res = await apiCall('/api/ipfiles', 'POST', {fileName:name, sources:getSources('file'), autoUpdate:document.getElementById('file-auto').checked});
            if(res.meta) {
                appData.ipFiles.push({...res.meta, stats: {total:0, today:0, lastAccess: null}});
                render();
            }
            showMsg('生成成功'); document.getElementById('file-name').value='';
        } catch(e) { alert(e.message); }
        btn.disabled=false; btn.innerText='💾 生成文件';
    }
    async function doTool(btn) {
        const v = getLines('tool-input'); if(!v.length) return;
        btn.disabled=true;
        try {
            const res = await apiCall('/api/tool_query', 'POST', {ipList:v});
            const outputEl = document.getElementById('tool-output');
            outputEl.style.display='block';
            outputEl.innerText = res.results.map(x=>x.formatted).join('\\n');
            document.getElementById('btn-tool-copy').style.display='inline-flex';
        } catch(e) { showMsg(e.message, 'error'); }
        btn.disabled=false;
    }
  
    render();
  })();
  </script>
  </body>
  </html>`;
  }
