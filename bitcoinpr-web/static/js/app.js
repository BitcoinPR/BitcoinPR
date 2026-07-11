/* ============================================================
   BitcoinPR Explorer — SPA Router & Core Application
   ============================================================ */

(function () {
    'use strict';

    const APP = document.getElementById('app');
    let wsConnection = null;
    let wsReconnectTimer = null;
    let wsReconnectDelay = 1000;
    let currentRoute = '';
    let dashboardRefreshInterval = null;

    /* Block transaction pagination state */
    let blockTxState = { id: null, page: 1, perPage: 25 };

    /* Last chain tip rendered in the blockchain strip — lets a fresh
       render know whether the newest cube should play the confirm
       animation (only when the tip actually advanced). */
    let chainStripTip = null;

    /* ---- Route Definitions ---- */

    const routes = [
        { pattern: /^\/$/, handler: renderDashboard },
        { pattern: /^\/block\/(.+)$/, handler: renderBlock },
        { pattern: /^\/tx\/(.+)$/, handler: renderTransaction },
        { pattern: /^\/address\/(.+)$/, handler: renderAddress },
        { pattern: /^\/mempool$/, handler: renderMempool },
        { pattern: /^\/mining$/, handler: renderMining },
        { pattern: /^\/mining\/config$/, handler: renderMiningConfig },
        { pattern: /^\/(?:info|peers)$/, handler: renderInfo },
    ];

    /* ---- Router ---- */

    function router() {
        const hash = location.hash.slice(1) || '/';
        if (hash === currentRoute) return;
        currentRoute = hash;

        clearDashboardRefresh();

        for (const route of routes) {
            const match = hash.match(route.pattern);
            if (match) {
                updateActiveNav(hash);
                route.handler(...match.slice(1));
                return;
            }
        }

        renderNotFound();
    }

    function navigate(path) {
        location.hash = '#' + path;
    }

    function updateActiveNav(hash) {
        document.querySelectorAll('.nav-link, .mobile-link').forEach(el => {
            const route = el.dataset.route;
            if (!route) return;
            const isActive = route === '/'
                ? hash === '/'
                : hash.startsWith(route);
            el.classList.toggle('active', isActive);
        });
    }

    function clearDashboardRefresh() {
        if (dashboardRefreshInterval) {
            clearInterval(dashboardRefreshInterval);
            dashboardRefreshInterval = null;
        }
    }

    /* ---- API Helpers ---- */

    async function api(path) {
        const resp = await fetch('/api/' + path);
        if (!resp.ok) {
            throw new Error(`API error: ${resp.status} ${resp.statusText}`);
        }
        return resp.json();
    }

    /* ---- Formatters ---- */

    function formatBtc(sats) {
        if (sats == null) return '—';
        const btc = Number(sats) / 1e8;
        return btc.toFixed(8) + ' BTC';
    }

    /* Compact BTC amount for tight spots like the Timechain cubes. */
    function formatBtcShort(sats) {
        if (sats == null) return '—';
        return (Number(sats) / 1e8).toFixed(3) + ' BTC';
    }

    function formatHashrate(h, unit) {
        if (h == null) return '—';
        const num = Number(h);
        if (unit) return num.toFixed(2) + ' ' + unit;
        if (num >= 1e18) return (num / 1e18).toFixed(2) + ' EH/s';
        if (num >= 1e15) return (num / 1e15).toFixed(2) + ' PH/s';
        if (num >= 1e12) return (num / 1e12).toFixed(2) + ' TH/s';
        if (num >= 1e9) return (num / 1e9).toFixed(2) + ' GH/s';
        if (num >= 1e6) return (num / 1e6).toFixed(2) + ' MH/s';
        if (num >= 1e3) return (num / 1e3).toFixed(2) + ' KH/s';
        return num.toFixed(2) + ' H/s';
    }

    function formatTime(unix) {
        if (!unix) return '—';
        const now = Date.now() / 1000;
        const diff = now - unix;
        if (diff < 60) return 'just now';
        if (diff < 3600) return Math.floor(diff / 60) + ' min ago';
        if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
        if (diff < 604800) return Math.floor(diff / 86400) + 'd ago';
        return new Date(unix * 1000).toLocaleDateString('en-US', {
            year: 'numeric', month: 'short', day: 'numeric',
            hour: '2-digit', minute: '2-digit'
        });
    }

    function formatTimeShort(unix) {
        if (!unix) return '—';
        return new Date(unix * 1000).toLocaleTimeString('en-US', {
            hour: '2-digit', minute: '2-digit', second: '2-digit'
        });
    }

    function formatNumber(n) {
        if (n == null) return '—';
        return Number(n).toLocaleString('en-US');
    }

    function formatBytes(bytes) {
        if (bytes == null) return '—';
        const b = Number(bytes);
        if (b >= 1e9) return (b / 1e9).toFixed(2) + ' GB';
        if (b >= 1e6) return (b / 1e6).toFixed(2) + ' MB';
        if (b >= 1e3) return (b / 1e3).toFixed(2) + ' KB';
        return b + ' B';
    }

    function formatUptime(secs) {
        if (!secs) return '—';
        const d = Math.floor(secs / 86400);
        const h = Math.floor((secs % 86400) / 3600);
        const m = Math.floor((secs % 3600) / 60);
        const parts = [];
        if (d > 0) parts.push(d + 'd');
        if (h > 0) parts.push(h + 'h');
        parts.push(m + 'm');
        return parts.join(' ');
    }

    function formatDifficulty(d) {
        if (d == null) return '—';
        const num = Number(d);
        if (num >= 1e12) return (num / 1e12).toFixed(2) + ' T';
        if (num >= 1e9) return (num / 1e9).toFixed(2) + ' G';
        if (num >= 1e6) return (num / 1e6).toFixed(2) + ' M';
        if (num >= 1e3) return (num / 1e3).toFixed(2) + ' K';
        return num.toFixed(2);
    }

    function truncateHash(hash, chars) {
        if (!hash) return '—';
        chars = chars || 8;
        if (hash.length <= chars * 2 + 3) return hash;
        return hash.slice(0, chars) + '…' + hash.slice(-chars);
    }

    function escapeHtml(str) {
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    /* ---- Render Helpers ---- */

    function setPage(html) {
        APP.innerHTML = '<div class="page-enter">' + html + '</div>';
        window.scrollTo(0, 0);
    }

    function showLoading(message) {
        APP.innerHTML = `
            <div class="loading-screen">
                <div class="spinner"></div>
                <p>${escapeHtml(message || 'Loading…')}</p>
            </div>`;
    }

    function showError(title, message) {
        setPage(`
            <div class="error-state">
                <div class="error-icon">!</div>
                <h2>${escapeHtml(title)}</h2>
                <p>${escapeHtml(message)}</p>
                <a class="btn" href="#/">Back to Dashboard</a>
            </div>`);
    }

    function hashLink(hash, label) {
        if (!hash) return '—';
        const display = label || truncateHash(hash);
        return `<a href="#/block/${encodeURIComponent(hash)}" class="mono">${escapeHtml(display)}</a>`;
    }

    function blockLink(heightOrHash, label) {
        if (heightOrHash == null) return '—';
        const display = label || String(heightOrHash);
        return `<a href="#/block/${encodeURIComponent(heightOrHash)}">${escapeHtml(display)}</a>`;
    }

    function txLink(txid, label) {
        if (!txid) return '—';
        const display = label || truncateHash(txid);
        return `<a href="#/tx/${encodeURIComponent(txid)}" class="mono">${escapeHtml(display)}</a>`;
    }

    function addrLink(addr, label) {
        if (!addr) return '—';
        const display = label || truncateHash(addr, 10);
        return `<a href="#/address/${encodeURIComponent(addr)}" class="mono">${escapeHtml(display)}</a>`;
    }

    function statCard(header, value, valueClass, sub) {
        return `
            <div class="card">
                <div class="card-header">${escapeHtml(header)}</div>
                <div class="card-value ${valueClass || ''}">${value}</div>
                ${sub ? `<div class="card-sub">${sub}</div>` : ''}
            </div>`;
    }

    /* ---- WebSocket ---- */

    function initWebSocket() {
        if (wsConnection && wsConnection.readyState <= 1) return;

        const proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        const url = proto + '//' + location.host + '/ws';

        try {
            wsConnection = new WebSocket(url);
        } catch (e) {
            console.warn('WebSocket connection failed:', e);
            scheduleReconnect();
            return;
        }

        wsConnection.onopen = function () {
            wsReconnectDelay = 1000;
            console.log('WebSocket connected');
        };

        wsConnection.onmessage = function (evt) {
            try {
                const msg = JSON.parse(evt.data);
                handleWsMessage(msg);
            } catch (e) {
                console.warn('Bad WS message:', e);
            }
        };

        wsConnection.onclose = function () {
            console.log('WebSocket closed, reconnecting…');
            scheduleReconnect();
        };

        wsConnection.onerror = function () {
            wsConnection.close();
        };
    }

    function scheduleReconnect() {
        if (wsReconnectTimer) return;
        wsReconnectTimer = setTimeout(function () {
            wsReconnectTimer = null;
            initWebSocket();
        }, wsReconnectDelay);
        wsReconnectDelay = Math.min(wsReconnectDelay * 2, 30000);
    }

    function handleWsMessage(msg) {
        switch (msg.type) {
            case 'NewBlock':
                showToast('New block #' + (msg.height || ''), 'info');
                if (currentRoute === '/') refreshDashboard();
                break;
            case 'NewTx':
                break;
            case 'MempoolUpdate':
                if (currentRoute === '/mempool') renderMempool();
                break;
            case 'MiningShare':
                if (typeof window.onMiningShare === 'function') {
                    window.onMiningShare(msg);
                }
                break;
            case 'MiningStats':
                if (typeof window.onMiningStats === 'function') {
                    window.onMiningStats(msg);
                }
                break;
            case 'DatumConnected':
            case 'DatumDisconnected':
            case 'DatumShareSubmitted':
            case 'DatumPayout':
                if (typeof window.onDatumEvent === 'function') {
                    window.onDatumEvent(msg);
                }
                break;
        }
    }

    /* ---- Toast ---- */

    function showToast(message, type) {
        const container = document.getElementById('toast-container');
        const toast = document.createElement('div');
        toast.className = 'toast ' + (type || 'info');
        toast.textContent = message;
        container.appendChild(toast);
        setTimeout(function () {
            toast.style.animation = 'toastOut 300ms ease forwards';
            setTimeout(function () { toast.remove(); }, 300);
        }, 4000);
    }

    /* ---- Page Renderers ---- */

    /* -- Dashboard -- */

    function dashboardStatsHtml(stats) {
        return `
            ${statCard('Block Height', formatNumber(stats.height), 'accent')}
            ${statCard('Difficulty', formatDifficulty(stats.difficulty), '')}
            ${statCard('Mempool Size', formatNumber(stats.mempool_size), '', formatBytes(stats.mempool_bytes))}
            ${statCard('Connected Peers', formatNumber(stats.peer_count), 'blue')}
            ${statCard('Network', escapeHtml(stats.network || 'mainnet'), '')}
            ${statCard('Uptime', formatUptime(stats.uptime_secs), 'green')}`;
    }

    /* In-place dashboard update on live events: swaps the stat cards,
       timechain strip, and recent lists without rebuilding the page,
       so the tip cube's confirm animation plays against a stable page. */
    async function refreshDashboard() {
        const statsGrid = document.getElementById('dashboard-stats');
        if (!statsGrid) {
            renderDashboard();
            return;
        }
        try {
            const stats = await api('stats');
            statsGrid.innerHTML = dashboardStatsHtml(stats);
            loadRecentBlocks(stats);
            loadRecentTxs();
        } catch (err) {
            // Transient refresh failure: keep showing the current data.
        }
    }

    async function renderDashboard() {
        showLoading('Loading dashboard…');
        try {
            const stats = await api('stats');

            if (document.getElementById('footer-version') && stats.node_version) {
                document.getElementById('footer-version').textContent = stats.node_version;
            }

            // Hide mining tabs if mining is not enabled
            document.querySelectorAll('[data-route="/mining"], [data-route="/mining/config"]').forEach(function (el) {
                el.style.display = stats.mining_enabled ? '' : 'none';
            });

            let html = `
                <div class="page-header">
                    <h1>Dashboard</h1>
                    <div class="subtitle">BitcoinPR Node Overview</div>
                </div>
                <div class="stats-grid" id="dashboard-stats">
                    ${dashboardStatsHtml(stats)}
                </div>
                <div class="chain-strip-wrapper" id="chain-strip">
                    <div class="chain-strip-title">The Timechain</div>
                    <div class="loading-inline" style="padding:20px;">
                        <div class="spinner"></div> Loading chain…
                    </div>
                </div>
                <div class="table-wrapper" id="recent-blocks">
                    <div class="table-title">
                        Recent Blocks
                        <span class="badge">Latest 10</span>
                    </div>
                    <div class="loading-inline" style="padding:20px;">
                        <div class="spinner"></div> Loading blocks…
                    </div>
                </div>
                <div class="table-wrapper" id="recent-txs">
                    <div class="table-title">
                        Recent Transactions
                        <span class="badge">Latest 12</span>
                    </div>
                    <div class="loading-inline" style="padding:20px;">
                        <div class="spinner"></div> Loading transactions…
                    </div>
                </div>`;

            setPage(html);
            loadRecentBlocks(stats);
            loadRecentTxs();
        } catch (err) {
            showError('Connection Error', 'Could not reach the BitcoinPR node. ' + err.message);
        }
    }

    /* Shared Timechain cube builders. */
    function chainCubeHtml(b, extraClasses) {
        return `
            <a class="chain-block confirmed${extraClasses || ''}" href="#/block/${encodeURIComponent(b.hash)}">
                <span class="chain-block-height">#${formatNumber(b.height)}</span>
                <span class="chain-block-meta">${formatNumber(b.tx_count)} tx</span>
                <span class="chain-block-meta">${formatBtcShort(b.fees)}</span>
            </a>`;
    }

    function mempoolCubeHtml(stats) {
        return `
            <div class="chain-divider" aria-hidden="true"></div>
            <a class="chain-block pending" href="#/mempool">
                <span class="chain-block-height">mempool</span>
                <span class="chain-block-meta">${formatNumber(stats.mempool_size)} tx</span>
                <span class="chain-block-meta">${formatBytes(stats.mempool_bytes)}</span>
            </a>`;
    }

    /* The Timechain strip: confirmed cubes oldest→tip, then the divider,
       with the pending mempool cube on the right. The tip cube animates
       in from the mempool side only when the tip advanced since the
       strip was last rendered. */
    function renderChainStrip(blocks, stats) {
        const container = document.getElementById('chain-strip');
        if (!container) return;

        const tipAdvanced = chainStripTip !== null
            && stats.height > chainStripTip;
        chainStripTip = stats.height;

        const shown = blocks.slice(0, 9).reverse();
        let cubes = '';
        shown.forEach(function (b, i) {
            const isTip = i === shown.length - 1;
            cubes += chainCubeHtml(b,
                (isTip ? ' tip' : '')
                + (isTip && tipAdvanced ? ' block-new' : ''));
        });

        container.innerHTML = `
            <div class="chain-strip-title">
                The Timechain
                <span class="chain-live"><span class="status-dot green pulse"></span>live</span>
            </div>
            <div class="chain-strip">
                ${cubes}
                ${mempoolCubeHtml(stats)}
            </div>`;

        // Keep the tip/mempool end in view when the strip overflows.
        const strip = container.querySelector('.chain-strip');
        strip.scrollLeft = strip.scrollWidth;
    }

    /* Block-page Timechain strip: a fixed window of 9 slots with the
       viewed height in the middle slot, highlighted as "you are here".
       Slots past the tip render as dashed "future" ghosts so the focus
       stays centered; slots before genesis are omitted. */
    async function loadBlockStrip(focusHeight) {
        const container = document.getElementById('block-strip');
        if (!container) return;

        let stats;
        try {
            stats = await api('stats');
        } catch (err) {
            container.style.display = 'none';
            return;
        }

        const tip = stats.height;
        const span = 9;
        const start = focusHeight - Math.floor(span / 2);

        const proms = [];
        for (let h = start; h < start + span; h++) {
            proms.push(
                (h < 0 || h > tip)
                    ? Promise.resolve(null)
                    : api('block/' + h).catch(function () { return null; })
            );
        }
        const blocks = await Promise.all(proms);

        let cubes = '';
        blocks.forEach(function (b, i) {
            const h = start + i;
            if (h < 0) return;
            if (h > tip) {
                cubes += '<div class="chain-block ghost" aria-hidden="true"></div>';
            } else if (b) {
                cubes += chainCubeHtml(b, h === focusHeight ? ' focus' : '');
            }
        });

        if (!cubes) {
            container.style.display = 'none';
            return;
        }

        container.innerHTML = `
            <div class="chain-strip-title">
                The Timechain
                <span class="chain-strip-note">viewing #${formatNumber(focusHeight)}</span>
            </div>
            <div class="chain-strip strip-centered">
                ${cubes}
            </div>`;

        // Center the viewed block when the strip overflows.
        const strip = container.querySelector('.chain-strip');
        const focusEl = container.querySelector('.chain-block.focus');
        if (strip && focusEl) {
            strip.scrollLeft = focusEl.offsetLeft
                - (strip.clientWidth - focusEl.offsetWidth) / 2;
        }
    }

    async function loadRecentBlocks(stats) {
        const currentHeight = stats.height;
        const container = document.getElementById('recent-blocks');
        if (!container) return;

        const blockPromises = [];
        const startHeight = currentHeight;
        const count = Math.min(10, currentHeight + 1);
        for (let i = 0; i < count; i++) {
            blockPromises.push(
                api('block/' + (startHeight - i)).catch(function () { return null; })
            );
        }

        const blocks = (await Promise.all(blockPromises)).filter(Boolean);

        renderChainStrip(blocks, stats);

        if (blocks.length === 0) {
            container.innerHTML = `
                <div class="table-title">Recent Blocks</div>
                <div class="empty-state">No blocks found</div>`;
            return;
        }

        let rows = '';
        for (const b of blocks) {
            rows += `
                <div class="block-item">
                    <a href="#/block/${encodeURIComponent(b.height)}" class="block-height">#${formatNumber(b.height)}</a>
                    <a href="#/block/${encodeURIComponent(b.hash)}" class="block-hash">${escapeHtml(b.hash)}</a>
                    <span class="block-time">${formatTime(b.time)}</span>
                </div>`;
        }

        container.innerHTML = `
            <div class="table-title">
                Recent Blocks
                <span class="badge">Latest ${blocks.length}</span>
            </div>
            ${rows}`;
    }

    async function loadRecentTxs() {
        const container = document.getElementById('recent-txs');
        if (!container) return;

        let data;
        try {
            data = await api('recent-txs?limit=12');
        } catch (err) {
            container.innerHTML = `
                <div class="table-title">Recent Transactions</div>
                <div class="empty-state">Recent transactions unavailable</div>`;
            return;
        }

        const txs = (data && data.transactions) || [];

        if (txs.length === 0) {
            container.innerHTML = `
                <div class="table-title">Recent Transactions</div>
                <div class="empty-state">No transactions found</div>`;
            return;
        }

        let rows = '';
        for (const tx of txs) {
            const feeRate = (tx.fee != null && tx.vsize)
                ? (tx.fee / tx.vsize).toFixed(1) + ' sat/vB'
                : '—';
            const coinbaseBadge = tx.is_coinbase
                ? '<span class="recent-tx-badge coinbase">coinbase</span>'
                : '';
            rows += `
                <div class="recent-tx-item">
                    <div class="recent-tx-id">
                        ${txLink(tx.txid, truncateHash(tx.txid, 8))}
                        ${coinbaseBadge}
                    </div>
                    <div class="recent-tx-value mono">${formatBtc(tx.value)}</div>
                    <div class="recent-tx-feerate mono">${escapeHtml(feeRate)}</div>
                    <div class="recent-tx-block">${tx.block_height != null ? blockLink(tx.block_height, '#' + formatNumber(tx.block_height)) : '<span class="status-badge syncing">Unconfirmed</span>'}</div>
                    <div class="recent-tx-time">${formatTime(tx.time)}</div>
                </div>`;
        }

        container.innerHTML = `
            <div class="table-title">
                Recent Transactions
                <span class="badge">Latest ${txs.length}</span>
            </div>
            ${rows}`;
    }

    /* -- Block Detail -- */

    async function renderBlock(id) {
        showLoading('Loading block ' + id + '…');
        try {
            const block = await api('block/' + encodeURIComponent(id));

            const fields = [
                ['Hash', `<span class="mono">${escapeHtml(block.hash)}</span>`],
                ['Height', blockLink(block.height, formatNumber(block.height))],
                ['Confirmations', formatNumber(block.confirmations)],
                ['Version', block.version != null ? '0x' + Number(block.version).toString(16) : '—'],
                ['Timestamp', block.time ? new Date(block.time * 1000).toLocaleString() + ' (' + formatTime(block.time) + ')' : '—'],
                ['Difficulty', formatDifficulty(block.difficulty)],
                ['Nonce', formatNumber(block.nonce)],
                ['Bits', escapeHtml(block.bits || '—')],
                ['Merkle Root', `<span class="mono" style="font-size:0.78rem;">${escapeHtml(block.merkleroot || '—')}</span>`],
                ['Previous Block', block.previousblockhash ? hashLink(block.previousblockhash) : 'Genesis'],
            ];

            let rows = '';
            for (const [label, value] of fields) {
                rows += `
                    <div class="detail-row">
                        <div class="detail-label">${escapeHtml(label)}</div>
                        <div class="detail-value">${value}</div>
                    </div>`;
            }

            const navLinks = [];
            if (block.previousblockhash) {
                navLinks.push(`<a class="pager-link" href="#/block/${encodeURIComponent(block.previousblockhash)}">← Prev Block</a>`);
            }
            if (block.height != null) {
                navLinks.push(`<a class="pager-link" href="#/block/${block.height + 1}">Next Block →</a>`);
            }

            setPage(`
                <div class="page-header">
                    <h1>Block #${formatNumber(block.height)}</h1>
                    <div class="subtitle">${escapeHtml(block.hash)}</div>
                </div>
                <div class="chain-strip-wrapper" id="block-strip">
                    <div class="chain-strip-title">The Timechain</div>
                    <div class="loading-inline" style="padding:20px;">
                        <div class="spinner"></div> Loading chain…
                    </div>
                </div>
                <div class="detail-card">
                    <div class="detail-title">Block Details</div>
                    ${rows}
                </div>
                <div class="table-wrapper">
                    <div class="table-title">
                        Transactions
                        <span class="badge" id="block-tx-count">${block.tx_count != null ? formatNumber(block.tx_count) : '—'}</span>
                    </div>
                    <div id="block-txs-container">
                        <div class="loading-inline" style="padding:20px;">
                            <div class="spinner"></div> Loading transactions…
                        </div>
                    </div>
                </div>
                ${navLinks.length ? '<div style="display:flex;gap:16px;flex-wrap:wrap;">' + navLinks.join('') + '</div>' : ''}`);

            // Initialize block tx pagination state and render first page.
            blockTxState = { id: id, page: 1, perPage: 25 };
            loadBlockTxs();
            loadBlockStrip(block.height);
        } catch (err) {
            showError('Block Not Found', 'Could not load block "' + id + '". ' + err.message);
        }
    }

    async function loadBlockTxs() {
        const container = document.getElementById('block-txs-container');
        if (!container) return;

        const id = blockTxState.id;
        const page = blockTxState.page;
        const perPage = blockTxState.perPage;

        let data;
        try {
            data = await api('block/' + encodeURIComponent(id) + '?page=' + page + '&per_page=' + perPage);
        } catch (err) {
            container.innerHTML = '<div class="empty-state">Transaction list unavailable for this block.</div>';
            return;
        }

        // Guard against header-only data (older / un-loadable blocks).
        if (!data || !data.txs || !Array.isArray(data.txs)) {
            container.innerHTML = '<div class="empty-state">Transaction list unavailable for this block.</div>';
            return;
        }

        if (data.txs.length === 0) {
            container.innerHTML = '<div class="empty-state">No transactions on this page.</div>';
            return;
        }

        const txCount = data.tx_count != null ? data.tx_count : data.txs.length;
        const effPerPage = data.per_page != null ? data.per_page : perPage;
        if (data.page != null) blockTxState.page = data.page;
        if (data.per_page != null) blockTxState.perPage = data.per_page;

        const countEl = document.getElementById('block-tx-count');
        if (countEl) countEl.textContent = formatNumber(txCount);

        let rows = '';
        for (const tx of data.txs) {
            rows += buildBlockTxRow(tx);
        }

        let pager = '';
        if (txCount > effPerPage) {
            const curPage = blockTxState.page;
            const totalPages = Math.max(1, Math.ceil(txCount / effPerPage));
            pager = `
                <div class="pagination">
                    <button id="block-tx-prev" ${curPage <= 1 ? 'disabled' : ''}>← Prev</button>
                    <span class="page-info">Page ${formatNumber(curPage)} of ${formatNumber(totalPages)}</span>
                    <button id="block-tx-next" ${curPage >= totalPages ? 'disabled' : ''}>Next →</button>
                </div>`;
        }

        container.innerHTML = '<div class="block-tx-list">' + rows + '</div>' + pager;

        const prevBtn = document.getElementById('block-tx-prev');
        const nextBtn = document.getElementById('block-tx-next');
        if (prevBtn) {
            prevBtn.addEventListener('click', function () {
                if (blockTxState.page > 1) {
                    blockTxState.page -= 1;
                    loadBlockTxs();
                }
            });
        }
        if (nextBtn) {
            nextBtn.addEventListener('click', function () {
                blockTxState.page += 1;
                loadBlockTxs();
            });
        }
    }

    function buildBlockTxRow(tx) {
        const inputs = tx.inputs || [];
        const outputs = tx.outputs || [];
        const inCount = tx.inputs_count != null ? tx.inputs_count : inputs.length;
        const outCount = tx.outputs_count != null ? tx.outputs_count : outputs.length;

        // Source summary
        let sourceHtml;
        const firstIn = inputs[0];
        if (tx.is_coinbase || (firstIn && firstIn.coinbase)) {
            sourceHtml = '<span class="block-tx-coinbase">Coinbase</span>';
        } else if (firstIn) {
            if (firstIn.address) {
                sourceHtml = addrLink(firstIn.address, truncateHash(firstIn.address, 8));
            } else if (firstIn.txid) {
                sourceHtml = '<span class="mono">' + escapeHtml(truncateHash(firstIn.txid, 6) + ':' + (firstIn.vout != null ? firstIn.vout : '?')) + '</span>';
            } else {
                sourceHtml = '<span class="mono">—</span>';
            }
        } else {
            sourceHtml = '<span class="mono">—</span>';
        }
        const moreIn = inCount > 1 ? '<span class="block-tx-chip">+' + (inCount - 1) + '</span>' : '';

        // Dest summary — show first 1-2 outputs
        const destParts = [];
        const shown = Math.min(2, outputs.length);
        for (let i = 0; i < shown; i++) {
            const out = outputs[i];
            const spk = out.script_pubkey || '';
            if (spk.indexOf('6a') === 0) {
                destParts.push('<span class="block-tx-script">OP_RETURN</span>');
            } else if (out.address) {
                destParts.push(addrLink(out.address, truncateHash(out.address, 8)));
            } else {
                destParts.push('<span class="block-tx-script">Script</span>');
            }
        }
        let destHtml = destParts.length ? destParts.join('<span class="block-tx-sep">,</span> ') : '<span class="mono">—</span>';
        const moreOut = outCount > shown ? '<span class="block-tx-chip">+' + (outCount - shown) + '</span>' : '';

        const feeRate = (tx.fee != null && tx.vsize)
            ? ' · ' + (tx.fee / tx.vsize).toFixed(1) + ' sat/vB'
            : '';

        const txHref = '#/tx/' + encodeURIComponent(tx.txid);

        return `
            <div class="block-tx-row" onclick="location.hash='${txHref}'">
                <a class="block-tx-txid mono" href="${txHref}" onclick="event.stopPropagation();">${escapeHtml(truncateHash(tx.txid, 8))}</a>
                <div class="block-tx-flow" onclick="event.stopPropagation();">
                    <span class="block-tx-src">${sourceHtml}${moreIn}</span>
                    <span class="block-tx-arrow">→</span>
                    <span class="block-tx-dest">${destHtml}${moreOut}</span>
                </div>
                <div class="block-tx-value mono">${formatBtc(tx.value)}<span class="block-tx-feerate">${escapeHtml(feeRate)}</span></div>
            </div>`;
    }

    /* -- Transaction Detail -- */

    /* Sankey band color palette (PHOSPHOR tokens + bright variants) */
    var SANKEY_COLORS = [
        '#f7931a', '#5ad7e6', '#3fd97a', '#c9a0ff', '#ffd23f',
        '#ff5c5c', '#ffb347', '#8ce8f5', '#7de8a8', '#ffe27a',
    ];

    var MAX_FLOW_DISPLAY = 20;

    /* ============================================================
       Interactive multi-stage transaction flow controller.
       Lets the user expand a transaction backward (into the tx that
       funded an input) or forward (into the tx that spends an output)
       and walk the chain in either direction.
       ============================================================ */

    function TxFlowController(container) {
        this.container = container;
        // Ordered list of stages, ancestors left of focus, descendants right.
        this.stages = [];
        // txid -> stage, for de-dup / loop prevention.
        this.byTxid = {};
        // Connections: { fromTxid, fromOutput, toTxid, toInput }.
        this.connections = [];
        this._relayoutBound = this.relayout.bind(this);
    }

    /* A "stage" wraps one transaction plus its (possibly missing) outspends. */
    function makeStage(tx, outspends) {
        return {
            txid: tx.txid,
            tx: tx,
            outspends: Array.isArray(outspends) ? outspends : null,
        };
    }

    TxFlowController.prototype.hasTxid = function (txid) {
        return !!(txid && this.byTxid[txid]);
    };

    /* Insert the focus transaction and draw. */
    TxFlowController.prototype.setFocus = function (tx, outspends) {
        var stage = makeStage(tx, outspends);
        stage.isFocus = true;
        this.stages = [stage];
        this.byTxid = {};
        this.byTxid[stage.txid] = stage;
        this.connections = [];
        this.render();
    };

    /* Add a stage to the left (an ancestor tx). */
    TxFlowController.prototype.addLeft = function (tx, outspends, conn) {
        if (this.hasTxid(tx.txid)) return false;
        var stage = makeStage(tx, outspends);
        this.stages.unshift(stage);
        this.byTxid[stage.txid] = stage;
        if (conn) this.connections.push(conn);
        this.render();
        return true;
    };

    /* Add a stage to the right (a descendant / spending tx). */
    TxFlowController.prototype.addRight = function (tx, outspends, conn) {
        if (this.hasTxid(tx.txid)) return false;
        var stage = makeStage(tx, outspends);
        this.stages.push(stage);
        this.byTxid[stage.txid] = stage;
        if (conn) this.connections.push(conn);
        this.render();
        return true;
    };

    /* Reset to just the focus transaction. */
    TxFlowController.prototype.reset = function () {
        var focus = null;
        for (var i = 0; i < this.stages.length; i++) {
            if (this.stages[i].isFocus) { focus = this.stages[i]; break; }
        }
        if (!focus) return;
        this.stages = [focus];
        this.byTxid = {};
        this.byTxid[focus.txid] = focus;
        this.connections = [];
        this.render();
    };

    /* Flash + scroll to an already-loaded stage. */
    TxFlowController.prototype.flashTo = function (txid) {
        var card = this.container.querySelector('.flow-stage[data-txid="' + cssEscapeAttr(txid) + '"]');
        if (!card) return;
        var scroller = this.container.querySelector('.flow-scroll');
        if (scroller) {
            scroller.scrollLeft = card.offsetLeft - 40;
        }
        card.classList.remove('flash');
        // Force reflow so the animation restarts.
        void card.offsetWidth;
        card.classList.add('flash');
    };

    TxFlowController.prototype.render = function () {
        var self = this;
        var stagesHtml = '';
        for (var i = 0; i < this.stages.length; i++) {
            stagesHtml += buildStageHtml(this.stages[i], i);
        }

        this.container.innerHTML =
            '<div class="flow-controls">' +
                '<div class="flow-controls-title">Transaction Flow ' +
                    '<span class="badge">' + this.stages.length + ' tx' + (this.stages.length > 1 ? 's' : '') + '</span>' +
                '</div>' +
                '<button type="button" class="flow-reset-btn"' + (this.stages.length > 1 ? '' : ' disabled') + '>Reset view</button>' +
            '</div>' +
            '<div class="flow-scroll">' +
                '<svg class="flow-connectors" xmlns="http://www.w3.org/2000/svg"></svg>' +
                '<div class="flow-stages' + (this.stages.length > 1 ? '' : ' single') + '">' + stagesHtml + '</div>' +
            '</div>';

        var resetBtn = this.container.querySelector('.flow-reset-btn');
        if (resetBtn) {
            resetBtn.addEventListener('click', function () { self.reset(); });
        }

        this.bindStageEvents();
        // Layout connectors after the DOM has painted.
        setTimeout(this._relayoutBound, 0);

        // Recompute connectors on resize / horizontal scroll.
        window.removeEventListener('resize', this._relayoutBound);
        window.addEventListener('resize', this._relayoutBound);
        var scroller = this.container.querySelector('.flow-scroll');
        if (scroller) {
            scroller.addEventListener('scroll', this._relayoutBound);
        }
    };

    TxFlowController.prototype.bindStageEvents = function () {
        var self = this;

        // Per-stage hover highlighting (bands within the same stage).
        var stageCards = this.container.querySelectorAll('.flow-stage');
        for (var s = 0; s < stageCards.length; s++) {
            (function (card) {
                var nodes = card.querySelectorAll('.tx-flow-node');
                var bands = card.querySelectorAll('.sankey-band');
                for (var n = 0; n < nodes.length; n++) {
                    (function (node) {
                        node.addEventListener('mouseenter', function () {
                            var side = node.dataset.side;
                            var idx = node.dataset.index;
                            if (side == null || idx == null) return;
                            for (var b = 0; b < bands.length; b++) {
                                if (bands[b].dataset[side] === idx) {
                                    bands[b].classList.add('highlighted');
                                }
                            }
                            card.classList.add('hovering');
                        });
                        node.addEventListener('mouseleave', function () {
                            for (var b = 0; b < bands.length; b++) {
                                bands[b].classList.remove('highlighted');
                            }
                            card.classList.remove('hovering');
                        });
                    })(nodes[n]);
                }
            })(stageCards[s]);
        }

        // Expand buttons.
        var expandBtns = this.container.querySelectorAll('.flow-expand-btn');
        for (var e = 0; e < expandBtns.length; e++) {
            expandBtns[e].addEventListener('click', function (ev) {
                ev.stopPropagation();
                ev.preventDefault();
                self.handleExpand(this);
            });
        }
    };

    TxFlowController.prototype.handleExpand = function (btn) {
        var self = this;
        var dir = btn.dataset.dir;
        var fromTxid = btn.dataset.txid;
        var targetTxid = btn.dataset.target;

        if (!targetTxid) return;

        // Already loaded? Just flash to it.
        if (this.hasTxid(targetTxid)) {
            this.flashTo(targetTxid);
            return;
        }

        if (btn.classList.contains('loading')) return;
        btn.classList.add('loading');
        btn.disabled = true;

        if (dir === 'back') {
            var vout = parseInt(btn.dataset.vout, 10);
            api('tx/' + encodeURIComponent(targetTxid))
                .then(function (prevTx) {
                    if (!prevTx || prevTx.error || !prevTx.txid) {
                        throw new Error('previous transaction unavailable');
                    }
                    // Outspends optional; expansion still works without them.
                    return fetchOutspends(prevTx.txid).then(function (os) {
                        var added = self.addLeft(prevTx, os, {
                            fromTxid: prevTx.txid,
                            fromOutput: vout,
                            toTxid: fromTxid,
                            toInput: parseInt(btn.dataset.vin, 10),
                        });
                        if (added) self.flashTo(prevTx.txid);
                    });
                })
                .catch(function (err) {
                    btn.classList.remove('loading');
                    btn.disabled = false;
                    showToast('Could not expand input: ' + err.message, 'error');
                });
        } else if (dir === 'fwd') {
            var vin = parseInt(btn.dataset.vin, 10);
            var fromOutput = parseInt(btn.dataset.vout, 10);
            api('tx/' + encodeURIComponent(targetTxid))
                .then(function (nextTx) {
                    if (!nextTx || nextTx.error || !nextTx.txid) {
                        throw new Error('spending transaction unavailable');
                    }
                    return fetchOutspends(nextTx.txid).then(function (os) {
                        var added = self.addRight(nextTx, os, {
                            fromTxid: fromTxid,
                            fromOutput: fromOutput,
                            toTxid: nextTx.txid,
                            toInput: vin,
                        });
                        if (added) self.flashTo(nextTx.txid);
                    });
                })
                .catch(function (err) {
                    btn.classList.remove('loading');
                    btn.disabled = false;
                    showToast('Could not expand output: ' + err.message, 'error');
                });
        }
    };

    /* Draw SVG connectors between connected output / input boxes. */
    TxFlowController.prototype.relayout = function () {
        var svg = this.container.querySelector('.flow-connectors');
        var scroller = this.container.querySelector('.flow-scroll');
        var stagesEl = this.container.querySelector('.flow-stages');
        if (!svg || !scroller || !stagesEl) return;

        var scrollRect = scroller.getBoundingClientRect();
        var w = stagesEl.scrollWidth;
        var h = stagesEl.scrollHeight;
        svg.setAttribute('width', w);
        svg.setAttribute('height', h);
        svg.setAttribute('viewBox', '0 0 ' + w + ' ' + h);
        svg.style.width = w + 'px';
        svg.style.height = h + 'px';

        var paths = '';
        for (var c = 0; c < this.connections.length; c++) {
            var conn = this.connections[c];
            var fromEl = this.container.querySelector(
                '.flow-stage[data-txid="' + cssEscapeAttr(conn.fromTxid) + '"] .tx-flow-node.output[data-index="' + conn.fromOutput + '"]');
            var toEl = this.container.querySelector(
                '.flow-stage[data-txid="' + cssEscapeAttr(conn.toTxid) + '"] .tx-flow-node.input[data-index="' + conn.toInput + '"]');
            if (!fromEl || !toEl) continue;

            var fr = fromEl.getBoundingClientRect();
            var tr = toEl.getBoundingClientRect();
            // Convert to coordinates inside the (scrolled) stages element.
            var x1 = fr.right - scrollRect.left + scroller.scrollLeft;
            var y1 = fr.top + fr.height / 2 - scrollRect.top + scroller.scrollTop;
            var x2 = tr.left - scrollRect.left + scroller.scrollLeft;
            var y2 = tr.top + tr.height / 2 - scrollRect.top + scroller.scrollTop;
            var midX = (x1 + x2) / 2;
            paths += '<path class="flow-connector-path" d="M' + x1.toFixed(1) + ',' + y1.toFixed(1) +
                ' C' + midX.toFixed(1) + ',' + y1.toFixed(1) +
                ' ' + midX.toFixed(1) + ',' + y2.toFixed(1) +
                ' ' + x2.toFixed(1) + ',' + y2.toFixed(1) + '"/>';
            paths += '<circle class="flow-connector-dot" cx="' + x1.toFixed(1) + '" cy="' + y1.toFixed(1) + '" r="3"/>';
            paths += '<circle class="flow-connector-dot" cx="' + x2.toFixed(1) + '" cy="' + y2.toFixed(1) + '" r="3"/>';
        }
        svg.innerHTML = paths;
    };

    /* Fetch outspends defensively; resolves to an array or null. */
    function fetchOutspends(txid) {
        return api('tx/' + encodeURIComponent(txid) + '/outspends')
            .then(function (os) {
                return Array.isArray(os) ? os : null;
            })
            .catch(function () { return null; });
    }

    /* Escape a value for use inside a CSS attribute selector "..." */
    function cssEscapeAttr(v) {
        return String(v == null ? '' : v).replace(/["\\]/g, '\\$&');
    }

    /* Classify a single outspends entry. Returns one of:
       'utxo', 'unspendable', 'spent-confirmed', 'spent-pending', 'unknown'. */
    function classifyOutspend(entry, scriptPubkey) {
        if ((scriptPubkey || '').indexOf('6a') === 0) return 'unspendable';
        if (!entry || typeof entry !== 'object') return 'unknown';
        if (entry.unspendable) return 'unspendable';
        if (entry.spent === false) return 'utxo';
        if (entry.spent === true) {
            if (entry.confirmed === false && entry.txid) return 'spent-pending';
            return 'spent-confirmed';
        }
        return 'unknown';
    }

    /**
     * Build the HTML for a single transaction stage (one inputs|bands|outputs
     * group) using the existing proportional Sankey visual language, plus
     * expand "+" buttons on inputs (backward) and spendable outputs (forward),
     * and spend badges on outputs.
     *
     * @param {object} stage  { tx, outspends, isFocus }
     * @param {number} stageIndex
     */
    function buildStageHtml(stage, stageIndex) {
        var tx = stage.tx;
        var inputs = tx.inputs || [];
        var outputs = tx.outputs || [];
        var outspends = stage.outspends;
        var fee = tx.fee;
        var feeRate = tx.fee_rate;
        var bodyHtml = renderSankeyBody(inputs, outputs, fee, feeRate, tx.txid, outspends);

        var titleLink = '<a href="#/tx/' + encodeURIComponent(tx.txid) + '" class="mono" onclick="event.stopPropagation();">' +
            escapeHtml(truncateHash(tx.txid, 8)) + '</a>';
        var focusBadge = stage.isFocus ? '<span class="flow-stage-focus">focus</span>' : '';
        var statusBadge = tx.confirmed === false
            ? '<span class="flow-stage-status pending">pending</span>'
            : '';

        return '<div class="flow-stage' + (stage.isFocus ? ' is-focus' : '') + '" data-txid="' + escapeHtml(tx.txid) + '">' +
            '<div class="flow-stage-head">' +
                '<span class="flow-stage-title">' + titleLink + focusBadge + statusBadge + '</span>' +
            '</div>' +
            bodyHtml +
            '</div>';
    }

    /**
     * Renders the inputs | bands | outputs body for a single tx, with
     * expand buttons and spend badges. Reuses the proportional-height
     * Sankey layout from the original single-tx diagram.
     */
    function renderSankeyBody(inputs, outputs, fee, feeRate, txid, outspends) {
        var MAX_DISPLAY = MAX_FLOW_DISPLAY;
        var isCoinbase = inputs.length > 0 && inputs[0].coinbase;
        var dispIn = inputs.slice(0, MAX_DISPLAY);
        var dispOut = outputs.slice(0, MAX_DISPLAY);
        var moreIn = inputs.length > MAX_DISPLAY ? inputs.length - MAX_DISPLAY : 0;
        var moreOut = outputs.length > MAX_DISPLAY ? outputs.length - MAX_DISPLAY : 0;

        var totalIn = 0, totalOut = 0;
        for (var i = 0; i < dispIn.length; i++) totalIn += (dispIn[i].value || 0);
        for (var i = 0; i < dispOut.length; i++) totalOut += (dispOut[i].value || 0);
        var totalFlow = Math.max(totalIn, totalOut, 1);

        // Tall enough for addr + value lines plus a spend badge; node
        // heights are exact (Sankey band anchors depend on them), so the
        // minimum must fit the content or it clips.
        var MIN_H = 60;
        var GAP = 4;
        var hasValues = totalIn > 0 && totalOut > 0;

        function calcHeights(nodes, total) {
            var baseH = Math.max(300, nodes.length * (MIN_H + GAP));
            return nodes.map(function (n) {
                if (hasValues && n.value != null && n.value > 0 && total > 0) {
                    return Math.max(MIN_H, (n.value / total) * baseH);
                }
                return MIN_H;
            });
        }

        var inH = calcHeights(dispIn, totalIn);
        var outH = calcHeights(dispOut, totalOut);

        var inTotal = 0, outTotal = 0;
        for (var i = 0; i < inH.length; i++) inTotal += inH[i] + (i > 0 ? GAP : 0);
        for (var i = 0; i < outH.length; i++) outTotal += outH[i] + (i > 0 ? GAP : 0);
        var svgH = Math.max(inTotal, outTotal);

        var inOff = (svgH - inTotal) / 2;
        var outOff = (svgH - outTotal) / 2;

        var inY = [], y = inOff;
        for (var i = 0; i < dispIn.length; i++) {
            inY.push(y);
            y += inH[i] + GAP;
        }
        var outY = [], y2 = outOff;
        for (var i = 0; i < dispOut.length; i++) {
            outY.push(y2);
            y2 += outH[i] + GAP;
        }

        var svgPaths = '';
        if (hasValues && !isCoinbase) {
            var inUsed = new Array(dispIn.length).fill(0);
            var outUsed = new Array(dispOut.length).fill(0);
            for (var i = 0; i < dispIn.length; i++) {
                var iv = dispIn[i].value || 0;
                if (iv <= 0) continue;
                for (var j = 0; j < dispOut.length; j++) {
                    var ov = dispOut[j].value || 0;
                    if (ov <= 0) continue;
                    var flow = iv * ov / totalFlow;
                    var bInH = (flow / iv) * inH[i];
                    var bOutH = (flow / ov) * outH[j];

                    var y1t = inY[i] + inUsed[i];
                    var y1b = y1t + bInH;
                    var y2t = outY[j] + outUsed[j];
                    var y2b = y2t + bOutH;
                    inUsed[i] += bInH;
                    outUsed[j] += bOutH;

                    var col = SANKEY_COLORS[i % SANKEY_COLORS.length];
                    svgPaths += '<path class="sankey-band" data-input="' + i + '" data-output="' + j + '" d="M0,' + y1t.toFixed(1) + ' C50,' + y1t.toFixed(1) + ' 50,' + y2t.toFixed(1) + ' 100,' + y2t.toFixed(1) + ' L100,' + y2b.toFixed(1) + ' C50,' + y2b.toFixed(1) + ' 50,' + y1b.toFixed(1) + ' 0,' + y1b.toFixed(1) + ' Z" fill="' + col + '" opacity="0.35"/>';
                }
            }
        } else {
            for (var i = 0; i < dispIn.length; i++) {
                for (var j = 0; j < dispOut.length; j++) {
                    var bInH = inH[i] / dispOut.length;
                    var bOutH = outH[j] / dispIn.length;
                    var y1t = inY[i] + bInH * j;
                    var y1b = y1t + bInH;
                    var y2t = outY[j] + bOutH * i;
                    var y2b = y2t + bOutH;
                    var col = SANKEY_COLORS[i % SANKEY_COLORS.length];
                    svgPaths += '<path class="sankey-band" data-input="' + i + '" data-output="' + j + '" d="M0,' + y1t.toFixed(1) + ' C50,' + y1t.toFixed(1) + ' 50,' + y2t.toFixed(1) + ' 100,' + y2t.toFixed(1) + ' L100,' + y2b.toFixed(1) + ' C50,' + y2b.toFixed(1) + ' 50,' + y1b.toFixed(1) + ' 0,' + y1b.toFixed(1) + ' Z" fill="' + col + '" opacity="0.35"/>';
                }
            }
        }

        // Input nodes (with backward expand "+").
        var inputNodes = '';
        for (var i = 0; i < dispIn.length; i++) {
            var inp = dispIn[i];
            var nodeClass = 'tx-flow-node input';
            var addrHtml, valHtml = '', clickNav = '';
            var expandBtn = '';
            if (inp.coinbase) {
                nodeClass = 'tx-flow-node coinbase';
                addrHtml = '<span style="color:var(--green);font-weight:600;">Coinbase</span>';
                valHtml = totalOut > 0 ? formatBtc(totalOut) : '';
            } else {
                var addr = inp.address || '';
                if (addr) {
                    addrHtml = '<a href="#/address/' + encodeURIComponent(addr) + '">' + escapeHtml(truncateHash(addr, 6)) + '</a>';
                } else {
                    addrHtml = escapeHtml(truncateHash(inp.txid, 6)) + ':' + inp.vout;
                }
                if (inp.txid) {
                    clickNav = '#/tx/' + encodeURIComponent(inp.txid);
                    expandBtn = '<button type="button" class="flow-expand-btn back" title="Expand previous transaction"' +
                        ' data-dir="back" data-txid="' + escapeHtml(txid) + '"' +
                        ' data-target="' + escapeHtml(inp.txid) + '"' +
                        ' data-vout="' + (inp.vout != null ? inp.vout : 0) + '"' +
                        ' data-vin="' + i + '">+</button>';
                }
                valHtml = inp.value != null ? formatBtc(inp.value) : '';
            }
            inputNodes += '<div class="' + nodeClass + '" data-side="input" data-index="' + i + '" style="height:' + inH[i].toFixed(0) + 'px;"' + (clickNav ? ' onclick="location.hash=\'' + clickNav + '\'"' : '') + '>' +
                expandBtn +
                '<div class="tx-flow-node-addr">' + addrHtml + '</div>' +
                (valHtml ? '<div class="tx-flow-node-value">' + valHtml + '</div>' : '') +
                '</div>';
        }
        if (moreIn > 0) {
            inputNodes += '<div class="tx-flow-more">+ ' + moreIn + ' more input' + (moreIn > 1 ? 's' : '') + '</div>';
        }

        // Output nodes (with spend badges + forward expand "+").
        var outputNodes = '';
        for (var i = 0; i < dispOut.length; i++) {
            var out = dispOut[i];
            var nodeClass = 'tx-flow-node output';
            var addr = out.address || '';
            var spk = out.script_pubkey || '';
            var addrHtml, clickNav = '';
            if (spk.indexOf('6a') === 0) {
                nodeClass = 'tx-flow-node output op-return';
                addrHtml = 'OP_RETURN';
            } else if (addr) {
                addrHtml = '<a href="#/address/' + encodeURIComponent(addr) + '">' + escapeHtml(truncateHash(addr, 6)) + '</a>';
                clickNav = '#/address/' + encodeURIComponent(addr);
            } else {
                addrHtml = 'Script';
            }
            var valHtml = out.value != null ? formatBtc(out.value) : '';

            // Spend badge + optional forward expand button.
            var vout = out.n != null ? out.n : i;
            var entry = outspends ? outspends[i] : null;
            var kind = classifyOutspend(entry, spk);
            var badge = '';
            var expandBtn = '';
            if (kind === 'utxo') {
                badge = '<span class="flow-spend-badge utxo">UTXO</span>';
            } else if (kind === 'spent-confirmed') {
                badge = '<span class="flow-spend-badge spent">spent</span>';
                // A confirmed spend with a known spender txid can be expanded
                // forward into the spending transaction.
                if (entry && entry.txid) {
                    expandBtn = '<button type="button" class="flow-expand-btn fwd" title="Expand spending transaction"' +
                        ' data-dir="fwd" data-txid="' + escapeHtml(txid) + '"' +
                        ' data-target="' + escapeHtml(entry.txid) + '"' +
                        ' data-vout="' + vout + '"' +
                        ' data-vin="' + (entry.vin != null ? entry.vin : 0) + '">+</button>';
                }
            } else if (kind === 'spent-pending') {
                badge = '<span class="flow-spend-badge pending">spent (pending)</span>';
                expandBtn = '<button type="button" class="flow-expand-btn fwd" title="Expand spending transaction"' +
                    ' data-dir="fwd" data-txid="' + escapeHtml(txid) + '"' +
                    ' data-target="' + escapeHtml(entry.txid) + '"' +
                    ' data-vout="' + vout + '"' +
                    ' data-vin="' + (entry.vin != null ? entry.vin : 0) + '">+</button>';
            }
            // unspendable / unknown → no badge, no button.

            outputNodes += '<div class="' + nodeClass + '" data-side="output" data-index="' + i + '" style="height:' + outH[i].toFixed(0) + 'px;"' + (clickNav ? ' onclick="location.hash=\'' + clickNav + '\'"' : '') + '>' +
                expandBtn +
                '<div class="tx-flow-node-addr">' + addrHtml + '</div>' +
                (valHtml ? '<div class="tx-flow-node-value">' + valHtml + '</div>' : '') +
                (badge ? '<div class="tx-flow-node-badges">' + badge + '</div>' : '') +
                '</div>';
        }
        if (moreOut > 0) {
            outputNodes += '<div class="tx-flow-more">+ ' + moreOut + ' more output' + (moreOut > 1 ? 's' : '') + '</div>';
        }

        var feeHtml = '';
        if (fee != null && fee > 0) {
            feeHtml = '<div class="tx-flow-fee">' +
                '<span class="tx-flow-fee-label">Fee</span>' +
                '<span class="tx-flow-fee-value">' + formatBtc(fee) + '</span>' +
                (feeRate != null ? '<span class="mono" style="font-size:0.78rem;">(' + feeRate.toFixed(2) + ' sat/vB)</span>' : '') +
                '</div>';
        }

        var inCount = inputs.length;
        var outCount = outputs.length;

        return '<div class="tx-flow-meta">' + inCount + ' in / ' + outCount + ' out</div>' +
            '<div class="tx-flow">' +
                '<div class="tx-flow-col tx-flow-inputs">' + inputNodes + '</div>' +
                '<div class="tx-flow-svg-wrap"><svg viewBox="0 0 100 ' + svgH.toFixed(1) + '" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg">' + svgPaths + '</svg></div>' +
                '<div class="tx-flow-col tx-flow-outputs">' + outputNodes + '</div>' +
            '</div>' +
            feeHtml;
    }

    /**
     * Build an SVG Sankey flow diagram for a transaction.
     * Returns HTML string containing the full flow wrapper.
     * (Kept for compatibility; the interactive controller is used for the
     * transaction view.)
     */
    function buildSankeyHtml(inputs, outputs, fee, feeRate) {
        var MAX_DISPLAY = 20;
        var isCoinbase = inputs.length > 0 && inputs[0].coinbase;
        var dispIn = inputs.slice(0, MAX_DISPLAY);
        var dispOut = outputs.slice(0, MAX_DISPLAY);
        var moreIn = inputs.length > MAX_DISPLAY ? inputs.length - MAX_DISPLAY : 0;
        var moreOut = outputs.length > MAX_DISPLAY ? outputs.length - MAX_DISPLAY : 0;

        var totalIn = 0, totalOut = 0;
        for (var i = 0; i < dispIn.length; i++) totalIn += (dispIn[i].value || 0);
        for (var i = 0; i < dispOut.length; i++) totalOut += (dispOut[i].value || 0);
        var totalFlow = Math.max(totalIn, totalOut, 1);

        // Tall enough for addr + value lines plus a spend badge; node
        // heights are exact (Sankey band anchors depend on them), so the
        // minimum must fit the content or it clips.
        var MIN_H = 60;
        var GAP = 4;
        var hasValues = totalIn > 0 && totalOut > 0;

        // Calculate node heights
        function calcHeights(nodes, total) {
            var baseH = Math.max(300, nodes.length * (MIN_H + GAP));
            return nodes.map(function (n) {
                if (hasValues && n.value != null && n.value > 0 && total > 0) {
                    return Math.max(MIN_H, (n.value / total) * baseH);
                }
                return MIN_H;
            });
        }

        var inH = calcHeights(dispIn, totalIn);
        var outH = calcHeights(dispOut, totalOut);

        var inTotal = 0, outTotal = 0;
        for (var i = 0; i < inH.length; i++) inTotal += inH[i] + (i > 0 ? GAP : 0);
        for (var i = 0; i < outH.length; i++) outTotal += outH[i] + (i > 0 ? GAP : 0);
        var svgH = Math.max(inTotal, outTotal);

        // Center the shorter column
        var inOff = (svgH - inTotal) / 2;
        var outOff = (svgH - outTotal) / 2;

        // Calculate y positions
        var inY = [], y = inOff;
        for (var i = 0; i < dispIn.length; i++) {
            inY.push(y);
            y += inH[i] + GAP;
        }
        var outY = [], y2 = outOff;
        for (var i = 0; i < dispOut.length; i++) {
            outY.push(y2);
            y2 += outH[i] + GAP;
        }

        // Build SVG bands
        var svgPaths = '';
        if (hasValues && !isCoinbase) {
            var inUsed = new Array(dispIn.length).fill(0);
            var outUsed = new Array(dispOut.length).fill(0);
            for (var i = 0; i < dispIn.length; i++) {
                var iv = dispIn[i].value || 0;
                if (iv <= 0) continue;
                for (var j = 0; j < dispOut.length; j++) {
                    var ov = dispOut[j].value || 0;
                    if (ov <= 0) continue;
                    var flow = iv * ov / totalFlow;
                    var bInH = (flow / iv) * inH[i];
                    var bOutH = (flow / ov) * outH[j];

                    var y1t = inY[i] + inUsed[i];
                    var y1b = y1t + bInH;
                    var y2t = outY[j] + outUsed[j];
                    var y2b = y2t + bOutH;
                    inUsed[i] += bInH;
                    outUsed[j] += bOutH;

                    var col = SANKEY_COLORS[i % SANKEY_COLORS.length];
                    svgPaths += '<path class="sankey-band" data-input="' + i + '" data-output="' + j + '" d="M0,' + y1t.toFixed(1) + ' C50,' + y1t.toFixed(1) + ' 50,' + y2t.toFixed(1) + ' 100,' + y2t.toFixed(1) + ' L100,' + y2b.toFixed(1) + ' C50,' + y2b.toFixed(1) + ' 50,' + y1b.toFixed(1) + ' 0,' + y1b.toFixed(1) + ' Z" fill="' + col + '" opacity="0.35"/>';
                }
            }
        } else {
            // Simple equal bands when values unknown or coinbase
            for (var i = 0; i < dispIn.length; i++) {
                for (var j = 0; j < dispOut.length; j++) {
                    var bInH = inH[i] / dispOut.length;
                    var bOutH = outH[j] / dispIn.length;
                    var y1t = inY[i] + bInH * j;
                    var y1b = y1t + bInH;
                    var y2t = outY[j] + bOutH * i;
                    var y2b = y2t + bOutH;
                    var col = SANKEY_COLORS[i % SANKEY_COLORS.length];
                    svgPaths += '<path class="sankey-band" data-input="' + i + '" data-output="' + j + '" d="M0,' + y1t.toFixed(1) + ' C50,' + y1t.toFixed(1) + ' 50,' + y2t.toFixed(1) + ' 100,' + y2t.toFixed(1) + ' L100,' + y2b.toFixed(1) + ' C50,' + y2b.toFixed(1) + ' 50,' + y1b.toFixed(1) + ' 0,' + y1b.toFixed(1) + ' Z" fill="' + col + '" opacity="0.35"/>';
                }
            }
        }

        // Build input nodes HTML
        var inputNodes = '';
        for (var i = 0; i < dispIn.length; i++) {
            var inp = dispIn[i];
            var nodeClass = 'tx-flow-node input';
            var addrHtml, valHtml = '', clickNav = '';
            if (inp.coinbase) {
                nodeClass = 'tx-flow-node coinbase';
                addrHtml = '<span style="color:var(--green);font-weight:600;">Coinbase</span>';
                valHtml = totalOut > 0 ? formatBtc(totalOut) : '';
            } else {
                var addr = inp.address || '';
                if (addr) {
                    addrHtml = '<a href="#/address/' + encodeURIComponent(addr) + '">' + escapeHtml(truncateHash(addr, 6)) + '</a>';
                } else {
                    addrHtml = escapeHtml(truncateHash(inp.txid, 6)) + ':' + inp.vout;
                }
                if (inp.txid) {
                    clickNav = '#/tx/' + encodeURIComponent(inp.txid);
                }
                valHtml = inp.value != null ? formatBtc(inp.value) : '';
            }
            inputNodes += '<div class="' + nodeClass + '" data-side="input" data-index="' + i + '" style="height:' + inH[i].toFixed(0) + 'px;"' + (clickNav ? ' onclick="location.hash=\'' + clickNav + '\'"' : '') + '>' +
                '<div class="tx-flow-node-addr">' + addrHtml + '</div>' +
                (valHtml ? '<div class="tx-flow-node-value">' + valHtml + '</div>' : '') +
                '</div>';
        }
        if (moreIn > 0) {
            inputNodes += '<div class="tx-flow-more">+ ' + moreIn + ' more input' + (moreIn > 1 ? 's' : '') + '</div>';
        }

        // Build output nodes HTML
        var outputNodes = '';
        for (var i = 0; i < dispOut.length; i++) {
            var out = dispOut[i];
            var nodeClass = 'tx-flow-node output';
            var addr = out.address || '';
            var spk = out.script_pubkey || '';
            var addrHtml, clickNav = '';
            if (spk.startsWith('6a')) {
                nodeClass = 'tx-flow-node output op-return';
                addrHtml = 'OP_RETURN';
            } else if (addr) {
                addrHtml = '<a href="#/address/' + encodeURIComponent(addr) + '">' + escapeHtml(truncateHash(addr, 6)) + '</a>';
                clickNav = '#/address/' + encodeURIComponent(addr);
            } else {
                addrHtml = 'Script';
            }
            var valHtml = out.value != null ? formatBtc(out.value) : '';
            outputNodes += '<div class="' + nodeClass + '" data-side="output" data-index="' + i + '" style="height:' + outH[i].toFixed(0) + 'px;"' + (clickNav ? ' onclick="location.hash=\'' + clickNav + '\'"' : '') + '>' +
                '<div class="tx-flow-node-addr">' + addrHtml + '</div>' +
                (valHtml ? '<div class="tx-flow-node-value">' + valHtml + '</div>' : '') +
                '</div>';
        }
        if (moreOut > 0) {
            outputNodes += '<div class="tx-flow-more">+ ' + moreOut + ' more output' + (moreOut > 1 ? 's' : '') + '</div>';
        }

        // Fee footer
        var feeHtml = '';
        if (fee != null && fee > 0) {
            feeHtml = '<div class="tx-flow-fee">' +
                '<span class="tx-flow-fee-label">Fee</span>' +
                '<span class="tx-flow-fee-value">' + formatBtc(fee) + '</span>' +
                (feeRate != null ? '<span class="mono" style="font-size:0.78rem;">(' + feeRate.toFixed(2) + ' sat/vB)</span>' : '') +
                '</div>';
        }

        var inCount = inputs.length;
        var outCount = outputs.length;

        return '<div class="tx-flow-wrapper" id="tx-flow-wrapper">' +
            '<div class="tx-flow-title">Transaction Flow <span class="badge">' + inCount + ' in / ' + outCount + ' out</span></div>' +
            '<div class="tx-flow">' +
                '<div class="tx-flow-col tx-flow-inputs">' + inputNodes + '</div>' +
                '<div class="tx-flow-svg-wrap"><svg viewBox="0 0 100 ' + svgH.toFixed(1) + '" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg">' + svgPaths + '</svg></div>' +
                '<div class="tx-flow-col tx-flow-outputs">' + outputNodes + '</div>' +
            '</div>' +
            feeHtml +
            '</div>';
    }

    async function renderTransaction(txid) {
        showLoading('Loading transaction…');
        try {
            const tx = await api('tx/' + encodeURIComponent(txid));

            const statusHtml = tx.confirmed
                ? `<span class="status-badge running"><span class="status-dot green"></span>Confirmed</span>`
                : `<span class="status-badge syncing"><span class="status-dot amber pulse"></span>Unconfirmed</span>`;

            const summaryFields = [
                ['Status', statusHtml],
                ['Transaction ID', `<span class="mono" style="font-size:0.78rem;">${escapeHtml(tx.txid)}</span>`],
                ['Confirmations', formatNumber(tx.confirmations)],
                ['Fee', tx.fee != null ? formatBtc(tx.fee) : '—'],
                ['Fee Rate', tx.fee_rate != null ? tx.fee_rate.toFixed(2) + ' sat/vB' : '—'],
                ['Size', tx.size != null ? formatNumber(tx.size) + ' bytes' : '—'],
                ['Weight', tx.weight != null ? formatNumber(tx.weight) + ' WU' : '—'],
            ];
            if (tx.block_hash) {
                summaryFields.push(['Block', hashLink(tx.block_hash) + (tx.block_height != null ? ' (height ' + formatNumber(tx.block_height) + ')' : '')]);
            }

            let detailRows = '';
            for (const [label, value] of summaryFields) {
                detailRows += `
                    <div class="detail-row">
                        <div class="detail-label">${escapeHtml(label)}</div>
                        <div class="detail-value">${value}</div>
                    </div>`;
            }

            const hasFlow = tx.inputs && tx.outputs && (tx.inputs.length > 0 || tx.outputs.length > 0);

            setPage(`
                <div class="page-header">
                    <h1>Transaction</h1>
                    <div class="subtitle mono">${escapeHtml(truncateHash(tx.txid, 16))}</div>
                </div>
                <div class="detail-card">
                    <div class="detail-title">Transaction Details</div>
                    ${detailRows}
                </div>
                ${hasFlow ? '<div class="tx-flow-wrapper" id="tx-flow-mount"></div>' : ''}`);

            // Mount the interactive multi-stage flow controller for the focus tx.
            if (hasFlow) {
                const mount = document.getElementById('tx-flow-mount');
                if (mount) {
                    const controller = new TxFlowController(mount);
                    // Fetch outspends defensively; the focus stage renders either way.
                    fetchOutspends(tx.txid).then(function (os) {
                        controller.setFocus(tx, os);
                    });
                }
            }
        } catch (err) {
            showError('Transaction Not Found', 'Could not load transaction. ' + err.message);
        }
    }

    /* -- Address Detail -- */

    async function renderAddress(addr) {
        showLoading('Loading address…');
        try {
            const data = await api('address/' + encodeURIComponent(addr));
            const bal = data.balance || {};

            let txRows = '';
            if (data.tx_history && data.tx_history.length > 0) {
                for (const tx of data.tx_history) {
                    const txid = tx.txid || tx.tx_hash || tx;
                    const height = tx.height || tx.block_height;
                    txRows += `
                        <tr>
                            <td>${typeof txid === 'string' ? txLink(txid) : '—'}</td>
                            <td>${height != null ? blockLink(height, formatNumber(height)) : '<span class="status-badge syncing">Unconfirmed</span>'}</td>
                            <td class="mono text-right">${tx.value != null ? formatBtc(tx.value) : '—'}</td>
                        </tr>`;
                }
            }

            setPage(`
                <div class="page-header">
                    <h1>Address</h1>
                    <div class="subtitle mono">${escapeHtml(addr)}</div>
                </div>
                <div class="stats-grid">
                    ${statCard('Confirmed Balance', formatBtc(bal.confirmed), 'accent')}
                    ${statCard('Unconfirmed Balance', formatBtc(bal.unconfirmed), bal.unconfirmed > 0 ? 'amber' : '')}
                    ${statCard('Total Transactions', formatNumber(data.tx_count), 'blue')}
                </div>
                <div class="detail-card">
                    <div class="detail-title">Address Info</div>
                    <div class="detail-row">
                        <div class="detail-label">Address</div>
                        <div class="detail-value mono">${escapeHtml(data.address || addr)}</div>
                    </div>
                    ${data.scripthash ? `
                    <div class="detail-row">
                        <div class="detail-label">Script Hash</div>
                        <div class="detail-value mono" style="font-size:0.78rem;">${escapeHtml(data.scripthash)}</div>
                    </div>` : ''}
                </div>
                <div class="table-wrapper">
                    <div class="table-title">
                        Transaction History
                        <span class="badge">${formatNumber(data.tx_count)}</span>
                    </div>
                    ${data.tx_history && data.tx_history.length > 0 ? `
                    <table>
                        <thead>
                            <tr>
                                <th>Transaction ID</th>
                                <th>Block</th>
                                <th class="text-right">Value</th>
                            </tr>
                        </thead>
                        <tbody>${txRows}</tbody>
                    </table>` : '<div class="empty-state">No transactions found</div>'}
                </div>`);
        } catch (err) {
            showError('Address Not Found', 'Could not load address data. ' + err.message);
        }
    }

    /* -- Mempool -- */

    /* Chart timeframe selection: seconds of history to plot, or 'all'
       (server retains ~2h of 10s samples). Persists across re-renders. */
    let mempoolChartRange = 'all';
    let mempoolChartData = null;

    function chartRangeButtonsHtml() {
        const ranges = [
            [900, '15m'], [1800, '30m'], [3600, '1h'], ['all', '2h'],
        ];
        return '<span class="chart-range">' + ranges.map(function (r) {
            const active = String(mempoolChartRange) === String(r[0]);
            return '<button type="button" class="chart-range-btn' + (active ? ' active' : '')
                + '" data-range="' + r[0] + '">' + r[1] + '</button>';
        }).join('') + '</span>';
    }

    /**
     * Build an inline SVG line chart of mempool fee rate (sat/vB) over time.
     * Plots the fee_p50 line with a shaded fee_p10–fee_p90 band, windowed
     * to the selected timeframe. Returns an HTML string (a .card).
     */
    function buildMempoolFeeChart(historyData) {
        const allSamples = (historyData && historyData.samples) || [];

        if (allSamples.length < 2) {
            return `
                <div class="card mempool-chart-card">
                    <div class="card-header">Mempool Fee Rate (sat/vB)</div>
                    <div class="empty-state">Collecting mempool data… (samples appear every ~10s)</div>
                </div>`;
        }

        let samples = allSamples;
        if (mempoolChartRange !== 'all') {
            const cutoff = Math.floor(Date.now() / 1000) - Number(mempoolChartRange);
            samples = allSamples.filter(function (s) { return s.time >= cutoff; });
        }

        if (samples.length < 2) {
            return `
                <div class="card mempool-chart-card">
                    <div class="card-header">
                        Mempool Fee Rate (sat/vB)
                        ${chartRangeButtonsHtml()}
                    </div>
                    <div class="empty-state">Not enough samples in this timeframe yet</div>
                </div>`;
        }

        // Internal coordinate space.
        const W = 1000, H = 300;
        const padL = 48, padR = 12, padT = 14, padB = 28;
        const plotW = W - padL - padR;
        const plotH = H - padT - padB;

        const n = samples.length;

        function num(v) { return (v == null || isNaN(v)) ? 0 : Number(v); }

        // Y scale based on max p90 (fall back to p50), with a sane minimum.
        let maxFee = 0;
        for (const s of samples) {
            maxFee = Math.max(maxFee, num(s.fee_p90), num(s.fee_p50));
        }
        if (maxFee < 4) maxFee = 4; // avoid a flat line filling full height

        function xAt(i) {
            return padL + (n === 1 ? 0 : (i / (n - 1)) * plotW);
        }
        function yAt(fee) {
            const f = Math.max(0, Math.min(maxFee, num(fee)));
            return padT + plotH - (f / maxFee) * plotH;
        }

        // Gridlines + y labels (4 lines).
        const gridCount = 4;
        let gridSvg = '';
        for (let g = 0; g <= gridCount; g++) {
            const frac = g / gridCount;
            const val = maxFee * (1 - frac);
            const y = padT + frac * plotH;
            gridSvg += '<line class="chart-grid" x1="' + padL + '" y1="' + y.toFixed(1) +
                '" x2="' + (W - padR) + '" y2="' + y.toFixed(1) + '"/>';
            gridSvg += '<text class="chart-label" x="' + (padL - 6) + '" y="' + (y + 4).toFixed(1) +
                '" text-anchor="end">' + val.toFixed(val < 10 ? 1 : 0) + '</text>';
        }

        // X-axis time labels (first / middle / last).
        let xLabelSvg = '';
        const labelIdx = [0, Math.floor((n - 1) / 2), n - 1];
        const anchors = ['start', 'middle', 'end'];
        for (let k = 0; k < labelIdx.length; k++) {
            const idx = labelIdx[k];
            const s = samples[idx];
            if (!s) continue;
            const x = xAt(idx);
            xLabelSvg += '<text class="chart-label" x="' + x.toFixed(1) + '" y="' + (H - 8) +
                '" text-anchor="' + anchors[k] + '">' + escapeHtml(formatTimeShort(s.time)) + '</text>';
        }

        // Stepped (step-after) paths: horizontal run per sample with a
        // vertical jump to the next — chunky 8-bit rendering that is also
        // honest about the discrete 10s sampling.

        // p10–p90 band (stepped across p90, stepped back across p10).
        let bandPath = '';
        for (let i = 0; i < n; i++) {
            const x = xAt(i).toFixed(1), y = yAt(samples[i].fee_p90).toFixed(1);
            bandPath += (i === 0 ? 'M' + x + ',' + y : 'H' + x + 'V' + y) + ' ';
        }
        for (let i = n - 1; i >= 0; i--) {
            const x = xAt(i).toFixed(1), y = yAt(samples[i].fee_p10).toFixed(1);
            bandPath += (i === n - 1 ? 'L' + x + ',' + y : 'H' + x + 'V' + y) + ' ';
        }
        bandPath += 'Z';

        // p50 line (stepped).
        let linePath = '';
        for (let i = 0; i < n; i++) {
            const x = xAt(i).toFixed(1), y = yAt(samples[i].fee_p50).toFixed(1);
            linePath += (i === 0 ? 'M' + x + ',' + y : 'H' + x + 'V' + y) + ' ';
        }

        const svg =
            '<svg class="mempool-chart-svg" viewBox="0 0 ' + W + ' ' + H + '" preserveAspectRatio="none" xmlns="http://www.w3.org/2000/svg">' +
                gridSvg +
                '<path class="chart-band" d="' + bandPath.trim() + '"/>' +
                '<path class="chart-line" d="' + linePath.trim() + '"/>' +
                xLabelSvg +
            '</svg>';

        return `
            <div class="card mempool-chart-card">
                <div class="card-header">
                    Mempool Fee Rate (sat/vB)
                    <span class="chart-legend">
                        <span class="chart-legend-item"><span class="chart-legend-line"></span>median (p50)</span>
                        <span class="chart-legend-item"><span class="chart-legend-band"></span>p10–p90</span>
                    </span>
                    ${chartRangeButtonsHtml()}
                </div>
                <div class="mempool-chart-wrap">${svg}</div>
            </div>`;
    }

    async function renderMempool() {
        showLoading('Loading mempool…');
        try {
            const [mempool, txData, historyData] = await Promise.all([
                api('mempool'),
                api('mempool/txs?page=1&per_page=20').catch(function () { return null; }),
                api('mempool/history').catch(function () { return null; })
            ]);

            mempoolChartData = historyData;
            const chartHtml = buildMempoolFeeChart(historyData);

            let histogramHtml = '';
            if (mempool.fee_histogram && mempool.fee_histogram.length > 0) {
                const maxSize = Math.max(...mempool.fee_histogram.map(function (b) { return b.size || b.count || 0; }));
                for (const bucket of mempool.fee_histogram) {
                    const pct = maxSize > 0 ? ((bucket.size || bucket.count || 0) / maxSize * 100) : 0;
                    const range = bucket.range || '?';
                    let barClass = 'low';
                    if (typeof range === 'number' || typeof range === 'string') {
                        const rangeNum = parseFloat(range);
                        if (rangeNum >= 50) barClass = 'high';
                        else if (rangeNum >= 10) barClass = 'medium';
                    }
                    histogramHtml += `
                        <div class="fee-row">
                            <span class="fee-label">${escapeHtml(String(range))} sat/vB</span>
                            <div class="fee-bar-track">
                                <div class="fee-bar-fill ${barClass}" style="width:${pct.toFixed(1)}%"></div>
                            </div>
                            <span class="fee-count">${formatNumber(bucket.count)} txs</span>
                        </div>`;
                }
            } else {
                histogramHtml = '<div class="empty-state">No fee data available</div>';
            }

            let txTableHtml = '';
            if (txData && txData.transactions && txData.transactions.length > 0) {
                let txRows = '';
                for (const tx of txData.transactions) {
                    txRows += `
                        <tr>
                            <td>${txLink(tx.txid)}</td>
                            <td class="mono text-right">${tx.fee != null ? formatNumber(tx.fee) + ' sat' : '—'}</td>
                            <td class="mono text-right">${tx.fee_rate != null ? tx.fee_rate.toFixed(1) : '—'}</td>
                            <td class="mono text-right">${tx.size != null ? formatNumber(tx.size) : '—'}</td>
                        </tr>`;
                }
                txTableHtml = `
                    <table>
                        <thead>
                            <tr>
                                <th>Transaction ID</th>
                                <th class="text-right">Fee</th>
                                <th class="text-right">Fee Rate (sat/vB)</th>
                                <th class="text-right">Size</th>
                            </tr>
                        </thead>
                        <tbody>${txRows}</tbody>
                    </table>`;
            } else {
                txTableHtml = '<div class="empty-state">No mempool transactions</div>';
            }

            setPage(`
                <div class="page-header">
                    <h1>Mempool</h1>
                    <div class="subtitle">Unconfirmed transaction pool</div>
                </div>
                <div class="stats-grid">
                    ${statCard('Transactions', formatNumber(mempool.size), 'accent')}
                    ${statCard('Memory Usage', formatBytes(mempool.bytes), '')}
                    ${statCard('Total Fees', mempool.total_fee != null ? formatBtc(mempool.total_fee) : '—', 'green')}
                </div>
                <div id="mempool-chart-slot">${chartHtml}</div>
                <div class="two-col">
                    <div class="card">
                        <div class="card-header">Fee Histogram</div>
                        <div class="fee-histogram">${histogramHtml}</div>
                    </div>
                    <div class="table-wrapper">
                        <div class="table-title">
                            Pending Transactions
                            ${txData ? `<span class="badge">${formatNumber(txData.total)}</span>` : ''}
                        </div>
                        ${txTableHtml}
                    </div>
                </div>`);

            // Timeframe buttons: delegated on the slot so the listener
            // survives chart re-renders.
            const chartSlot = document.getElementById('mempool-chart-slot');
            if (chartSlot) {
                chartSlot.addEventListener('click', function (e) {
                    const btn = e.target.closest('.chart-range-btn');
                    if (!btn) return;
                    const r = btn.dataset.range;
                    mempoolChartRange = r === 'all' ? 'all' : Number(r);
                    chartSlot.innerHTML = buildMempoolFeeChart(mempoolChartData);
                });
            }
        } catch (err) {
            showError('Mempool Error', 'Could not load mempool data. ' + err.message);
        }
    }

    /* -- Mining -- */

    async function renderMining() {
        showLoading('Loading mining dashboard…');
        try {
            const [miningData, workersData, historyData] = await Promise.all([
                api('mining').catch(function () { return null; }),
                api('mining/workers').catch(function () { return null; }),
                api('mining/history').catch(function () { return null; })
            ]);

            if (!miningData) {
                showError('Mining Unavailable', 'Mining data is not available. The mining module may not be enabled.');
                return;
            }

            const m = miningData;
            const totalShares = (m.shares_accepted || 0) + (m.shares_rejected || 0);
            const acceptRate = totalShares > 0 ? ((m.shares_accepted || 0) / totalShares * 100) : 100;

            const gatewayRunning = m.gateway_status === 'running' || m.gateway_status === 'Running';
            const gatewayClass = gatewayRunning ? 'running' : 'stopped';
            const gatewayDotClass = gatewayRunning ? 'green pulse' : 'red';
            const gatewayLabel = gatewayRunning ? 'Running' : 'Stopped';

            let workerRows = '';
            const workers = (workersData && workersData.workers) || [];
            if (workers.length > 0) {
                for (const w of workers) {
                    workerRows += `
                        <tr>
                            <td class="mono">${escapeHtml(w.name || '—')}</td>
                            <td class="mono">${formatHashrate(w.hashrate)}</td>
                            <td class="mono share-accepted">${formatNumber(w.shares_accepted)}</td>
                            <td class="mono share-rejected">${formatNumber(w.shares_rejected)}</td>
                            <td>${formatTime(w.last_share_time)}</td>
                        </tr>`;
                }
            }

            let shareRows = '';
            const shares = (historyData && historyData.shares) || [];
            const recentShares = shares.slice(0, 50);
            if (recentShares.length > 0) {
                for (const s of recentShares) {
                    const accepted = s.accepted !== false;
                    shareRows += `
                        <tr>
                            <td class="mono">${escapeHtml(s.worker || '—')}</td>
                            <td>${formatTimeShort(s.timestamp)}</td>
                            <td class="mono">${s.difficulty != null ? formatNumber(s.difficulty) : '—'}</td>
                            <td class="text-center">${accepted
                                ? '<span class="share-accepted">✓</span>'
                                : '<span class="share-rejected">✗</span>'
                            }</td>
                        </tr>`;
                }
            }

            const datumSection = buildDatumSection(m.datum_status);

            setPage(`
                <div class="page-header">
                    <h1>Mining Dashboard</h1>
                    <div class="subtitle">
                        <span class="status-badge ${gatewayClass}">
                            <span class="status-dot ${gatewayDotClass}"></span>
                            Gateway ${gatewayLabel}
                        </span>
                        ${m.solo_mining ? ' · Solo Mining' : ''}
                    </div>
                </div>

                <div class="card hashrate-display" id="mining-hashrate-card">
                    <div class="hashrate-value" id="mining-hashrate-value">${escapeHtml(String(m.hashrate != null ? Number(m.hashrate).toFixed(2) : '0.00'))}</div>
                    <div class="hashrate-unit" id="mining-hashrate-unit">${escapeHtml(m.hashrate_unit || 'H/s')}</div>
                    <div class="hashrate-label">Hashrate</div>
                </div>

                <div class="stats-grid stats-grid-wide" id="mining-stats-grid">
                    ${statCard('Shares Accepted', '<span id="mining-accepted">' + formatNumber(m.shares_accepted) + '</span>', 'green')}
                    ${statCard('Shares Rejected', '<span id="mining-rejected">' + formatNumber(m.shares_rejected) + '</span>', m.shares_rejected > 0 ? 'red' : '')}
                    ${statCard('Blocks Found', formatNumber(m.blocks_found), 'accent')}
                    ${statCard('Best Difficulty', formatDifficulty(m.best_share_difficulty), '')}
                    ${statCard('Connected Workers', '<span id="mining-workers-count">' + formatNumber(m.connected_workers) + '</span>', 'blue')}
                    ${statCard('Mining Uptime', formatUptime(m.uptime_secs), 'green')}
                </div>

                <div class="card" id="mining-acceptance-bar">
                    <div class="card-header">Acceptance Rate</div>
                    <div class="acceptance-bar-container">
                        <div class="acceptance-bar-label">
                            <span class="share-accepted">${formatNumber(m.shares_accepted)} accepted</span>
                            <span id="mining-accept-rate" style="font-weight:600;">${acceptRate.toFixed(1)}%</span>
                            <span class="share-rejected">${formatNumber(m.shares_rejected)} rejected</span>
                        </div>
                        <div class="acceptance-bar">
                            <div class="acceptance-bar-fill" id="mining-accept-fill" style="width:${acceptRate.toFixed(1)}%"></div>
                        </div>
                    </div>
                </div>

                <div class="two-col" style="margin-top:24px;">
                    <div class="table-wrapper" id="mining-workers-table">
                        <div class="table-title">
                            Workers
                            <span class="badge">${workers.length}</span>
                        </div>
                        ${workers.length > 0 ? `
                        <table>
                            <thead>
                                <tr>
                                    <th>Name</th>
                                    <th>Hashrate</th>
                                    <th>Accepted</th>
                                    <th>Rejected</th>
                                    <th>Last Share</th>
                                </tr>
                            </thead>
                            <tbody>${workerRows}</tbody>
                        </table>` : '<div class="empty-state">No workers connected</div>'}
                    </div>

                    <div class="table-wrapper" id="mining-shares-table">
                        <div class="table-title">
                            Recent Shares
                            <span class="badge">${recentShares.length}</span>
                        </div>
                        ${recentShares.length > 0 ? `
                        <table>
                            <thead>
                                <tr>
                                    <th>Worker</th>
                                    <th>Time</th>
                                    <th>Difficulty</th>
                                    <th class="text-center">Status</th>
                                </tr>
                            </thead>
                            <tbody id="mining-shares-tbody">${shareRows}</tbody>
                        </table>` : '<div class="empty-state">No recent shares</div>'}
                    </div>
                </div>
                ${datumSection}`);

            if (typeof window.initMiningWebSocket === 'function') {
                window.initMiningWebSocket();
            }
        } catch (err) {
            showError('Mining Error', 'Could not load mining data. ' + err.message);
        }
    }

    /* -- Datum Pool Section (rendered inside the mining dashboard) -- */

    function buildDatumSection(datum) {
        if (!datum) return '';

        const connected = !!datum.connected;
        const badgeClass = connected ? 'running' : 'stopped';
        const dotClass = connected ? 'green pulse' : 'red';
        const badgeLabel = connected ? 'Connected' : 'Disconnected';

        const submitted = datum.shares_submitted || 0;
        const accepted = datum.shares_accepted || 0;
        const acceptRate = submitted > 0 ? (accepted / submitted * 100) : 0;

        let payoutHtml;
        if (datum.last_payout) {
            const p = datum.last_payout;
            payoutHtml =
                txLink(p.txid) +
                ' · ' + formatBtc(p.amount) +
                (p.block_height != null ? ' · height ' + blockLink(p.block_height, formatNumber(p.block_height)) : '');
        } else {
            payoutHtml = '—';
        }

        return `
            <div class="page-header" style="margin-top:32px;">
                <h1>Pool Connection</h1>
                <div class="subtitle">Datum decentralized pool status</div>
            </div>
            <div class="stats-grid stats-grid-wide">
                <div class="card">
                    <div class="card-header">Connection</div>
                    <div class="card-value" style="font-size:1rem;">
                        <span class="status-badge ${badgeClass}" id="datum-conn-badge">
                            <span class="status-dot ${dotClass}"></span>${badgeLabel}
                        </span>
                    </div>
                    <div class="card-sub">Pool: <span id="datum-pool-name">${escapeHtml(datum.pool_name || '—')}</span></div>
                </div>
                ${statCard('Payout Scheme', '<span id="datum-payout-scheme">' + escapeHtml(datum.payout_scheme || '—') + '</span>', '')}
                ${statCard('Pool Difficulty', '<span id="datum-pool-difficulty">' + (datum.pool_difficulty != null ? formatDifficulty(datum.pool_difficulty) : '—') + '</span>', '')}
                ${statCard('Shares Submitted', '<span id="datum-shares-submitted">' + formatNumber(submitted) + '</span>', 'blue')}
                ${statCard('Shares Accepted', '<span id="datum-shares-accepted">' + formatNumber(accepted) + '</span>', 'green', '<span id="datum-accept-rate">' + acceptRate.toFixed(1) + '%</span> accepted')}
                ${statCard('Pool Uptime', formatUptime(datum.uptime_secs), 'green')}
            </div>
            <div class="detail-card">
                <div class="detail-title">Recent Payout</div>
                <div class="detail-row">
                    <div class="detail-label">Last Payout</div>
                    <div class="detail-value" id="datum-payout-line">${payoutHtml}</div>
                </div>
            </div>`;
    }

    /* -- Mining Config -- */

    async function renderMiningConfig() {
        showLoading('Loading mining configuration…');
        try {
            const response = await api('mining/config');

            if (response.error) {
                showError('Mining Unavailable', response.error);
                return;
            }

            const cfg = response;
            const datum = cfg.datum || {};
            const isDatum = cfg.mode === 'datum';

            setPage(`
                <div class="page-header">
                    <h1>Mining Configuration</h1>
                    <div class="subtitle">Coinbase, mode, and Datum pool settings</div>
                </div>
                <form class="config-form" id="mining-config-form" autocomplete="off">
                    <div class="card config-card">
                        <div class="card-header">Coinbase Settings</div>
                        <div class="config-row">
                            <label for="cfg-mining-address">Mining Address</label>
                            <input type="text" id="cfg-mining-address" placeholder="OP_TRUE (anyone-can-spend) if empty" spellcheck="false">
                        </div>
                        <div class="config-row">
                            <label for="cfg-coinbase-tag">Coinbase Tag</label>
                            <input type="text" id="cfg-coinbase-tag" spellcheck="false">
                        </div>
                        <div class="config-row">
                            <label for="cfg-pool-name">Pool Name</label>
                            <input type="text" id="cfg-pool-name" spellcheck="false">
                        </div>
                    </div>

                    <div class="card config-card">
                        <div class="card-header">Mining Mode</div>
                        <div class="config-radio-group">
                            <label class="config-radio">
                                <input type="radio" name="mining-mode" value="solo" ${isDatum ? '' : 'checked'}>
                                <span>Solo</span>
                            </label>
                            <label class="config-radio">
                                <input type="radio" name="mining-mode" value="datum" ${isDatum ? 'checked' : ''}>
                                <span>Datum</span>
                            </label>
                        </div>
                    </div>

                    <div class="card config-card" id="datum-settings" style="display:${isDatum ? 'block' : 'none'};">
                        <div class="card-header">Datum Settings</div>
                        <div class="config-row">
                            <label for="cfg-datum-server">Server URL</label>
                            <input type="text" id="cfg-datum-server" placeholder="datum.ocean.xyz:3334" spellcheck="false">
                        </div>
                        <div class="config-row">
                            <label for="cfg-datum-payout">Payout Address</label>
                            <input type="text" id="cfg-datum-payout" spellcheck="false">
                        </div>
                        <div class="config-row">
                            <label for="cfg-datum-worker">Worker Name</label>
                            <input type="text" id="cfg-datum-worker" spellcheck="false">
                        </div>
                        <div class="config-row">
                            <label for="cfg-datum-token">Auth Token</label>
                            <input type="password" id="cfg-datum-token" placeholder="${datum.auth_token_set ? '•••• (set)' : ''}" spellcheck="false">
                        </div>
                    </div>

                    <div class="card config-card">
                        <div class="card-header">Status (read-only)</div>
                        <div class="config-row">
                            <label>Stratum Port</label>
                            <div class="config-readonly mono" id="cfg-stratum-port">${escapeHtml(String(cfg.stratum_port != null ? cfg.stratum_port : '—'))}</div>
                        </div>
                        <div class="config-note">Port changes require a restart.</div>
                    </div>

                    <div class="config-actions">
                        <button type="submit" class="btn" id="cfg-save-btn">Save</button>
                        <div class="config-save-status" id="config-save-status"></div>
                    </div>
                </form>`);

            // Populate values programmatically (safer than escaping attributes)
            const setVal = function (id, val) {
                const el = document.getElementById(id);
                if (el) el.value = val != null ? val : '';
            };
            setVal('cfg-mining-address', cfg.mining_address);
            setVal('cfg-coinbase-tag', cfg.coinbase_tag);
            setVal('cfg-pool-name', cfg.pool_name);
            setVal('cfg-datum-server', datum.server_url);
            setVal('cfg-datum-payout', datum.payout_address);
            setVal('cfg-datum-worker', datum.worker_name);

            // Toggle Datum settings visibility on mode change
            const datumSettings = document.getElementById('datum-settings');
            document.querySelectorAll('input[name="mining-mode"]').forEach(function (radio) {
                radio.addEventListener('change', function () {
                    if (datumSettings) {
                        datumSettings.style.display = this.value === 'datum' ? 'block' : 'none';
                    }
                });
            });

            // Save handler
            const form = document.getElementById('mining-config-form');
            const statusEl = document.getElementById('config-save-status');
            const saveBtn = document.getElementById('cfg-save-btn');

            form.addEventListener('submit', async function (e) {
                e.preventDefault();
                if (statusEl) {
                    statusEl.className = 'config-save-status';
                    statusEl.textContent = '';
                }
                if (saveBtn) saveBtn.disabled = true;

                const modeRadio = document.querySelector('input[name="mining-mode"]:checked');
                const payload = {
                    mining_address: document.getElementById('cfg-mining-address').value,
                    coinbase_tag: document.getElementById('cfg-coinbase-tag').value,
                    pool_name: document.getElementById('cfg-pool-name').value,
                    mode: modeRadio ? modeRadio.value : 'solo',
                    datum: {
                        server_url: document.getElementById('cfg-datum-server').value,
                        payout_address: document.getElementById('cfg-datum-payout').value,
                        worker_name: document.getElementById('cfg-datum-worker').value
                    }
                };

                // Only include auth_token if the user typed something (avoid wiping existing token)
                const tokenVal = document.getElementById('cfg-datum-token').value;
                if (tokenVal) {
                    payload.datum.auth_token = tokenVal;
                }

                // Mutating endpoints require the node's admin token
                // (--webadmintoken). Kept in sessionStorage so the user is
                // prompted at most once per browser session.
                const postConfig = function () {
                    const headers = { 'Content-Type': 'application/json' };
                    const adminToken = sessionStorage.getItem('webAdminToken');
                    if (adminToken) headers['Authorization'] = 'Bearer ' + adminToken;
                    return fetch('/api/mining/config', {
                        method: 'POST',
                        headers: headers,
                        body: JSON.stringify(payload)
                    });
                };

                try {
                    let res = await postConfig();

                    // 401 = token required/wrong: prompt and retry once.
                    // (403 means tokens are disabled server-side or the
                    // request was cross-origin — prompting won't help.)
                    if (res.status === 401) {
                        sessionStorage.removeItem('webAdminToken');
                        const entered = window.prompt(
                            'Admin token required to change the mining configuration\n' +
                            '(the value passed to bitcoinpr via --webadmintoken):');
                        if (entered) {
                            sessionStorage.setItem('webAdminToken', entered.trim());
                            res = await postConfig();
                        }
                    }

                    if (res.ok) {
                        if (statusEl) {
                            statusEl.className = 'config-save-status success';
                            statusEl.textContent = 'Saved ✓ — changes applied live';
                        }
                    } else {
                        let errMsg = 'Save failed (' + res.status + ')';
                        try {
                            const body = await res.json();
                            if (body && body.error) errMsg = body.error;
                        } catch (_) { /* ignore parse error */ }
                        if (statusEl) {
                            statusEl.className = 'config-save-status error';
                            statusEl.textContent = errMsg;
                        }
                    }
                } catch (err) {
                    if (statusEl) {
                        statusEl.className = 'config-save-status error';
                        statusEl.textContent = 'Network error: ' + err.message;
                    }
                } finally {
                    if (saveBtn) saveBtn.disabled = false;
                }
            });
        } catch (err) {
            showError('Mining Unavailable', 'Could not load mining configuration. ' + err.message);
        }
    }

    /* -- Info (node overview + peers) -- */

    /* One labeled progress bar: "label  12,345 / 900,000 (1.4%)". */
    function progressRow(label, value, target) {
        const pct = target > 0 ? Math.min(100, (value / target) * 100) : 0;
        const done = target > 0 && value >= target;
        return `
            <div class="progress-row">
                <div class="progress-head">
                    <span class="progress-label">${escapeHtml(label)}</span>
                    <span class="progress-nums mono">${formatNumber(value)} / ${formatNumber(target)}
                        <span class="progress-pct ${done ? 'done' : ''}">${pct.toFixed(pct >= 99.95 && !done ? 2 : 1)}%</span>
                    </span>
                </div>
                <div class="progress-track">
                    <div class="progress-fill ${done ? 'done' : ''}" style="width:${pct.toFixed(2)}%"></div>
                </div>
            </div>`;
    }

    const STORAGE_LABELS = {
        blocks: 'Block Files',
        utxo: 'UTXO Set (chainstate)',
        headers: 'Header Index',
        txindex: 'Transaction Index',
        index: 'Address Index',
        other: 'Other Files',
    };

    async function renderInfo() {
        showLoading('Loading node info…');
        try {
            const [info, peersData] = await Promise.all([api('info'), api('peers')]);
            const peers = (peersData && peersData.peers) || [];

            const headerTip = info.header_tip || 0;
            const behind = Math.max(0, headerTip - info.blocks_verified);
            const synced = !info.is_ibd && behind <= 1;
            const tipAge = info.tip_time
                ? formatUptime(Math.max(0, Math.floor(Date.now() / 1000) - info.tip_time))
                : null;

            /* Sync / index progress bars. */
            let bars = progressRow('Blocks Verified', info.blocks_verified, headerTip);
            if (info.txindex_height != null) {
                bars += progressRow('Transaction Index', info.txindex_height, headerTip);
            }
            if (info.addrindex_height != null) {
                bars += progressRow('Address Index', info.addrindex_height, headerTip);
            }

            /* Storage breakdown. */
            const storage = info.storage || [];
            const storageTotal = info.storage_total_bytes || 0;
            let storageRows = '';
            for (const s of storage) {
                const pct = storageTotal > 0 ? (s.bytes / storageTotal) * 100 : 0;
                storageRows += `
                    <tr>
                        <td>${escapeHtml(STORAGE_LABELS[s.name] || s.name)}</td>
                        <td class="mono">${escapeHtml(s.name)}/</td>
                        <td class="mono text-right">${formatBytes(s.bytes)}</td>
                        <td class="mono text-right">${pct.toFixed(1)}%</td>
                    </tr>`;
            }

            /* Services. */
            let serviceRows = '';
            for (const s of (info.services || [])) {
                serviceRows += `
                    <tr>
                        <td>${escapeHtml(s.name)}</td>
                        <td class="mono">${s.port != null ? s.port : '—'}</td>
                        <td>${s.enabled
                            ? '<span class="status-dot green"></span> enabled'
                            : '<span class="status-dot"></span> disabled'}</td>
                    </tr>`;
            }

            /* Peers table (collapsed by default). */
            let peerRows = '';
            for (const p of peers) {
                peerRows += `
                    <tr>
                        <td class="mono">${p.id != null ? p.id : '—'}</td>
                        <td class="mono">${escapeHtml(p.addr || '—')}</td>
                        <td>${escapeHtml(p.network || 'ipv4')}</td>
                        <td class="mono">${p.version != null ? p.version : '—'}</td>
                        <td>${escapeHtml(p.subver || '—')}</td>
                        <td class="mono text-right">${p.synced_height != null ? formatNumber(p.synced_height) : (p.start_height != null ? formatNumber(p.start_height) : '—')}</td>
                    </tr>`;
            }

            setPage(`
                <div class="page-header">
                    <h1>Node Info</h1>
                    <div class="subtitle">BitcoinPR v${escapeHtml(info.node_version || '?')} — ${escapeHtml(info.network || 'mainnet')}</div>
                </div>
                <div class="stats-grid">
                    ${statCard('Sync Status', synced
                        ? '<span class="status-dot green pulse"></span> Synced'
                        : '<span class="status-dot amber pulse"></span> Syncing',
                        synced ? 'green' : 'amber',
                        synced ? (tipAge ? 'tip ' + escapeHtml(tipAge) + ' ago' : '') : formatNumber(behind) + ' blocks behind')}
                    ${statCard('Header Tip', formatNumber(headerTip), 'accent')}
                    ${statCard('Blocks Verified', formatNumber(info.blocks_verified), 'accent', tipAge && !synced ? 'chain time ' + escapeHtml(tipAge) + ' ago' : '')}
                    ${statCard('Uptime', formatUptime(info.uptime_secs), 'green')}
                    ${statCard('Connected Peers', formatNumber(info.peer_count), 'blue')}
                    ${statCard('Storage Used', formatBytes(info.storage_total_bytes), '', info.datadir ? escapeHtml(info.datadir) : '')}
                </div>
                <div class="detail-card">
                    <div class="detail-title">Sync Progress</div>
                    <div class="progress-group">${bars}</div>
                </div>
                <div class="info-grid">
                    <div class="table-wrapper">
                        <div class="table-title">Storage</div>
                        ${storage.length > 0 ? `
                        <table>
                            <thead>
                                <tr>
                                    <th>Component</th>
                                    <th>Directory</th>
                                    <th class="text-right">Size</th>
                                    <th class="text-right">Share</th>
                                </tr>
                            </thead>
                            <tbody>${storageRows}</tbody>
                        </table>` : '<div class="empty-state">Storage information unavailable</div>'}
                    </div>
                    <div class="table-wrapper">
                        <div class="table-title">Services</div>
                        <table>
                            <thead>
                                <tr>
                                    <th>Service</th>
                                    <th>Port</th>
                                    <th>Status</th>
                                </tr>
                            </thead>
                            <tbody>${serviceRows}</tbody>
                        </table>
                    </div>
                </div>
                <details class="collapse-section">
                    <summary class="table-title">
                        <span class="collapse-arrow" aria-hidden="true">▸</span>
                        Connected Peers
                        <span class="badge">${peers.length}</span>
                    </summary>
                    ${peers.length > 0 ? `
                    <table>
                        <thead>
                            <tr>
                                <th>ID</th>
                                <th>Address</th>
                                <th>Net</th>
                                <th>Protocol</th>
                                <th>User Agent</th>
                                <th class="text-right">Block Height</th>
                            </tr>
                        </thead>
                        <tbody>${peerRows}</tbody>
                    </table>` : '<div class="empty-state">No peers connected</div>'}
                </details>`);
        } catch (err) {
            showError('Info Error', 'Could not load node info. ' + err.message);
        }
    }

    /* -- 404 -- */

    function renderNotFound() {
        setPage(`
            <div class="error-state">
                <div class="error-icon">?</div>
                <h2>404 — Page Not Found</h2>
                <p>The page you're looking for doesn't exist.</p>
                <a class="btn" href="#/">Back to Dashboard</a>
            </div>`);
    }

    /* ---- Search ---- */

    async function handleSearch(query) {
        if (!query || !query.trim()) return;
        query = query.trim();

        try {
            const result = await api('search/' + encodeURIComponent(query));
            switch (result.type) {
                case 'block':
                    navigate('/block/' + (result.hash || result.height || query));
                    break;
                case 'tx':
                    navigate('/tx/' + (result.txid || query));
                    break;
                case 'address':
                    navigate('/address/' + (result.address || query));
                    break;
                default:
                    showToast('No results found for "' + query + '"', 'error');
                    break;
            }
        } catch (err) {
            if (/^\d+$/.test(query)) {
                navigate('/block/' + query);
            } else if (query.length === 64) {
                navigate(/^[0-9a-fA-F]+$/.test(query) ? '/tx/' + query : '/block/' + query);
            } else if (query.startsWith('bc1') || query.startsWith('1') || query.startsWith('3') || query.startsWith('tb1')) {
                navigate('/address/' + query);
            } else {
                showToast('Search failed: ' + err.message, 'error');
            }
        }
    }

    /* ---- Init ---- */

    function init() {
        window.addEventListener('hashchange', router);

        document.getElementById('search-form').addEventListener('submit', function (e) {
            e.preventDefault();
            const input = document.getElementById('search-input');
            handleSearch(input.value);
            input.value = '';
            input.blur();
        });

        var hamburger = document.getElementById('hamburger-btn');
        var mobileMenu = document.getElementById('mobile-menu');
        hamburger.addEventListener('click', function () {
            hamburger.classList.toggle('open');
            mobileMenu.classList.toggle('open');
        });

        mobileMenu.addEventListener('click', function (e) {
            if (e.target.classList.contains('mobile-link')) {
                hamburger.classList.remove('open');
                mobileMenu.classList.remove('open');
            }
        });

        if (!location.hash || location.hash === '#') {
            location.hash = '#/';
        }

        router();
        initWebSocket();
    }

    /* ---- Expose globals for mining.js ---- */

    window.BitcoinPR = {
        api: api,
        formatBtc: formatBtc,
        formatHashrate: formatHashrate,
        formatTime: formatTime,
        formatTimeShort: formatTimeShort,
        formatNumber: formatNumber,
        formatDifficulty: formatDifficulty,
        formatUptime: formatUptime,
        escapeHtml: escapeHtml,
        showToast: showToast,
        navigate: navigate,
        wsConnection: function () { return wsConnection; }
    };

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
