/* ============================================================
   BitcoinPR Mining Dashboard — Dedicated WebSocket Logic
   Handles real-time updates for the mining page.
   ============================================================ */

(function () {
    'use strict';

    var miningWs = null;
    var miningWsTimer = null;
    var miningWsDelay = 1000;
    var miningActive = false;
    var MAX_SHARE_ROWS = 50;

    /* ---- WebSocket Management ---- */

    function initMiningWebSocket() {
        miningActive = true;

        if (miningWs && miningWs.readyState <= 1) return;

        var proto = location.protocol === 'https:' ? 'wss:' : 'ws:';
        var url = proto + '//' + location.host + '/ws';

        try {
            miningWs = new WebSocket(url);
        } catch (e) {
            console.warn('[mining] WebSocket connection failed:', e);
            scheduleMiningReconnect();
            return;
        }

        miningWs.onopen = function () {
            miningWsDelay = 1000;
            console.log('[mining] WebSocket connected');
        };

        miningWs.onmessage = function (evt) {
            if (!miningActive) return;
            try {
                var msg = JSON.parse(evt.data);
                handleMiningMessage(msg);
            } catch (e) {
                // ignore malformed messages
            }
        };

        miningWs.onclose = function () {
            if (miningActive) {
                console.log('[mining] WebSocket closed, reconnecting…');
                scheduleMiningReconnect();
            }
        };

        miningWs.onerror = function () {
            if (miningWs) miningWs.close();
        };
    }

    function scheduleMiningReconnect() {
        if (miningWsTimer || !miningActive) return;
        miningWsTimer = setTimeout(function () {
            miningWsTimer = null;
            if (miningActive) initMiningWebSocket();
        }, miningWsDelay);
        miningWsDelay = Math.min(miningWsDelay * 2, 30000);
    }

    function stopMiningWebSocket() {
        miningActive = false;
        if (miningWsTimer) {
            clearTimeout(miningWsTimer);
            miningWsTimer = null;
        }
        if (miningWs) {
            miningWs.onclose = null;
            miningWs.close();
            miningWs = null;
        }
    }

    function handleMiningMessage(msg) {
        switch (msg.type) {
            case 'MiningStats':
                onMiningStatsUpdate(msg);
                break;
            case 'MiningShare':
                onMiningShareUpdate(msg);
                break;
            case 'DatumConnected':
                onDatumConnected(msg);
                break;
            case 'DatumDisconnected':
                onDatumDisconnected(msg);
                break;
            case 'DatumShareSubmitted':
                onDatumShareSubmitted(msg);
                break;
            case 'DatumPayout':
                onDatumPayout(msg);
                break;
        }
    }

    /* ---- Datum Pool Live Updates ---- */

    function onDatumConnected(msg) {
        var badge = document.getElementById('datum-conn-badge');
        if (badge) {
            badge.className = 'status-badge running';
            badge.innerHTML = '<span class="status-dot green pulse"></span>Connected';
        }
        if (msg.pool_name != null) {
            var nameEl = document.getElementById('datum-pool-name');
            if (nameEl) nameEl.textContent = msg.pool_name;
        }
    }

    function onDatumDisconnected(msg) {
        var badge = document.getElementById('datum-conn-badge');
        if (badge) {
            badge.className = 'status-badge stopped';
            var label = msg.reason ? 'Disconnected (' + msg.reason + ')' : 'Disconnected';
            badge.innerHTML = '<span class="status-dot red"></span>' + fmt().escapeHtml(label);
        }
    }

    function onDatumShareSubmitted(msg) {
        var submittedEl = document.getElementById('datum-shares-submitted');
        var acceptedEl = document.getElementById('datum-shares-accepted');
        if (!submittedEl && !acceptedEl) return;

        var f = fmt();
        var submitted = 0;
        if (submittedEl) {
            submitted = (parseInt(submittedEl.textContent.replace(/,/g, ''), 10) || 0) + 1;
            submittedEl.textContent = f.formatNumber(submitted);
        }
        var accepted = acceptedEl ? (parseInt(acceptedEl.textContent.replace(/,/g, ''), 10) || 0) : 0;
        if (msg.accepted !== false && acceptedEl) {
            accepted += 1;
            acceptedEl.textContent = f.formatNumber(accepted);
        }

        var rateEl = document.getElementById('datum-accept-rate');
        if (rateEl) {
            var rate = submitted > 0 ? (accepted / submitted * 100) : 0;
            rateEl.textContent = rate.toFixed(1) + '%';
        }
    }

    function onDatumPayout(msg) {
        var lineEl = document.getElementById('datum-payout-line');
        if (!lineEl) return;

        var f = fmt();
        var html = '';
        if (msg.txid) {
            html += '<a href="#/tx/' + encodeURIComponent(msg.txid) + '" class="mono">' +
                f.escapeHtml(truncate(msg.txid)) + '</a>';
        }
        if (msg.amount != null) {
            html += (html ? ' · ' : '') + f.formatBtc(msg.amount);
        }
        lineEl.innerHTML = html || '—';
    }

    function truncate(hash) {
        if (!hash) return '—';
        if (hash.length <= 19) return hash;
        return hash.slice(0, 8) + '…' + hash.slice(-8);
    }

    /* ---- Stats Update ---- */

    function onMiningStatsUpdate(msg) {
        if (msg.hashrate != null) {
            updateHashrateDisplay(msg.hashrate, msg.hashrate_unit);
        }
        if (msg.shares_accepted != null || msg.shares_rejected != null) {
            updateShareCounters(msg.shares_accepted, msg.shares_rejected);
        }
        if (msg.workers) {
            updateWorkerTable(msg.workers);
        }
        if (msg.connected_workers != null) {
            var el = document.getElementById('mining-workers-count');
            if (el) el.textContent = fmt().formatNumber(msg.connected_workers);
        }
    }

    /* ---- Hashrate Display ---- */

    function updateHashrateDisplay(hashrate, unit) {
        var valueEl = document.getElementById('mining-hashrate-value');
        var unitEl = document.getElementById('mining-hashrate-unit');
        if (!valueEl || !unitEl) return;

        valueEl.style.opacity = '0.5';
        setTimeout(function () {
            valueEl.textContent = Number(hashrate).toFixed(2);
            unitEl.textContent = unit || 'H/s';
            valueEl.style.opacity = '1';
        }, 150);
    }

    /* ---- Share Counters ---- */

    function updateShareCounters(accepted, rejected) {
        var acceptedEl = document.getElementById('mining-accepted');
        var rejectedEl = document.getElementById('mining-rejected');
        var rateEl = document.getElementById('mining-accept-rate');
        var fillEl = document.getElementById('mining-accept-fill');

        if (acceptedEl && accepted != null) {
            acceptedEl.textContent = fmt().formatNumber(accepted);
        }
        if (rejectedEl && rejected != null) {
            rejectedEl.textContent = fmt().formatNumber(rejected);
        }

        if (rateEl && fillEl && accepted != null && rejected != null) {
            var total = (accepted || 0) + (rejected || 0);
            var rate = total > 0 ? ((accepted || 0) / total * 100) : 100;
            rateEl.textContent = rate.toFixed(1) + '%';
            fillEl.style.width = rate.toFixed(1) + '%';
        }
    }

    /* ---- Worker Table ---- */

    function updateWorkerTable(workers) {
        var container = document.getElementById('mining-workers-table');
        if (!container) return;

        var f = fmt();
        if (!workers || workers.length === 0) {
            container.innerHTML =
                '<div class="table-title">Workers <span class="badge">0</span></div>' +
                '<div class="empty-state">No workers connected</div>';
            return;
        }

        var rows = '';
        for (var i = 0; i < workers.length; i++) {
            var w = workers[i];
            rows +=
                '<tr>' +
                '<td class="mono">' + f.escapeHtml(w.name || '—') + '</td>' +
                '<td class="mono">' + f.formatHashrate(w.hashrate) + '</td>' +
                '<td class="mono share-accepted">' + f.formatNumber(w.shares_accepted) + '</td>' +
                '<td class="mono share-rejected">' + f.formatNumber(w.shares_rejected) + '</td>' +
                '<td>' + f.formatTime(w.last_share_time) + '</td>' +
                '</tr>';
        }

        container.innerHTML =
            '<div class="table-title">Workers <span class="badge">' + workers.length + '</span></div>' +
            '<table>' +
            '<thead><tr>' +
            '<th>Name</th><th>Hashrate</th><th>Accepted</th><th>Rejected</th><th>Last Share</th>' +
            '</tr></thead>' +
            '<tbody>' + rows + '</tbody>' +
            '</table>';
    }

    /* ---- Share History ---- */

    function onMiningShareUpdate(share) {
        addShareToHistory(share);

        var acceptedEl = document.getElementById('mining-accepted');
        var rejectedEl = document.getElementById('mining-rejected');
        if (share.accepted !== false) {
            if (acceptedEl) {
                var cur = parseInt(acceptedEl.textContent.replace(/,/g, ''), 10) || 0;
                acceptedEl.textContent = fmt().formatNumber(cur + 1);
            }
        } else {
            if (rejectedEl) {
                var curR = parseInt(rejectedEl.textContent.replace(/,/g, ''), 10) || 0;
                rejectedEl.textContent = fmt().formatNumber(curR + 1);
            }
        }

        recalcAcceptanceRate();
    }

    function addShareToHistory(share) {
        var tbody = document.getElementById('mining-shares-tbody');
        if (!tbody) {
            ensureSharesTable();
            tbody = document.getElementById('mining-shares-tbody');
            if (!tbody) return;
        }

        var f = fmt();
        var accepted = share.accepted !== false;
        var row = document.createElement('tr');
        row.style.animation = 'fadeIn 300ms ease';
        row.innerHTML =
            '<td class="mono">' + f.escapeHtml(share.worker || '—') + '</td>' +
            '<td>' + f.formatTimeShort(share.timestamp || (Date.now() / 1000)) + '</td>' +
            '<td class="mono">' + (share.difficulty != null ? f.formatNumber(share.difficulty) : '—') + '</td>' +
            '<td class="text-center">' +
            (accepted
                ? '<span class="share-accepted">✓</span>'
                : '<span class="share-rejected">✗</span>') +
            '</td>';

        tbody.insertBefore(row, tbody.firstChild);

        while (tbody.children.length > MAX_SHARE_ROWS) {
            tbody.removeChild(tbody.lastChild);
        }

        var wrapper = document.getElementById('mining-shares-table');
        if (wrapper) {
            var badge = wrapper.querySelector('.badge');
            if (badge) {
                badge.textContent = Math.min(tbody.children.length, MAX_SHARE_ROWS);
            }
        }
    }

    function ensureSharesTable() {
        var container = document.getElementById('mining-shares-table');
        if (!container) return;

        if (!container.querySelector('table')) {
            container.innerHTML =
                '<div class="table-title">Recent Shares <span class="badge">0</span></div>' +
                '<table>' +
                '<thead><tr>' +
                '<th>Worker</th><th>Time</th><th>Difficulty</th><th class="text-center">Status</th>' +
                '</tr></thead>' +
                '<tbody id="mining-shares-tbody"></tbody>' +
                '</table>';
        }
    }

    function recalcAcceptanceRate() {
        var acceptedEl = document.getElementById('mining-accepted');
        var rejectedEl = document.getElementById('mining-rejected');
        var rateEl = document.getElementById('mining-accept-rate');
        var fillEl = document.getElementById('mining-accept-fill');
        if (!acceptedEl || !rejectedEl || !rateEl || !fillEl) return;

        var accepted = parseInt(acceptedEl.textContent.replace(/,/g, ''), 10) || 0;
        var rejected = parseInt(rejectedEl.textContent.replace(/,/g, ''), 10) || 0;
        var total = accepted + rejected;
        var rate = total > 0 ? (accepted / total * 100) : 100;
        rateEl.textContent = rate.toFixed(1) + '%';
        fillEl.style.width = rate.toFixed(1) + '%';
    }

    /* ---- Formatter accessor ---- */

    function fmt() {
        return window.BitcoinPR || {
            formatNumber: function (n) { return n != null ? Number(n).toLocaleString('en-US') : '—'; },
            formatHashrate: function (h) { return h != null ? Number(h).toFixed(2) + ' H/s' : '—'; },
            formatTime: function (t) { return t ? new Date(t * 1000).toLocaleString() : '—'; },
            formatTimeShort: function (t) {
                return t ? new Date(t * 1000).toLocaleTimeString('en-US', {
                    hour: '2-digit', minute: '2-digit', second: '2-digit'
                }) : '—';
            },
            formatDifficulty: function (d) { return d != null ? String(d) : '—'; },
            escapeHtml: function (s) { var d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
        };
    }

    /* ---- Navigation-aware cleanup ---- */

    window.addEventListener('hashchange', function () {
        var hash = location.hash.slice(1) || '/';
        if (hash !== '/mining') {
            stopMiningWebSocket();
        }
    });

    /* ---- Global hooks for app.js WebSocket dispatch ---- */

    window.onMiningShare = function (msg) {
        if (!miningActive) return;
        onMiningShareUpdate(msg);
    };

    window.onMiningStats = function (msg) {
        if (!miningActive) return;
        onMiningStatsUpdate(msg);
    };

    // Datum events are routed from the always-on app.js socket. They update the
    // DOM only when the Datum cards are present, so no miningActive guard here.
    window.onDatumEvent = function (msg) {
        handleMiningMessage(msg);
    };

    window.initMiningWebSocket = initMiningWebSocket;

})();
