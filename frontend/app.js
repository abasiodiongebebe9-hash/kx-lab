/* Key Exchange Lab: front end (plain JavaScript, no libraries).
   All text from the server is inserted with textContent, never innerHTML, so it cannot inject markup. */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  var token = sessionStorage.getItem('kx_token');
  var user = null;
  try { user = JSON.parse(sessionStorage.getItem('kx_user') || 'null'); } catch (e) { user = null; }
  var timers = [];

  // ---------------------------------------------------------------- helpers
  function el(tag, cls, text) {
    var node = document.createElement(tag);
    if (cls) { node.className = cls; }
    if (text !== undefined && text !== null) { node.textContent = text; }
    return node;
  }

  function api(path, options) {
    options = options || {};
    var headers = { 'Content-Type': 'application/json' };
    if (token) { headers.Authorization = 'Bearer ' + token; }
    return fetch(path, { method: options.method || 'GET', headers: headers, body: options.body })
      .then(function (res) {
        return res.json().catch(function () { return null; }).then(function (data) {
          if (res.status === 401 && token) {
            logout();
            throw new Error('Your session has expired, please log in again.');
          }
          if (!res.ok) { throw new Error((data && data.error) || ('Request failed (' + res.status + ')')); }
          return data;
        });
      });
  }

  function post(path, obj) { return api(path, { method: 'POST', body: JSON.stringify(obj) }); }
  function yesNo(v) { return v === null || v === undefined ? 'n/a' : (v ? 'Yes' : 'No'); }
  function fmtMs(v) { return v === null || v === undefined ? 'n/a' : Number(v).toFixed(3); }
  function actorLabel(a) { return a.charAt(0).toUpperCase() + a.slice(1); }
  function clear(node) { while (node.firstChild) { node.removeChild(node.firstChild); } }
  function clearTimers() { timers.forEach(clearTimeout); timers = []; }

  // ---------------------------------------------------------------- views
  var VIEWS = ['auth', 'sim', 'dash', 'admin'];
  function showView(name) {
    VIEWS.forEach(function (v) { $('view-' + v).classList.toggle('hidden', v !== name); });
    document.querySelectorAll('.nav-btn').forEach(function (b) {
      b.classList.toggle('active', b.getAttribute('data-view') === name);
    });
    if (name === 'dash') { loadDashboard(); }
    if (name === 'admin') { loadAdmin(); }
  }

  function setSignedIn(signedIn) {
    $('nav').classList.toggle('hidden', !signedIn);
    if (signedIn) {
      $('whoami').textContent = user.username + ' (' + user.role + ')';
      $('nav-admin').classList.toggle('hidden', user.role !== 'admin');
    }
  }

  function logout() {
    token = null; user = null;
    sessionStorage.removeItem('kx_token'); sessionStorage.removeItem('kx_user');
    clearTimers();
    setSignedIn(false);
    selectTab('login');
    showView('auth');
  }

  // ---------------------------------------------------------------- auth
  function selectTab(which) {
    $('tab-login').classList.toggle('active', which === 'login');
    $('tab-register').classList.toggle('active', which === 'register');
    $('form-login').classList.toggle('hidden', which !== 'login');
    $('form-register').classList.toggle('hidden', which !== 'register');
    $('auth-error').textContent = '';
  }
  $('tab-login').addEventListener('click', function () { selectTab('login'); });
  $('tab-register').addEventListener('click', function () { selectTab('register'); });

  function afterLogin(data) {
    token = data.token; user = data.user;
    sessionStorage.setItem('kx_token', token);
    sessionStorage.setItem('kx_user', JSON.stringify(user));
    setSignedIn(true);
    loadProtocols();
    showView('sim');
  }

  $('form-login').addEventListener('submit', function (e) {
    e.preventDefault();
    $('auth-error').textContent = '';
    post('/api/auth/login', { username: $('login-username').value, password: $('login-password').value })
      .then(afterLogin)
      .catch(function (err) { $('auth-error').textContent = err.message; });
  });

  $('form-register').addEventListener('submit', function (e) {
    e.preventDefault();
    $('auth-error').textContent = '';
    var creds = { username: $('reg-username').value, email: $('reg-email').value, password: $('reg-password').value };
    post('/api/auth/register', creds)
      .then(function () { return post('/api/auth/login', { username: creds.username, password: creds.password }); })
      .then(afterLogin)
      .catch(function (err) { $('auth-error').textContent = err.message; });
  });

  $('logout').addEventListener('click', logout);
  document.querySelectorAll('.nav-btn').forEach(function (b) {
    b.addEventListener('click', function () { showView(b.getAttribute('data-view')); });
  });

  // ---------------------------------------------------------------- simulation
  var protocolInfo = {};
  function loadProtocols() {
    api('/api/protocols').then(function (list) {
      var sel = $('protocol');
      clear(sel);
      list.forEach(function (p) {
        protocolInfo[p.name] = p.description;
        var o = el('option', null, p.name); o.value = p.name; sel.appendChild(o);
      });
      showProtocolNote();
    }).catch(function () {});
  }
  function showProtocolNote() { $('protocol-note').textContent = protocolInfo[$('protocol').value] || ''; }
  $('protocol').addEventListener('change', showProtocolNote);

  function resetSim() {
    clearTimers();
    clear($('timeline'));
    $('timeline').appendChild(el('li', 'placeholder', 'Running...'));
    $('verdict').className = 'verdict neutral';
    $('verdict').textContent = 'Running...';
    $('fp-alice').textContent = 'No key yet';
    $('fp-bob').textContent = 'No key yet';
    $('fp-mallory').textContent = 'Not active';
    $('card-mallory').classList.add('dim');
    clear($('metrics').querySelector('tbody'));
  }

  function renderStep(s) {
    var li = el('li', 'step actor-' + s.actor + (s.warning ? ' warn' : ''));
    li.appendChild(el('span', 'badge', actorLabel(s.actor)));
    li.appendChild(el('span', 'note', s.note));
    li.appendChild(el('span', 'ms', s.elapsed_ms === null || s.elapsed_ms === undefined ? '' : fmtMs(s.elapsed_ms) + ' ms'));
    if (s.value_hex) { li.appendChild(el('code', 'value', s.value_hex)); }
    return li;
  }

  function renderVerdict(r) {
    var box = $('verdict');
    clear(box);
    var main = el('span', null), sub = el('span', 'sub');
    if (r.attack_outcome === 'detected') {
      box.className = 'verdict ok';
      main.textContent = 'Attack detected. The exchange was stopped.';
      sub.textContent = 'A signature check failed, so no key was derived from the tampered value.';
    } else if (r.attack_outcome === 'succeeded') {
      box.className = 'verdict bad';
      main.textContent = 'Attack succeeded. Mallory read the message.';
      sub.textContent = r.keys_match
        ? 'Alice and Bob\'s keys match, yet Mallory holds a copy of that key. Matching keys do not prove safety.'
        : 'Alice and Bob ended up with different keys, each shared with Mallory. Neither saw an error.';
    } else {
      box.className = 'verdict ok';
      main.textContent = 'Honest exchange. Alice and Bob share the same key.';
      sub.textContent = 'Bob decrypted: "' + r.bob_read + '"';
    }
    box.appendChild(main); box.appendChild(sub);
    if (r.mallory_read) {
      box.appendChild(el('span', 'sub', 'Mallory read: "' + r.mallory_read + '"'));
    }
  }

  function renderMetrics(r) {
    var body = $('metrics').querySelector('tbody');
    clear(body);
    var m = r.metrics || {};
    var rows = [
      ['Keys match', yesNo(r.keys_match)],
      ['Mallory knows a key', yesNo(r.mallory_knows_key)],
      ['Key generation (one key pair)', m.keygen_ms === undefined ? 'n/a' : fmtMs(m.keygen_ms) + ' ms'],
      ['Shared secret', m.secret_ms === undefined ? 'n/a' : fmtMs(m.secret_ms) + ' ms'],
      ['Whole exchange', fmtMs(m.total_ms) + ' ms'],
      ['Message 1', m.first_message_bytes + ' bytes'],
      ['Message 2', m.second_message_bytes + ' bytes'],
      ['Signatures', m.signature_bytes + ' bytes'],
      ['Total sent', m.bytes_transmitted + ' bytes']
    ];
    rows.forEach(function (row) {
      var tr = el('tr');
      tr.appendChild(el('th', null, row[0])); tr.appendChild(el('td', null, row[1]));
      body.appendChild(tr);
    });
  }

  function updateFingerprints(r, upToStep) {
    // reveal key fingerprints only once the key-derivation step has been shown
    var f = r.fingerprints || {};
    var reached = r.steps.slice(0, upToStep).some(function (s) { return s.action === 'derive_key'; });
    if (!reached) { return; }
    $('fp-alice').textContent = f.alice || 'No key';
    $('fp-bob').textContent = f.bob || 'No key';
    if (r.mitm && r.mallory_knows_key) {
      $('card-mallory').classList.remove('dim');
      $('fp-mallory').textContent = f.mallory
        ? 'Same key: ' + f.mallory
        : 'With Alice: ' + f.mallory_with_alice + '  With Bob: ' + f.mallory_with_bob;
    }
  }

  function playResult(r, delay) {
    clearTimers();
    var list = $('timeline');
    clear(list);
    if (r.mitm) { $('card-mallory').classList.remove('dim'); $('fp-mallory').textContent = 'Active'; }
    var finish = function () { renderVerdict(r); renderMetrics(r); updateFingerprints(r, r.steps.length); };
    if (!delay) {
      r.steps.forEach(function (s) { list.appendChild(renderStep(s)); });
      finish();
      return;
    }
    r.steps.forEach(function (s, i) {
      timers.push(setTimeout(function () {
        list.appendChild(renderStep(s));
        updateFingerprints(r, i + 1);
        if (i === r.steps.length - 1) { finish(); }
      }, delay * (i + 1)));
    });
  }

  $('run').addEventListener('click', function () {
    var btn = $('run');
    $('sim-error').textContent = '';
    resetSim();
    btn.disabled = true;
    post('/api/exchanges', {
      protocol: $('protocol').value,
      mitm: $('opt-mitm').checked,
      signatures: $('opt-sign').checked,
      message: $('message').value
    }).then(function (result) {
      playResult(result, parseInt($('speed').value, 10));
    }).catch(function (err) {
      $('sim-error').textContent = err.message;
      clear($('timeline'));
      $('timeline').appendChild(el('li', 'placeholder', 'No exchange was run.'));
      $('verdict').className = 'verdict neutral';
      $('verdict').textContent = 'Nothing run yet.';
    }).then(function () { btn.disabled = false; });
  });

  function replaySession(id) {
    api('/api/exchanges/' + encodeURIComponent(id)).then(function (s) {
      var result = {
        protocol: s.protocol, mitm: !!s.mitm_enabled, signatures: !!s.auth_enabled,
        steps: s.steps, fingerprints: s.fingerprints || {}, attack_outcome: s.attack_outcome,
        keys_match: s.keys_match === null ? null : !!s.keys_match, mallory_knows_key: !!s.mallory_knows_key,
        bob_read: s.bob_read, mallory_read: s.mallory_read,
        metrics: {
          keygen_ms: s.benchmark ? s.benchmark.keygen_ms : undefined,
          secret_ms: s.benchmark ? s.benchmark.secret_ms : undefined,
          total_ms: s.benchmark ? s.benchmark.total_ms : undefined,
          first_message_bytes: s.benchmark ? s.benchmark.public_bytes : 0,
          second_message_bytes: 0, signature_bytes: 0,
          bytes_transmitted: s.benchmark ? s.benchmark.bytes_transmitted : 0
        }
      };
      showView('sim');
      $('protocol').value = s.protocol; showProtocolNote();
      $('opt-mitm').checked = result.mitm; $('opt-sign').checked = result.signatures;
      playResult(result, 0);
    }).catch(function (err) { alert(err.message); });
  }

  // ---------------------------------------------------------------- dashboard
  function tag(outcome) { return el('span', 'tag ' + outcome, outcome); }

  function sessionRow(s, withUser) {
    var tr = el('tr');
    tr.appendChild(el('td', null, s.created_at));
    if (withUser) { tr.appendChild(el('td', null, s.username)); }
    tr.appendChild(el('td', null, s.protocol));
    tr.appendChild(el('td', null, s.mitm_enabled ? 'On' : 'Off'));
    tr.appendChild(el('td', null, s.auth_enabled ? 'On' : 'Off'));
    var td = el('td'); td.appendChild(tag(s.attack_outcome)); tr.appendChild(td);
    if (!withUser) {
      tr.appendChild(el('td', null, yesNo(s.keys_match === null ? null : !!s.keys_match)));
      tr.appendChild(el('td', null, fmtMs(s.total_ms)));
      tr.appendChild(el('td', null, s.bytes_transmitted === null ? 'n/a' : String(s.bytes_transmitted)));
      var last = el('td'), b = el('button', 'link-btn', 'Replay');
      b.addEventListener('click', function () { replaySession(s.session_id); });
      last.appendChild(b); tr.appendChild(last);
    }
    return tr;
  }

  function bars(container, rows, valueKey, log, unit) {
    clear(container);
    if (!rows.length) { container.appendChild(el('p', 'muted small', 'No benchmark yet.')); return; }
    rows.forEach(function (r) {
      var v = r[valueKey];
      var pct;
      if (log) { pct = (Math.log10(Math.max(v, 0.001)) + 2) / 5 * 100; }   // 0.01 ms .. 1000 ms
      else { pct = v / Math.max.apply(null, rows.map(function (x) { return x[valueKey]; })) * 100; }
      pct = Math.min(100, Math.max(1, pct)) * 0.74;   // leave room for the value label
      var row = el('div', 'bar-row');
      row.appendChild(el('span', null, r.protocol));
      var track = el('div', 'bar-track'), fill = el('div', 'bar-fill');
      fill.style.width = pct + '%';
      track.appendChild(fill);
      track.appendChild(el('span', 'bar-val', v + ' ' + unit));
      row.appendChild(track);
      container.appendChild(row);
    });
  }

  function renderBenchmarks(rows) {
    var body = $('bench-table').querySelector('tbody');
    clear(body);
    rows.forEach(function (r) {
      var tr = el('tr');
      [r.protocol, r.keygen_ms_median, r.secret_ms_median, r.first_message_bytes,
       r.second_message_bytes, r.total_bytes, r.runs].forEach(function (v) { tr.appendChild(el('td', null, String(v))); });
      body.appendChild(tr);
    });
    bars($('chart-keygen'), rows, 'keygen_ms_median', true, 'ms');
    bars($('chart-secret'), rows, 'secret_ms_median', true, 'ms');
    bars($('chart-bytes'), rows, 'total_bytes', false, 'B');
    $('bench-machine').textContent = rows.length && rows[0].machine ? 'Measured on: ' + rows[0].machine : '';
  }

  function loadDashboard() {
    api('/api/exchanges').then(function (d) {
      $('stat-total').textContent = d.stats.total;
      $('stat-succ').textContent = d.stats.attacks_succeeded;
      $('stat-det').textContent = d.stats.attacks_detected;
      var body = $('sessions-table').querySelector('tbody');
      clear(body);
      d.sessions.forEach(function (s) { body.appendChild(sessionRow(s, false)); });
    }).catch(function () {});
    api('/api/benchmarks/latest').then(renderBenchmarks).catch(function () {});
  }

  $('bench-run').addEventListener('click', function () {
    var btn = $('bench-run');
    $('bench-error').textContent = '';
    $('bench-status').textContent = 'Running, please wait (RSA key generation is slow)...';
    btn.disabled = true;
    post('/api/benchmarks/run', { runs: parseInt($('bench-runs').value, 10) })
      .then(function () { $('bench-status').textContent = 'Done.'; return api('/api/benchmarks/latest'); })
      .then(renderBenchmarks)
      .catch(function (err) { $('bench-error').textContent = err.message; $('bench-status').textContent = ''; })
      .then(function () { btn.disabled = false; });
  });

  // ---------------------------------------------------------------- admin
  function loadAdmin() {
    api('/api/admin/users').then(function (users) {
      var body = $('admin-users').querySelector('tbody');
      clear(body);
      users.forEach(function (u) {
        var tr = el('tr');
        [u.username, u.email, u.role, u.sessions, u.created_at].forEach(function (v) { tr.appendChild(el('td', null, String(v))); });
        body.appendChild(tr);
      });
    }).catch(function () {});
    api('/api/admin/sessions').then(function (sessions) {
      var body = $('admin-sessions').querySelector('tbody');
      clear(body);
      sessions.forEach(function (s) { body.appendChild(sessionRow(s, true)); });
    }).catch(function () {});
  }

  // ---------------------------------------------------------------- start
  if (token && user) {
    setSignedIn(true);
    loadProtocols();
    showView('sim');
  } else {
    showView('auth');
  }
})();
