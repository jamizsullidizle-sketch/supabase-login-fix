/* Supabase Auth Email Checker. Runs entirely in the browser.
   Only network calls: public DNS-over-HTTPS (Cloudflare, Google fallback). No trackers, no storage. */
(function () {
  'use strict';

  var DOH = [
    function (n, t) { return 'https://cloudflare-dns.com/dns-query?name=' + encodeURIComponent(n) + '&type=' + t; },
    function (n, t) { return 'https://dns.google/resolve?name=' + encodeURIComponent(n) + '&type=' + t; }
  ];
  var TYPE = { A: 1, CNAME: 5, MX: 15, TXT: 16, AAAA: 28 };

  // Things that look like secrets. We refuse them outright.
  var SECRET_RE = /(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+)|sb_secret_|sb_publishable_|service_role|\bre_[A-Za-z0-9_]{16,}|\bSG\.[A-Za-z0-9_-]{10,}|xkeysib-|xsmtpsib-|\bpassword\b|\bpasswd\b|-----BEGIN/i;

  var DKIM_SELECTORS = [
    ['resend', 'Resend'], ['s1', 'SendGrid'], ['s2', 'SendGrid'], ['google', 'Google Workspace'],
    ['zoho', 'Zoho'], ['zmail', 'Zoho'], ['k1', 'Mailgun / Mailchimp'], ['k2', 'Mailchimp'], ['mx', 'Mailgun'],
    ['smtp', 'Mailgun'], ['pm', 'Postmark'], ['mail', 'Brevo (older)'], ['brevo1', 'Brevo'], ['brevo2', 'Brevo'],
    ['selector1', 'Microsoft 365'], ['selector2', 'Microsoft 365'], ['mandrill', 'Mandrill'],
    ['default', 'generic'], ['dkim', 'generic'], ['sig1', 'iCloud']
  ];

  var SPF_PROVIDERS = [
    [/amazonses\.com/, 'Amazon SES (also used by Resend)'], [/sendgrid\.net/, 'SendGrid'],
    [/mailgun\.org/, 'Mailgun'], [/spf\.brevo\.com|sendinblue\.com/, 'Brevo'], [/_spf\.google\.com/, 'Google Workspace'],
    [/zoho\.(com|eu|in)|zeptomail/, 'Zoho / ZeptoMail'], [/mtasv\.net/, 'Postmark'], [/spf\.protection\.outlook\.com/, 'Microsoft 365'],
    [/mcsv\.net|mandrillapp/, 'Mailchimp / Mandrill'], [/_spf\.resend\.com/, 'Resend']
  ];

  var PREVIEW_HOSTS = /(\.lovable\.app|\.lovableproject\.com|\.vercel\.app|\.netlify\.app|\.bolt\.new|\.bolt\.host|\.replit\.app|\.repl\.co|\.pages\.dev|\.github\.io|\.onrender\.com|\.web\.app|\.firebaseapp\.com|\.base44\.app|\.webcontainer\.io|\.stackblitz\.io|\.hostingersite\.com)$/i;

  function $(id) { return document.getElementById(id); }
  function esc(s) { return String(s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); }

  function txtData(d) { // join "a" "b" chunks and strip quotes
    var m = String(d).match(/"((?:[^"\\]|\\.)*)"/g);
    return m ? m.map(function (x) { return x.slice(1, -1).replace(/\\"/g, '"'); }).join('') : String(d);
  }

  function doh(name, type) {
    var i = 0;
    function attempt() {
      var url = DOH[i](name, type);
      return fetch(url, { headers: { accept: 'application/dns-json' }, referrerPolicy: 'no-referrer', credentials: 'omit' })
        .then(function (r) { if (!r.ok) throw new Error('HTTP ' + r.status); return r.json(); })
        .then(function (j) {
          var want = TYPE[type];
          var all = j.Answer || [];
          return {
            status: j.Status, // 0 NOERROR, 3 NXDOMAIN
            answers: all.filter(function (a) { return a.type === want; }).map(function (a) { return type === 'TXT' ? txtData(a.data) : String(a.data); }),
            cname: all.filter(function (a) { return a.type === 5; }).map(function (a) { return String(a.data); })
          };
        })
        .catch(function (e) { i++; if (i < DOH.length) return attempt(); throw e; });
    }
    return attempt();
  }

  function normDomain(v) {
    v = (v || '').trim().toLowerCase();
    if (v.indexOf('@') >= 0) v = v.split('@').pop();
    v = v.replace(/^[a-z]+:\/\//, '').split(/[\/?#:]/)[0].replace(/\.$/, '');
    if (v.indexOf('www.') === 0) v = v.slice(4);
    return v;
  }
  var DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

  function parseUrl(v) {
    v = (v || '').trim();
    if (!v) return null;
    if (!/^[a-z]+:\/\//i.test(v)) v = 'https://' + v;
    try { return new URL(v); } catch (e) { return false; }
  }

  // ---------- rendering ----------
  var results = [];
  function add(level, title, body) { results.push({ level: level, title: title, body: body }); }
  function render(domain) {
    var order = { bad: 0, warn: 1, info: 2, ok: 3 };
    results.sort(function (a, b) { return order[a.level] - order[b.level]; });
    var labels = { ok: 'Looks good', warn: 'Worth fixing', bad: 'Broken / missing', info: 'Info' };
    $('results').innerHTML = results.map(function (r) {
      return '<div class="result ' + r.level + '"><span class="tag">' + labels[r.level] + '</span><h4>' + r.title + '</h4>' + r.body + '</div>';
    }).join('');
    var c = { bad: 0, warn: 0, ok: 0 };
    results.forEach(function (r) { if (c[r.level] !== undefined) c[r.level]++; });
    $('summary').innerHTML =
      '<span class="pill bad">' + c.bad + ' broken</span><span class="pill warn">' + c.warn + ' to improve</span><span class="pill ok">' + c.ok + ' good</span>';
    $('outdomain').textContent = domain;
    $('out').classList.remove('hidden');
    $('out').scrollIntoView({ behavior: 'smooth', block: 'start' });
  }
  function pre(lines) { return '<pre>' + lines.map(esc).join('\n') + '</pre>'; }

  // ---------- checks ----------
  function checkMX(d, mx) {
    if (mx.answers.length === 1 && /^0\s+\.$/.test(mx.answers[0].trim())) {
      add('info', 'MX: "null MX" (this domain says it never receives mail)', '<p>That\'s allowed, but replies and bounces to your From address go nowhere. Make sure your From/Reply-To uses an address that can receive mail.</p>');
    } else if (mx.answers.length) {
      add('ok', 'MX records found: this domain can receive mail', pre(mx.answers));
    } else {
      add('warn', 'No MX records: this domain can\'t receive email',
        '<p>Sending can still work, but replies and bounces have nowhere to go, and some spam filters trust a domain less when it can\'t receive mail. <strong>Fix:</strong> if you have email hosting (Google Workspace, Zoho, etc.), add its MX records at your DNS host. If you only send, use a Reply-To address that does receive mail.</p>');
    }
  }

  function spfLookups(rec) {
    var terms = rec.split(/\s+/).slice(1);
    return terms.filter(function (t) { return /^[+\-~?]?(include:|a\b|a:|a\/|mx\b|mx:|mx\/|ptr|exists:)|^redirect=/i.test(t); }).length;
  }

  function checkSPF(d, root, sendSub) {
    var spf = root.answers.filter(function (t) { return /^v=spf1\b/i.test(t); });
    var subSpf = sendSub.answers.filter(function (t) { return /^v=spf1\b/i.test(t); });
    if (spf.length > 1) {
      add('bad', 'SPF: ' + spf.length + ' SPF records found. Only one is allowed',
        pre(spf) + '<p>With more than one SPF record, receivers treat SPF as an error and it fails. This is very common when two email services each told you to "add this TXT record". <strong>Fix:</strong> merge them into one record, e.g. <code>v=spf1 include:A include:B ~all</code>, and delete the extras.</p>');
      return;
    }
    if (!spf.length) {
      if (subSpf.length) {
        add('ok', 'SPF is on the <code>send.' + esc(d) + '</code> subdomain (the Resend-style setup)', pre(subSpf) + '<p>Resend publishes SPF on a <code>send.</code> subdomain, so a missing SPF on the main domain is fine for Resend.</p>');
      } else {
        add('bad', 'SPF: no SPF record found',
          '<p>SPF tells inboxes which services may send email for <strong>' + esc(d) + '</strong>. Without it, Gmail and others are more likely to spam or reject your auth emails. <strong>Fix:</strong> in your email provider\'s dashboard, add your domain. It will show the exact TXT record to add at your DNS host (Resend puts it on <code>send.' + esc(d) + '</code>; Brevo, Zoho, Postmark and others give you an <code>include:</code>).</p>');
      }
      return;
    }
    var rec = spf[0];
    var providers = SPF_PROVIDERS.filter(function (p) { return p[0].test(rec); }).map(function (p) { return p[1]; });
    var n = spfLookups(rec);
    var allM = (rec.match(/\s([+\-~?]?)all\b/i) || []);
    var body = pre([rec]);
    if (providers.length) body += '<p>Services allowed to send: ' + esc(providers.join(', ')) + '.</p>';
    if (/\s\+?all\b/i.test(rec) && allM[1] !== '-' && allM[1] !== '~' && allM[1] !== '?') {
      add('bad', 'SPF ends in "+all": anyone can send as you', body + '<p><strong>Fix:</strong> change the ending to <code>~all</code> (soft fail) or <code>-all</code> (hard fail).</p>');
    } else if (n > 10) {
      add('bad', 'SPF needs too many DNS lookups (' + n + ' at top level; the limit is 10)', body + '<p>Over 10 lookups and SPF fails outright. <strong>Fix:</strong> remove services you no longer use.</p>');
    } else if (!allM.length && !/redirect=/i.test(rec)) {
      add('warn', 'SPF has no "all" ending', body + '<p><strong>Fix:</strong> end the record with <code>~all</code> so receivers know what to do with everyone else.</p>');
    } else if (allM[1] === '?') {
      add('warn', 'SPF ends in "?all" (neutral). It doesn\'t protect much', body + '<p><strong>Fix:</strong> use <code>~all</code> or <code>-all</code>.</p>');
    } else {
      add('ok', 'SPF record found and looks valid', body + (n > 7 ? '<p class="note">Heads-up: ' + n + ' lookups at the top level, and nested includes add more. Keep it under 10.</p>' : ''));
    }
    if (subSpf.length) add('info', 'Also found SPF on <code>send.' + esc(d) + '</code> (Resend-style)', pre(subSpf));
  }

  function checkDKIM(d, found) {
    var hits = found.filter(function (f) { return f.ok; });
    if (!hits.length) {
      add('warn', 'DKIM: none found at the common selectors I checked',
        '<p>DKIM is a signature that proves an email really came from you. I checked ' + DKIM_SELECTORS.length + ' common names (<code>resend</code>, SendGrid <code>s1</code>/<code>s2</code>, <code>google</code>, <code>zoho</code>, Mailgun, Brevo, Postmark <code>pm</code>, Microsoft and others) and found nothing. Some services use their own names (Postmark uses a dated name like <code>20240101123456pm</code>, Amazon SES uses random tokens), so <strong>this isn\'t proof you have no DKIM</strong>. <strong>Fix:</strong> open your email provider\'s domain page. If it doesn\'t say "verified" next to DKIM, add the records it shows.</p>');
      return;
    }
    hits.forEach(function (h) {
      if (h.revoked) {
        add('warn', 'DKIM selector <code>' + esc(h.sel) + '</code> exists but has an empty key (revoked)', '<p>Fine if you stopped using ' + esc(h.who) + '. If not, re-add the DKIM record from its dashboard.</p>');
      } else {
        add('ok', 'DKIM found: <code>' + esc(h.sel) + '._domainkey.' + esc(d) + '</code> (' + esc(h.who) + ')',
          '<p>Signed email from this service should pass DKIM.</p>' + (h.cname ? '<p class="note">Points to: ' + esc(h.cname) + '</p>' : ''));
      }
    });
  }

  function checkDMARC(d, r) {
    var recs = r.answers.filter(function (t) { return /^v=DMARC1/i.test(t); });
    var g = ' <a href="https://support.google.com/a/answer/81126" rel="noopener">Gmail\'s sender guidelines</a>';
    if (!recs.length) {
      add('bad', 'DMARC: no DMARC record',
        '<p>DMARC tells inboxes what to do when an email claiming to be from you fails SPF/DKIM. Without it, more of your emails land in spam, and' + g + ' require it for bulk senders. <strong>Fix (safe starter):</strong> add a TXT record at your DNS host:</p>' +
        pre(['Name/Host:  _dmarc', 'Type:       TXT', 'Value:      v=DMARC1; p=none; rua=mailto:you@' + d]) +
        '<p class="note"><code>p=none</code> only monitors and won\'t block anything. Once SPF and DKIM pass, you can tighten it to <code>quarantine</code>.</p>');
      return;
    }
    if (recs.length > 1) { add('bad', 'DMARC: more than one record. Receivers may ignore both', pre(recs) + '<p><strong>Fix:</strong> keep exactly one <code>_dmarc</code> TXT record.</p>'); return; }
    var p = (recs[0].match(/;\s*p=([a-z]+)/i) || [])[1] || '';
    if (/none/i.test(p)) add('ok', 'DMARC found (policy: none, monitoring only)', pre(recs) + '<p>Good starting point. Once SPF and DKIM pass reliably, consider <code>p=quarantine</code>.</p>');
    else if (/quarantine|reject/i.test(p)) add('ok', 'DMARC found (policy: ' + esc(p) + ')', pre(recs) + '<p>Strict policy. Make sure your auth email provider passes SPF or DKIM <em>for this domain</em>, or your own emails will be blocked.</p>');
    else add('warn', 'DMARC record found but the policy (p=) is missing or invalid', pre(recs) + '<p><strong>Fix:</strong> start the record with <code>v=DMARC1; p=none;</code>.</p>');
  }

  function checkResendSub(d, mx) {
    if (mx.answers.some(function (a) { return /amazonses\.com/i.test(a); })) {
      add('info', 'Resend-style bounce domain found on <code>send.' + esc(d) + '</code>', pre(mx.answers));
    }
  }

  function checkSupabaseUrl(u) {
    if (u === null) return;
    if (u === false) { add('warn', 'Supabase project URL doesn\'t look like a URL', '<p>Expected something like <code>https://abcd1234.supabase.co</code>.</p>'); return; }
    var host = u.hostname.toLowerCase();
    var m = host.match(/^([a-z0-9]{15,30})\.supabase\.co$/);
    var cb = 'https://' + host + '/auth/v1/callback';
    if (m) {
      add('info', 'Your Google sign-in callback URL',
        '<p>In Google Cloud → APIs &amp; Services → Credentials → your OAuth client → <strong>Authorized redirect URIs</strong>, this exact URL must be listed:</p>' + pre([cb]) +
        '<p>And in Supabase → Authentication → Providers → Google, the Client ID and Secret must come from that same Google OAuth client. (I don\'t contact your project. This is worked out from the URL you typed.)</p>');
    } else if (/supabase\.(co|in|com)$/.test(host)) {
      add('warn', 'That doesn\'t look like a project URL', '<p>Use the Project URL from Supabase → Project Settings → Data API. It looks like <code>https://&lt;ref&gt;.supabase.co</code>, not the dashboard address.</p>');
    } else {
      add('info', 'Custom Supabase domain? Google callback would be:', pre([cb]) + '<p class="note">If you use a Supabase custom domain, Google\'s redirect URI should use it.</p>');
    }
  }

  function checkAppUrl(u, senderDomain, dnsRes) {
    if (u === null) return;
    if (u === false) { add('warn', 'App URL doesn\'t look like a URL', '<p>Expected something like <code>https://myapp.com</code>.</p>'); return; }
    var host = u.hostname.toLowerCase();
    var origin = u.protocol + '//' + u.host;
    if (/^(localhost|127\.0\.0\.1)$/.test(host)) {
      add('warn', 'App URL is localhost', '<p>Your <strong>Site URL</strong> in Supabase should be your live address, not localhost. Otherwise every confirmation and reset email sends users to a page that only exists on your computer. Keep <code>http://localhost:3000/**</code> in the <em>Redirect URLs</em> list for development instead.</p>');
      return;
    }
    if (u.protocol !== 'https:') add('warn', 'App URL uses http://, not https://', '<p>Use the https address in Site URL and Redirect URLs. Mixing them causes "redirect URL not allowed" errors.</p>');
    if (dnsRes && !dnsRes.ok) add('bad', 'App host <code>' + esc(host) + '</code> doesn\'t resolve in DNS', '<p>Nothing answers at this address right now, so links in emails pointing here will fail. Check the domain is connected at your host (Lovable, Vercel, Netlify, etc.).</p>');
    if (PREVIEW_HOSTS.test(host)) {
      add('warn', 'App URL is a platform/preview host (<code>' + esc(host) + '</code>)',
        '<p>That\'s fine if this <em>is</em> your live address. But if you also have a custom domain, the #1 cause of "works in preview, broken live" is Supabase\'s Site URL or Redirect URLs still pointing at this preview host (or the reverse). Make sure the one users actually visit is the Site URL, and both are in Redirect URLs while you transition.</p>');
    }
    add('info', 'Suggested Supabase URL Configuration for ' + esc(host),
      '<p>Authentication → URL Configuration:</p>' +
      pre(['Site URL:        ' + origin, 'Redirect URLs:   ' + origin + '/**', '                 http://localhost:3000/**   (dev only; adjust the port)']) +
      '<p class="note">Supabase recommends exact paths in production (e.g. <code>' + esc(origin) + '/auth/callback</code>) where you can. <code>/**</code> matches any path; a single <code>*</code> doesn\'t cross <code>/</code>.</p>');
    var reg = function (h) { return h.split('.').slice(-2).join('.'); };
    if (senderDomain && reg(host) !== reg(senderDomain) && !PREVIEW_HOSTS.test(host)) {
      add('info', 'App and sender use different domains', '<p>App: <code>' + esc(host) + '</code>, email from: <code>' + esc(senderDomain) + '</code>. That works, but emails from the same domain as your app look more trustworthy to users and filters.</p>');
    }
  }

  // ---------- main ----------
  $('f').addEventListener('submit', function (ev) {
    ev.preventDefault();
    var err = $('formerr'); err.classList.add('hidden');
    var fields = ['domain', 'sburl', 'appurl'];
    for (var i = 0; i < fields.length; i++) {
      if (SECRET_RE.test($(fields[i]).value)) {
        fields.forEach(function (f) { $(f).value = ""; });
        err.textContent = 'That looked like a key, token or password, so I cleared it. This check never needs secrets. Please only enter your domain and public URLs.';
        err.classList.remove('hidden');
        return;
      }
    }
    var d = normDomain($('domain').value);
    if (!DOMAIN_RE.test(d)) { err.textContent = 'Please enter a domain like myapp.com.'; err.classList.remove('hidden'); return; }
    var sb = parseUrl($('sburl').value), app = parseUrl($('appurl').value);
    var btn = $('go'); btn.disabled = true; btn.textContent = 'Checking…';
    results = [];

    var appHost = app ? app.hostname : null;
    Promise.all([
      doh(d, 'MX'), doh(d, 'TXT'), doh('_dmarc.' + d, 'TXT'), doh('send.' + d, 'TXT'), doh('send.' + d, 'MX'),
      Promise.all(DKIM_SELECTORS.map(function (s) {
        return doh(s[0] + '._domainkey.' + d, 'TXT').then(function (r) {
          var rec = r.answers.join('');
          var ok = /v=DKIM1|k=rsa|p=/i.test(rec) || r.cname.length > 0 && r.answers.length > 0;
          return { sel: s[0], who: s[1], ok: ok, revoked: ok && /p=\s*(;|$)/i.test(rec), cname: r.cname[0] };
        }).catch(function () { return { sel: s[0], ok: false }; });
      })),
      appHost && !/^(localhost|127\.0\.0\.1)$/.test(appHost)
        ? Promise.all([doh(appHost, 'A'), doh(appHost, 'AAAA')]).then(function (rs) { return { ok: rs[0].answers.length + rs[1].answers.length + rs[0].cname.length > 0 }; }).catch(function () { return null; })
        : Promise.resolve(null)
    ]).then(function (r) {
      if (r[0].status === 3 && r[1].status === 3) {
        add('bad', 'Domain not found', '<p><strong>' + esc(d) + '</strong> doesn\'t exist in DNS (NXDOMAIN). Check the spelling.</p>');
      } else {
        checkMX(d, r[0]); checkSPF(d, r[1], r[3]); checkDKIM(d, r[5]); checkDMARC(d, r[2]); checkResendSub(d, r[4]);
      }
      checkSupabaseUrl(sb); checkAppUrl(app, d, r[6]);
      add('info', 'Things a DNS check can\'t see', '<p>Whether custom SMTP is actually switched on in Supabase, your rate limit, and your email templates. Tick through the checklist below.</p>');
      render(d);
    }).catch(function (e) {
      $('results').innerHTML = '<div class="result bad"><span class="tag">Error</span><h4>DNS lookup failed</h4><p>' + esc(e.message) + '. Your network may block DNS-over-HTTPS. Try again or on another network.</p></div>';
      $('out').classList.remove('hidden');
    }).then(function () { btn.disabled = false; btn.textContent = 'Check my setup'; });
  });

  // Prefill from ?domain= for shareable links (no tracking).
  var q = new URLSearchParams(location.search);
  if (q.get('domain') && !SECRET_RE.test(q.get('domain'))) { $('domain').value = q.get('domain'); }
  if (q.get('app') && !SECRET_RE.test(q.get('app'))) { $('appurl').value = q.get('app'); }
  if (q.get('sb') && !SECRET_RE.test(q.get('sb'))) { $('sburl').value = q.get('sb'); }
  if (q.get('run') === '1' && $('domain').value) { $('f').requestSubmit(); }
})();
