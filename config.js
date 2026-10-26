/* ============================================================
   SITE CONFIG: the ONE place to turn on booking and contact.
   Paste your links between the quotes, commit, push. That's it.
   Leave a value empty ("") to keep the "Booking opens soon" state / hide it.
   ============================================================ */
window.SITE_CONFIG = {
  PAYMENT_LINK: "",   // e.g. "https://buy.stripe.com/xxxx"  -> all "Book the $49 fix" buttons
  BOOKING_LINK: "",   // e.g. "https://cal.com/you/49-fix"   -> "Pick a time" link on offer.html
  CONTACT_EMAIL: ""   // e.g. "jimmy@yourdomain.com"         -> shows "Questions: ..." lines
};

/* --- no need to edit below --- */
(function () {
  var c = window.SITE_CONFIG || {};
  function upgrade(sel, url, label) {
    document.querySelectorAll(sel).forEach(function (el) {
      if (!url) return; // stays as the non-clickable "Booking opens soon" state
      var a = document.createElement('a');
      a.className = el.className.replace(/\bsoon\b/, '').trim();
      a.href = url; a.rel = 'noopener';
      a.textContent = el.getAttribute('data-label') || label;
      el.replaceWith(a);
    });
  }
  function run() {
    upgrade('[data-cta="payment"]', c.PAYMENT_LINK, 'Book the $49 fix');
    upgrade('[data-cta="booking"]', c.BOOKING_LINK, 'Pick a time');
    if (c.BOOKING_LINK) document.querySelectorAll('[data-show-if="booking"]').forEach(function (e) { e.hidden = false; });
    if (c.CONTACT_EMAIL) {
      document.querySelectorAll('[data-email]').forEach(function (e) {
        var a = document.createElement('a'); a.href = 'mailto:' + c.CONTACT_EMAIL; a.textContent = c.CONTACT_EMAIL;
        if (e.getAttribute('data-email') === 'light') a.style.color = '#fff';
        e.textContent = 'Questions: '; e.appendChild(a); e.hidden = false;
      });
    }
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', run); else run();
})();
