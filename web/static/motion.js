/* TrapKey motion runtime: scroll progress, kinetic reveals, X-Ray tabs, tilt/spotlight, ripples, nav controls. */
(() => {
  'use strict';
  if (typeof window === 'undefined' || typeof document === 'undefined') return;

  const reduced = !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
  const coarse = !!(window.matchMedia && window.matchMedia('(pointer: coarse)').matches);
  const hasIO = 'IntersectionObserver' in window;
  const raf = window.requestAnimationFrame
    ? window.requestAnimationFrame.bind(window)
    : (fn) => setTimeout(fn, 16);
  const caf = window.cancelAnimationFrame
    ? window.cancelAnimationFrame.bind(window)
    : clearTimeout;

  function parseCounterSpec(el) {
    const attr = el.dataset.count;
    const raw = String(attr !== undefined && attr !== '' ? attr : el.textContent || '').trim();
    const target = parseFloat(raw);
    if (!Number.isFinite(target)) return null;

    let decimals = 0;
    if (el.dataset.decimals !== undefined && el.dataset.decimals !== '') {
      const parsed = parseInt(el.dataset.decimals, 10);
      decimals = Number.isFinite(parsed) && parsed >= 0 ? parsed : 0;
    } else {
      const dot = raw.indexOf('.');
      if (dot !== -1) {
        const match = raw.slice(dot + 1).match(/^\d+/);
        decimals = match ? match[0].length : 0;
      }
    }

    return {
      target,
      decimals,
      prefix: el.dataset.prefix || '',
      suffix: el.dataset.suffix || '',
    };
  }

  function formatCounter(value, spec) {
    return spec.prefix + value.toFixed(spec.decimals) + spec.suffix;
  }

  function animateCounter(el) {
    if (el.dataset.counted === '1') return;
    const spec = parseCounterSpec(el);
    if (!spec) return;
    el.dataset.counted = '1';

    if (reduced || !hasIO) {
      el.textContent = formatCounter(spec.target, spec);
      return;
    }

    const duration = 850;
    let start = null;
    el.textContent = formatCounter(0, spec);

    function step(now) {
      if (start === null) start = now;
      const t = Math.min(1, Math.max(0, (now - start) / duration));
      const eased = 1 - Math.pow(1 - t, 3);
      el.textContent = formatCounter(spec.target * eased, spec);
      if (t < 1) {
        raf(step);
      } else {
        el.textContent = formatCounter(spec.target, spec);
      }
    }
    raf(step);
  }

  function initScrollAndTagline() {
    const scrollRail = document.getElementById('scrollRail');
    const hudScrollFill = document.getElementById('hudScrollFill');
    const scrollPct = document.getElementById('scrollPct');
    const tagline = document.getElementById('taglineReveal');
    const words = tagline ? Array.from(tagline.querySelectorAll('.reveal-word')) : [];

    let taglineObserver = null;
    let taglineInView = false;
    let taglineTimer = 0;

    function updateScrollProgress() {
      const maxScroll = document.documentElement.scrollHeight - window.innerHeight;
      const scrollY = window.scrollY !== undefined ? window.scrollY : (window.pageYOffset || 0);
      const p = maxScroll > 0 ? Math.min(1, Math.max(0, scrollY / maxScroll)) : 0;
      const scale = 'scaleX(' + p + ')';
      if (scrollRail) scrollRail.style.transform = scale;
      if (hudScrollFill) hudScrollFill.style.transform = scale;
      if (scrollPct) scrollPct.textContent = Math.round(p * 100) + '%';
    }

    function lightTaglineSequentially() {
      if (!tagline || tagline.dataset.done === '1') return;
      tagline.dataset.done = '1';
      words.forEach((w, idx) => {
        if (w.classList.contains('lit')) return;
        setTimeout(() => w.classList.add('lit'), Math.min(idx * 45, 700));
      });
      if (taglineObserver) taglineObserver.unobserve(tagline);
    }

    function updateTagline() {
      if (!tagline || !words.length || tagline.dataset.done === '1') return;
      const vh = window.innerHeight || document.documentElement.clientHeight || 800;
      const rect = tagline.getBoundingClientRect();
      const start = 0.82 * vh;
      const end = 0.28 * vh;
      const progress = Math.min(1, Math.max(0, (start - rect.top) / Math.max(1, start - end)));

      if (progress >= 0.95 || rect.top < 0.25 * vh) {
        words.forEach((w) => w.classList.add('lit'));
        tagline.dataset.done = '1';
        clearTimeout(taglineTimer);
        if (taglineObserver) taglineObserver.unobserve(tagline);
        return;
      }

      if (progress <= 0) {
        words.forEach((w) => w.classList.remove('lit'));
        return;
      }

      const cutoff = Math.floor(progress * words.length);
      words.forEach((w, idx) => {
        w.classList.toggle('lit', idx <= cutoff);
      });
    }

    if (tagline && words.length) {
      if (reduced || !hasIO) {
        words.forEach((w) => w.classList.add('lit'));
        tagline.dataset.done = '1';
      } else {
        // Fallback when jumping directly to #taglineReveal without scrubbing through the band.
        taglineObserver = new IntersectionObserver(
          (entries) => {
            entries.forEach((entry) => {
              taglineInView = entry.isIntersecting;
              if (entry.isIntersecting && tagline.dataset.done !== '1') {
                clearTimeout(taglineTimer);
                taglineTimer = setTimeout(() => {
                  if (taglineInView && tagline.dataset.done !== '1') {
                    lightTaglineSequentially();
                  }
                }, 380);
              } else if (!entry.isIntersecting) {
                clearTimeout(taglineTimer);
              }
            });
          },
          { threshold: 0.35 }
        );
        taglineObserver.observe(tagline);
      }
    }

    let pending = false;
    const flushFrame = () => {
      pending = false;
      updateScrollProgress();
      if (!reduced && hasIO) updateTagline();
    };
    const scheduleFrame = () => {
      if (pending) return;
      pending = true;
      raf(flushFrame);
    };

    updateScrollProgress();
    if (!reduced && hasIO) updateTagline();

    if (scrollRail || hudScrollFill || scrollPct || (tagline && words.length && !reduced && hasIO)) {
      window.addEventListener(
        'scroll',
        () => {
          // Reset fallback timer while actively scrolling so word-by-word scrub stays responsive.
          if (tagline && taglineInView && tagline.dataset.done !== '1') {
            clearTimeout(taglineTimer);
            taglineTimer = setTimeout(() => {
              if (taglineInView && tagline.dataset.done !== '1') {
                lightTaglineSequentially();
              }
            }, 420);
          }
          scheduleFrame();
        },
        { passive: true }
      );
      window.addEventListener('resize', scheduleFrame, { passive: true });
      window.addEventListener('load', scheduleFrame, { passive: true });
    }
  }

  function initRevealsAndCounters() {
    const blocks = document.querySelectorAll('.reveal-block');
    const counters = document.querySelectorAll('[data-count]');
    if (!blocks.length && !counters.length) return;

    if (reduced || !hasIO) {
      blocks.forEach((el) => el.classList.add('visible'));
      counters.forEach((el) => animateCounter(el));
      return;
    }

    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (!entry.isIntersecting) return;
          const el = entry.target;
          if (el.classList && el.classList.contains('reveal-block')) {
            el.classList.add('visible');
          }
          if (
            (el.hasAttribute && el.hasAttribute('data-count')) ||
            (el.dataset && el.dataset.count !== undefined)
          ) {
            animateCounter(el);
          }
          observer.unobserve(el);
        });
      },
      { threshold: 0.1, rootMargin: '0px 0px -24px 0px' }
    );

    blocks.forEach((el) => observer.observe(el));
    counters.forEach((el) => observer.observe(el));
  }

  function initDemoTabs() {
    const tabs = document.querySelectorAll('[data-demo-tab]');
    const panels = document.querySelectorAll('[data-demo-panel]');
    const xrayFile = document.getElementById('xrayFile');
    if (!tabs.length) return;

    tabs.forEach((btn) => {
      btn.addEventListener('click', () => {
        const target = btn.getAttribute('data-demo-tab');
        tabs.forEach((tab) => {
          const active = tab === btn;
          tab.classList.toggle('active', active);
          tab.setAttribute('aria-pressed', active ? 'true' : 'false');
        });
        panels.forEach((panel) => {
          const match = panel.getAttribute('data-demo-panel') === target;
          panel.hidden = !match;
          if (match) {
            panel.classList.remove('panel-enter');
            if (!reduced) {
              void panel.offsetWidth;
              panel.classList.add('panel-enter');
            }
          }
        });
        if (xrayFile) {
          xrayFile.textContent =
            btn.dataset.file || (target === 'after' ? 'InvoicePro.protected.exe' : 'InvoicePro.exe');
        }
      });
    });
  }

  function initPointerEffects() {
    if (reduced || coarse) return;

    document.querySelectorAll('[data-tilt]').forEach((el) => {
      let tiltRaf = 0;
      let dx = 0;
      let dy = 0;
      let active = false;

      el.addEventListener(
        'pointermove',
        (e) => {
          if (e.pointerType === 'touch') return;
          const rect = el.getBoundingClientRect();
          if (!rect.width || !rect.height) return;
          dx = Math.max(-0.5, Math.min(0.5, (e.clientX - rect.left) / rect.width - 0.5));
          dy = Math.max(-0.5, Math.min(0.5, (e.clientY - rect.top) / rect.height - 0.5));
          active = true;
          if (tiltRaf) return;
          tiltRaf = raf(() => {
            tiltRaf = 0;
            if (!active) return;
            el.style.transform =
              'perspective(1100px) rotateX(' +
              (-dy * 4).toFixed(2) +
              'deg) rotateY(' +
              (dx * 5).toFixed(2) +
              'deg)';
          });
        },
        { passive: true }
      );

      const clearTilt = () => {
        active = false;
        if (tiltRaf) {
          caf(tiltRaf);
          tiltRaf = 0;
        }
        el.style.transform = '';
      };

      el.addEventListener('pointerleave', clearTilt);
      el.addEventListener('pointercancel', clearTilt);
    });

    document.querySelectorAll('[data-spotlight]').forEach((el) => {
      el.addEventListener(
        'pointermove',
        (e) => {
          if (e.pointerType === 'touch') return;
          const rect = el.getBoundingClientRect();
          el.style.setProperty('--mx', (e.clientX - rect.left) + 'px');
          el.style.setProperty('--my', (e.clientY - rect.top) + 'px');
        },
        { passive: true }
      );
    });
  }

  function initButtonRipples() {
    if (reduced) return;

    let lastPointerBtn = null;
    let lastPointerAt = 0;

    const spawnRipple = (btn, clientX, clientY, centered) => {
      if (!btn || btn.disabled || btn.hasAttribute('disabled') || btn.getAttribute('aria-disabled') === 'true') {
        return;
      }
      const rect = btn.getBoundingClientRect();
      if (!rect.width && !rect.height) return;

      const wave = document.createElement('span');
      wave.className = 'ripple-wave';
      wave.style.left = (centered ? rect.width / 2 : clientX - rect.left) + 'px';
      wave.style.top = (centered ? rect.height / 2 : clientY - rect.top) + 'px';
      btn.appendChild(wave);

      let cleaned = false;
      const cleanup = () => {
        if (cleaned) return;
        cleaned = true;
        if (wave.parentNode) wave.parentNode.removeChild(wave);
      };
      wave.addEventListener('animationend', cleanup, { once: true });
      setTimeout(cleanup, 700);
    };

    document.addEventListener(
      'pointerdown',
      (e) => {
        if (e.pointerType === 'mouse' && e.button !== 0) return;
        const btn = e.target && e.target.closest ? e.target.closest('.btn') : null;
        if (!btn) return;
        lastPointerBtn = btn;
        lastPointerAt = Date.now();
        spawnRipple(btn, e.clientX, e.clientY, false);
      },
      { passive: true }
    );

    document.addEventListener('click', (e) => {
      const btn = e.target && e.target.closest ? e.target.closest('.btn') : null;
      if (!btn) return;
      if (lastPointerBtn === btn && Date.now() - lastPointerAt < 600) {
        lastPointerBtn = null;
        return;
      }
      const centered = e.detail === 0 || (e.clientX === 0 && e.clientY === 0);
      spawnRipple(btn, e.clientX, e.clientY, centered);
    });
  }

  function initNavControls() {
    const toggle = document.getElementById('menuToggle');
    const drawer = document.getElementById('mobileDrawer');

    const setDrawerOpen = (open) => {
      if (!drawer) return;
      drawer.classList.toggle('open', open);
      drawer.setAttribute('aria-hidden', String(!open));
      if (toggle) toggle.setAttribute('aria-expanded', String(open));
    };

    if (toggle && drawer) {
      toggle.addEventListener('click', () => {
        setDrawerOpen(!drawer.classList.contains('open'));
      });
    }

    if (drawer) {
      drawer.addEventListener('click', (e) => {
        const link = e.target && e.target.closest ? e.target.closest('a') : null;
        if (link) setDrawerOpen(false);
      });
    }

    document.addEventListener('click', (e) => {
      document.querySelectorAll('.lang-menu[open]').forEach((menu) => {
        if (!menu.contains(e.target)) menu.removeAttribute('open');
      });
      if (
        drawer &&
        drawer.classList.contains('open') &&
        !drawer.contains(e.target) &&
        (!toggle || !toggle.contains(e.target))
      ) {
        setDrawerOpen(false);
      }
    });

    document.addEventListener('keydown', (e) => {
      if (e.key !== 'Escape' && e.key !== 'Esc') return;
      document.querySelectorAll('.lang-menu[open]').forEach((menu) => {
        const focused = menu.contains(document.activeElement);
        menu.removeAttribute('open');
        if (focused) {
          const summary = menu.querySelector('summary');
          if (summary && typeof summary.focus === 'function') summary.focus();
        }
      });
      if (drawer && drawer.classList.contains('open')) {
        const focused =
          drawer.contains(document.activeElement) ||
          (toggle && document.activeElement === toggle);
        setDrawerOpen(false);
        if (focused && toggle && typeof toggle.focus === 'function') {
          toggle.focus();
        }
      }
    });
  }

  function boot() {
    initScrollAndTagline();
    initRevealsAndCounters();
    initDemoTabs();
    initPointerEffects();
    initButtonRipples();
    initNavControls();
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot, { once: true });
  } else {
    boot();
  }
})();
