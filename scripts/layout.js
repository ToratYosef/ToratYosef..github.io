(function () {
  const existingLoader = document.querySelector('script[src$="/scripts/layout.js"], script[src="scripts/layout.js"], script[src="../scripts/layout.js"]');
  const scriptUrl = existingLoader ? new URL(existingLoader.getAttribute('src'), window.location.href) : new URL('/scripts/layout.js', window.location.origin);
  const siteRoot = scriptUrl.pathname.replace(/\/scripts\/layout\.js$/, '') || '';

  function toSitePath(path) {
    return siteRoot + path;
  }

  function loadSharedStyles() {
    if (document.getElementById('shared-layout-styles')) {
      return;
    }
    const link = document.createElement('link');
    link.id = 'shared-layout-styles';
    link.rel = 'stylesheet';
    link.href = toSitePath('/assets/shared-layout.css');
    document.head.appendChild(link);
  }

  function loadReferralTrackingScript() {
    if (document.getElementById('site-referral-script')) {
      return;
    }

    const script = document.createElement('script');
    script.id = 'site-referral-script';
    script.type = 'module';
    script.src = toSitePath('/scripts/referral.js');
    document.head.appendChild(script);
  }

  function ensureMount(id, position) {
    let mount = document.getElementById(id);
    if (mount) {
      return mount;
    }

    mount = document.createElement('div');
    mount.id = id;

    if (position === 'top') {
      document.body.prepend(mount);
      return mount;
    }

    document.body.appendChild(mount);
    return mount;
  }

  function ensurePageContentWrapper() {
    let wrapper = document.getElementById('site-page-content');
    if (wrapper) {
      return wrapper;
    }

    wrapper = document.createElement('div');
    wrapper.id = 'site-page-content';

    const nodesToMove = Array.from(document.body.children).filter(function (node) {
      return node.id !== 'site-header-root' && node.id !== 'site-footer-root';
    });

    nodesToMove.forEach(function (node) {
      wrapper.appendChild(node);
    });

    document.body.appendChild(wrapper);
    return wrapper;
  }

  function removeLegacyElements() {
    document.querySelectorAll('.logo-container, nav, footer.footer, footer:not(.site-footer-shell)').forEach(function (node) {
      if (!node.closest('#site-header-root') && !node.closest('#site-footer-root')) {
        node.remove();
      }
    });
  }

  function setActiveLink(rootNode) {
    const page = (window.location.pathname.split('/').pop() || 'index.html').toLowerCase();
    rootNode.querySelectorAll('.site-nav a').forEach(function (link) {
      const href = (link.getAttribute('href') || '').toLowerCase();
      const target = href.split('/').pop();
      if (target === page || (page === '' && target === 'index.html')) {
        link.classList.add('active');
      }
    });
  }

  function setupScrollState(rootNode) {
    const shell = rootNode.querySelector('.site-header-shell');
    if (!shell) {
      return;
    }

    function onScroll() {
      if (window.scrollY > 14) {
        shell.classList.add('scrolled');
      } else {
        shell.classList.remove('scrolled');
      }
    }

    onScroll();
    window.addEventListener('scroll', onScroll, { passive: true });
  }

  function setupMobileNav(rootNode) {
    const toggle = rootNode.querySelector('.site-nav-toggle');
    const nav = rootNode.querySelector('.site-nav');
    if (!toggle || !nav) {
      return;
    }

    toggle.addEventListener('click', function () {
      const isOpen = nav.classList.toggle('open');
      toggle.setAttribute('aria-expanded', String(isOpen));
    });

    nav.querySelectorAll('a').forEach(function (link) {
      link.addEventListener('click', function () {
        nav.classList.remove('open');
        toggle.setAttribute('aria-expanded', 'false');
      });
    });
  }

  function loadPartial(path, mount) {
    return fetch(toSitePath(path), { cache: 'no-cache' })
      .then(function (response) {
        if (!response.ok) {
          throw new Error('Failed to load partial: ' + path);
        }
        return response.text();
      })
      .then(function (html) {
        mount.innerHTML = html;
      });
  }

  function init() {
    if (!document.body) {
      return;
    }

    removeLegacyElements();
    loadSharedStyles();
    loadReferralTrackingScript();
    ensurePageContentWrapper();

    const headerMount = ensureMount('site-header-root', 'top');
    const footerMount = ensureMount('site-footer-root', 'bottom');
    const isAdminPage = window.location.pathname.indexOf('/admin/') === 0;
    const headerPath = isAdminPage ? '/admin/header.html' : '/header.html';
    const footerPath = isAdminPage ? '/admin/footer.html' : '/footer.html';

    Promise.all([
      loadPartial(headerPath, headerMount),
      loadPartial(footerPath, footerMount)
    ]).then(function () {
      setActiveLink(headerMount);
      setupScrollState(headerMount);
      setupMobileNav(headerMount);
      if (window.__referral && typeof window.__referral.keepRefOnInternalLinks === 'function') {
        window.__referral.keepRefOnInternalLinks();
      }
    }).catch(function (error) {
      console.error(error);
    });
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();
