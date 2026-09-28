/**
 * 홈 화면을 탭 셸로 만든다 — 사이드바에서 홈을 제외한 메뉴를 클릭하면 페이지 전체를 새로
 * 불러오는 대신, 그 화면을 iframe(?embed=1 — 자기 사이드바/상단바는 숨기고 내용만 보여준다)
 * 으로 열어 탭에 추가한다. 홈은 탭이 아니라 항상 존재하는 기본 화면이라 클릭하면 탭들을 그대로
 * 둔 채 홈 내용만 다시 보여준다.
 *
 * 이 화면(홈)에만 #tabNav(상단바)/#tabPanels/#homePanel이 있으므로, 단위 화면을 직접 열었을 때는
 * 이 스크립트가 아무것도 하지 않고 조용히 빠진다(사이드바 링크가 원래대로 페이지 전체를 이동).
 */
(function () {
    const tabNav = document.getElementById('tabNav');
    const tabPanels = document.getElementById('tabPanels');
    const homePanel = document.getElementById('homePanel');
    if (!tabNav || !tabPanels || !homePanel) {
        return;
    }

    const tabs = []; // { url, title, menuKey, iframe, btn }
    let activeUrl = null; // null이면 홈 화면이 보이는 상태

    function findTab(url) {
        return tabs.find(function (t) { return t.url === url; });
    }

    function updateSidebarActive(menuKey) {
        document.querySelectorAll('.nav a').forEach(function (a) {
            const isHome = a.classList.contains('home-link');
            const matches = menuKey ? a.dataset.menu === menuKey : isHome;
            a.classList.toggle('is-active', matches);
        });
    }

    function showHome() {
        activeUrl = null;
        homePanel.classList.remove('hidden');
        tabPanels.classList.remove('active');
        tabs.forEach(function (t) {
            t.iframe.style.display = 'none';
            t.btn.classList.remove('active');
        });
        updateSidebarActive(null);
    }

    function activateTab(url) {
        const tab = findTab(url);
        if (!tab) {
            showHome();
            return;
        }
        activeUrl = url;
        homePanel.classList.add('hidden');
        tabPanels.classList.add('active');
        tabs.forEach(function (t) {
            t.iframe.style.display = (t.url === url) ? 'block' : 'none';
            t.btn.classList.toggle('active', t.url === url);
        });
        updateSidebarActive(tab.menuKey);
    }

    function openTab(url, title, menuKey) {
        let tab = findTab(url);
        if (!tab) {
            const iframe = document.createElement('iframe');
            iframe.src = url + (url.indexOf('?') >= 0 ? '&' : '?') + 'embed=1';
            iframe.className = 'tab-iframe';
            tabPanels.appendChild(iframe);

            const btn = document.createElement('div');
            btn.className = 'tab-btn';
            btn.title = title; // 탭 폭이 고정이라 잘린 이름을 마우스 오버로 전체 표시
            const label = document.createElement('span');
            label.className = 'tab-label';
            label.textContent = title;
            const close = document.createElement('span');
            close.className = 'tab-close';
            close.textContent = '×';
            close.title = '닫기';
            btn.appendChild(label);
            btn.appendChild(close);
            tabNav.appendChild(btn);

            tab = { url: url, title: title, menuKey: menuKey, iframe: iframe, btn: btn };
            tabs.push(tab);

            btn.addEventListener('click', function (e) {
                if (e.target === close) {
                    return;
                }
                activateTab(tab.url);
            });
            close.addEventListener('click', function (e) {
                e.stopPropagation();
                closeTab(tab.url);
            });
            btn.addEventListener('contextmenu', function (e) {
                e.preventDefault();
                showContextMenu(e.clientX, e.clientY, tab.url);
            });
        }
        activateTab(tab.url);
    }

    function closeTab(url) {
        const index = tabs.findIndex(function (t) { return t.url === url; });
        if (index === -1) {
            return;
        }
        const tab = tabs[index];
        const wasActive = activeUrl === tab.url;
        tab.iframe.remove();
        tab.btn.remove();
        tabs.splice(index, 1);

        if (wasActive) {
            const next = tabs[index] || tabs[index - 1];
            if (next) {
                activateTab(next.url);
            } else {
                showHome();
            }
        }
    }

    function closeOtherTabs(url) {
        tabs.slice().forEach(function (t) {
            if (t.url !== url) {
                closeTab(t.url);
            }
        });
    }

    function closeAllTabs() {
        tabs.slice().forEach(function (t) { closeTab(t.url); });
    }

    // ── 탭 우클릭 컨텍스트 메뉴: 닫기 / 다른 탭 모두 닫기 / 모두 닫기 ──────────────
    let menuEl = null;

    function hideContextMenu() {
        if (menuEl) {
            menuEl.remove();
            menuEl = null;
        }
    }

    function showContextMenu(x, y, url) {
        hideContextMenu();
        menuEl = document.createElement('div');
        menuEl.className = 'tab-context-menu';

        [
            ['닫기', function () { closeTab(url); }],
            ['다른 탭 모두 닫기', function () { closeOtherTabs(url); }],
            ['모두 닫기', function () { closeAllTabs(); }]
        ].forEach(function (entry) {
            const item = document.createElement('div');
            item.className = 'tab-context-menu-item';
            item.textContent = entry[0];
            item.addEventListener('click', function () {
                entry[1]();
                hideContextMenu();
            });
            menuEl.appendChild(item);
        });

        document.body.appendChild(menuEl);

        // 화면 오른쪽/아래 밖으로 나가지 않게 위치를 보정한다.
        const rect = menuEl.getBoundingClientRect();
        menuEl.style.left = Math.min(x, window.innerWidth - rect.width - 8) + 'px';
        menuEl.style.top = Math.min(y, window.innerHeight - rect.height - 8) + 'px';
    }

    document.addEventListener('click', hideContextMenu);
    document.addEventListener('scroll', hideContextMenu, true);
    window.addEventListener('blur', hideContextMenu);

    // ── 사이드바 링크 가로채기: 홈은 그대로 홈 화면 표시, 나머지는 탭으로 연다 ──────
    document.querySelectorAll('.nav a').forEach(function (a) {
        a.addEventListener('click', function (e) {
            e.preventDefault();
            if (a.classList.contains('home-link')) {
                showHome();
                return;
            }
            const url = a.getAttribute('href');
            const title = a.dataset.title || a.textContent.trim();
            const menuKey = a.dataset.menu;
            openTab(url, title, menuKey);
        });
    });

    showHome();
})();
