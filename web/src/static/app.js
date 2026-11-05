/* VPNFree interactions */
(function () {
  "use strict";

  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };

  function readJson(id) {
    var node = document.getElementById(id);
    if (!node) return null;
    try { return JSON.parse(node.textContent || "{}"); } catch (e) { return null; }
  }

  var quota = readJson("quota-data");
  var webcfg = readJson("web-config") || {
    ssh: true,
    xray: true,
    protocols: { vmess: true, vless: true, trojan: true },
    maintenance: false
  };
  var form = $("#create-form");

  function selected(serviceName) {
    var input = document.querySelector('input[name="' + serviceName + '"]:checked');
    return input ? input.value : "";
  }

  function quotaFor(service, days) {
    if (!quota || !quota.services || !quota.services[service]) return null;
    return quota.services[service][String(days)] || null;
  }

  function pct(used, limit) {
    if (!limit) return 0;
    return Math.max(0, Math.min(100, (used / limit) * 100));
  }

  function paintCard(card, on) {
    if (!card) return;
    card.classList.toggle("selected", on);
  }

  function serviceAvailable(service) {
    if (service === "ssh") return webcfg.ssh !== false;
    if (service === "xray") return webcfg.xray !== false;
    return false;
  }

  function protocolAvailable(protocol) {
    return Boolean(protocol && webcfg.protocols && webcfg.protocols[protocol] !== false);
  }

  function firstProtocol() {
    var order = ["vmess", "vless", "trojan"];
    for (var i = 0; i < order.length; i++) {
      if (protocolAvailable(order[i])) return order[i];
    }
    return "";
  }

  function checkInput(name, value) {
    var input = document.querySelector('input[name="' + name + '"][value="' + value + '"]');
    if (input && !input.disabled) input.checked = true;
    return input ? input.value : "";
  }

  function updateUI() {
    if (!form) return;

    var service = selected("service");
    if (!serviceAvailable(service)) {
      service = webcfg.ssh !== false ? "ssh" : (webcfg.xray !== false ? "xray" : "");
      if (service) {
        checkInput("service", service);
      } else {
        $$('input[name="service"]').forEach(function (input) { input.checked = false; });
      }
    }

    var days = selected("days") || "3";
    var protocol = selected("protocol");
    var isXray = service === "xray";
    var wrap = $("#protocol-wrap");
    if (wrap) {
      wrap.hidden = !isXray;
      if (isXray && !protocolAvailable(protocol)) {
        protocol = firstProtocol();
        if (protocol) checkInput("protocol", protocol);
      }
    }

    $$("[data-service-card]").forEach(function (card) {
      var cardService = card.getAttribute("data-service-card");
      paintCard(card, cardService === service && serviceAvailable(cardService));
    });
    $$("[data-duration-card]").forEach(function (card) {
      paintCard(card, card.getAttribute("data-duration-card") === days);
    });
    $$("[data-protocol-card]").forEach(function (card) {
      var proto = card.getAttribute("data-protocol-card");
      card.classList.toggle("selected", isXray && proto === protocol && protocolAvailable(proto));
    });

    var q = service ? quotaFor(service, days) : null;
    var remaining = q ? q.remaining : 0;
    var limit = q ? q.limit : 0;
    var serviceLabel = service === "ssh" ? "SSH" : "Xray";
    var title = $("#quota-title");
    var sub = $("#quota-sub");
    var ring = $("#quota-ring");
    var remainingNode = $("#quota-remaining");
    var button = $("#create-button");
    var closed = !service;

    if (remainingNode) remainingNode.textContent = q ? String(remaining) : "—";
    if (title) {
      if (webcfg.maintenance) {
        title.textContent = "Website sedang dalam perawatan";
      } else if (closed) {
        title.textContent = "Semua layanan sedang ditutup";
      } else if (!q) {
        title.textContent = "Kuota belum tersedia";
      } else if (remaining > 0) {
        title.textContent = remaining + " slot tersisa untuk " + serviceLabel + " " + days + " hari";
      } else {
        title.textContent = "Kuota " + serviceLabel + " " + days + " hari habis";
      }
    }
    if (sub) {
      if (webcfg.maintenance) {
        sub.textContent = "Admin menutup sementara seluruh pembuatan akun.";
      } else if (closed) {
        sub.textContent = "Tidak ada layanan yang sedang dibuka admin.";
      } else if (q) {
        sub.textContent = "Terpakai " + q.used + " dari " + limit + " akun hari ini · global per layanan.";
      } else {
        sub.textContent = "Silakan muat ulang halaman.";
      }
    }
    if (ring) {
      var ringOn = Boolean(q && remaining > 0 && !webcfg.maintenance && !closed);
      ring.style.borderColor = ringOn ? "rgba(166,63,35,.28)" : "rgba(179,54,43,.35)";
      ring.style.color = ringOn ? "var(--terracotta)" : "var(--red)";
    }
    if (button) {
      var protocolOk = !isXray || protocolAvailable(protocol);
      var enabled = Boolean(!webcfg.maintenance && !closed && serviceAvailable(service) && protocolOk && q && remaining > 0);
      button.disabled = !enabled;
      button.setAttribute("aria-disabled", String(!enabled));
      if (webcfg.maintenance) {
        button.innerHTML = 'Website perawatan <span aria-hidden="true">·</span>';
      } else if (closed) {
        button.innerHTML = 'Semua layanan ditutup <span aria-hidden="true">·</span>';
      } else if (q && remaining <= 0) {
        button.innerHTML = 'Kuota habis <span aria-hidden="true">·</span>';
      } else if (!protocolOk) {
        button.innerHTML = 'Protokol ditutup <span aria-hidden="true">·</span>';
      } else {
        button.innerHTML = 'Buat akun <span aria-hidden="true">↗</span>';
      }
    }
    $$("[data-quota-label]").forEach(function (node) {
      var d = node.getAttribute("data-quota-label");
      var qq = service ? quotaFor(service, d) : null;
      node.textContent = qq ? qq.remaining + " / " + qq.limit + " slot tersisa" : "—";
    });
    $$("[data-quota-chip]").forEach(function (node) {
      var key = node.getAttribute("data-quota-chip").split("-");
      var qq = quotaFor(key[0], key[1]);
      node.textContent = qq ? qq.remaining + " / " + qq.limit : "—";
    });
    $$("[data-quota-fill]").forEach(function (node) {
      var key = node.getAttribute("data-quota-fill").split("-");
      var qq = quotaFor(key[0], key[1]);
      node.style.width = qq ? pct(qq.used, qq.limit).toFixed(1) + "%" : "0%";
    });
  }

  if (form) {
    $$('input[name="service"], input[name="days"], input[name="protocol"]').forEach(function (input) {
      input.addEventListener("change", updateUI);
    });
    $$("[data-service-card], [data-duration-card]").forEach(function (card) {
      card.addEventListener("click", function () {
        window.setTimeout(updateUI, 0);
      });
    });
    form.addEventListener("submit", function (event) {
      var button = $("#create-button");
      if (button && button.disabled) {
        event.preventDefault();
        return;
      }
      if (button) {
        button.disabled = true;
        button.innerHTML = '<span class="spinner"></span> Membuat akun…';
      }
    });
    updateUI();
  }

  var countdown = $("#reset-countdown");
  if (countdown && quota && quota.reset_at) {
    var resetAt = Number(quota.reset_at) * 1000;
    var tick = function () {
      var diff = Math.max(0, resetAt - Date.now());
      var total = Math.floor(diff / 1000);
      var h = Math.floor(total / 3600);
      var m = Math.floor((total % 3600) / 60);
      var s = total % 60;
      countdown.textContent = String(h).padStart(2, "0") + ":" + String(m).padStart(2, "0") + ":" + String(s).padStart(2, "0");
      if (diff <= 0) {
        window.setTimeout(function () { window.location.reload(); }, 2500);
      }
    };
    tick();
    window.setInterval(tick, 1000);
  }

  function fallbackCopy(text) {
    var area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.appendChild(area);
    area.select();
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (e) { ok = false; }
    document.body.removeChild(area);
    return ok;
  }

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).then(function () { return true; }).catch(function () {
        return fallbackCopy(text);
      });
    }
    return Promise.resolve(fallbackCopy(text));
  }

  function flash(node, message, isError) {
    if (!node) return;
    node.textContent = message;
    node.style.color = isError ? "var(--red)" : "var(--green)";
    window.clearTimeout(node._timer);
    node._timer = window.setTimeout(function () { node.textContent = ""; }, 3500);
  }

  var copyOutput = $("#copy-output");
  if (copyOutput) {
    copyOutput.addEventListener("click", function () {
      var output = $("#account-output");
      if (!output) return;
      copyText(output.textContent || "").then(function (ok) {
        flash($("#copy-status"), ok ? "Output akun disalin ke clipboard." : "Gagal menyalin. Pilih teks lalu salin manual.", !ok);
      });
    });
  }

  var copyLink = $("#copy-link");
  if (copyLink) {
    copyLink.addEventListener("click", function () {
      var url = window.location.origin + window.location.pathname;
      copyText(url).then(function (ok) {
        copyLink.textContent = ok ? "Tautan tersalin ✓" : "Gagal menyalin";
        window.setTimeout(function () { copyLink.textContent = "Salin tautan hasil"; }, 2600);
      });
    });
  }

  $$("form[data-confirm]").forEach(function (formNode) {
    formNode.addEventListener("submit", function (event) {
      var message = formNode.getAttribute("data-confirm") || "Lanjutkan?";
      if (!window.confirm(message)) event.preventDefault();
    });
  });

  $$(".nav a[href^='#']").forEach(function (link) {
    link.addEventListener("click", function (event) {
      if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
      var target = document.querySelector(link.getAttribute("href"));
      if (target) {
        event.preventDefault();
        target.scrollIntoView({ behavior: "smooth", block: "start" });
      }
    });
  });
})();
