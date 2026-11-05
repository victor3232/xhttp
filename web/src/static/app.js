/* HITS SSH interactions */
(function () {
  "use strict";

  var $ = function (sel, root) { return (root || document).querySelector(sel); };
  var $$ = function (sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); };

  function readJson(id) {
    var node = document.getElementById(id);
    if (!node) return null;
    try { return JSON.parse(node.textContent || "{}"); } catch (e) { return null; }
  }

  var navHeader = $(".nav-public");
  var navToggle = $("#nav-toggle");
  var navScrim = $("#nav-scrim");

  function setMenu(open) {
    if (!navHeader || !navToggle) return;
    navHeader.classList.toggle("menu-open", open);
    document.body.classList.toggle("menu-open", open);
    navToggle.setAttribute("aria-expanded", open ? "true" : "false");
    navToggle.setAttribute("aria-label", open ? "Tutup menu" : "Buka menu");
    if (!navScrim) return;
    if (open) {
      navScrim.hidden = false;
      window.requestAnimationFrame(function () { navScrim.classList.add("show"); });
    } else {
      navScrim.classList.remove("show");
      window.setTimeout(function () { navScrim.hidden = true; }, 170);
    }
  }

  if (navToggle) {
    navToggle.addEventListener("click", function () {
      setMenu(!navHeader.classList.contains("menu-open"));
    });
    if (navScrim) navScrim.addEventListener("click", function () { setMenu(false); });
    $$("#site-menu a").forEach(function (link) {
      link.addEventListener("click", function () { setMenu(false); });
    });
    document.addEventListener("keydown", function (event) {
      if (event.key === "Escape") setMenu(false);
    });
    window.addEventListener("resize", function () {
      if (window.innerWidth > 900) setMenu(false);
    });
  }

  var quota = readJson("quota-data");
  var webcfg = readJson("web-config") || {
    free: true,
    ssh: true,
    xray: true,
    protocols: { vmess: true, vless: true, trojan: true },
    maintenance: false
  };
  var premium = readJson("premium-data") || { products: [] };
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
    if (webcfg.free === false) return false;
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

  function premiumRp(value) {
    return "Rp " + Number(value).toLocaleString("id-ID");
  }

  var premiumForm = $("#premium-form");
  var premiumProductInput = $("#premium-product");
  var premiumButton = $("#premium-button");
  var premiumSummary = $("#premium-summary");
  var premiumState = { protocol: "", code: "" };

  function premiumItems(protocol) {
    return (premium.products || []).filter(function (p) { return p.protocol === protocol; });
  }

  function choosePremiumProduct(product) {
    if (!product) {
      premiumState.code = "";
      if (premiumProductInput) premiumProductInput.value = "";
      if (premiumButton) premiumButton.disabled = true;
      if (premiumSummary) premiumSummary.hidden = true;
      return;
    }
    premiumState.code = product.code;
    if (premiumProductInput) premiumProductInput.value = product.code;
    if (premiumButton) premiumButton.disabled = false;
    if (premiumSummary) premiumSummary.hidden = false;
    var name = $("#premium-summary-name");
    var price = $("#premium-summary-price");
    var days = $("#premium-summary-days");
    if (name) name.textContent = product.label;
    if (price) price.textContent = premiumRp(product.price) + " + kode unik";
    if (days) days.textContent = product.days + " hari";
  }

  function renderPremiumDurations(protocol) {
    var box = $("#premium-durations");
    if (!box) return;
    var items = premiumItems(protocol);
    box.innerHTML = "";
    if (!items.length) {
      box.innerHTML = '<p class="premium-hint">Belum ada paket untuk layanan ini.</p>';
      choosePremiumProduct(null);
      return;
    }
    items.forEach(function (item) {
      var button = document.createElement("button");
      button.type = "button";
      button.className = "premium-duration";
      button.setAttribute("data-code", item.code);
      button.innerHTML = '<b>' + item.days + ' hari</b><span>' + premiumRp(item.price) + '</span>';
      button.addEventListener("click", function () {
        $$(".premium-duration").forEach(function (node) { node.classList.remove("selected"); });
        button.classList.add("selected");
        choosePremiumProduct(item);
      });
      box.appendChild(button);
    });
    var first = box.querySelector(".premium-duration");
    if (first) first.click();
  }

  function selectPremiumProtocol(protocol) {
    premiumState.protocol = protocol;
    $$(".premium-service").forEach(function (node) {
      node.classList.toggle("selected", node.getAttribute("data-protocol") === protocol);
    });
    renderPremiumDurations(protocol);
  }

  $$(".premium-service").forEach(function (button) {
    button.addEventListener("click", function () {
      selectPremiumProtocol(button.getAttribute("data-protocol"));
    });
  });

  if (premiumForm) {
    premiumForm.addEventListener("submit", function (event) {
      if (!premiumState.code) {
        event.preventDefault();
        return;
      }
      if (premiumButton) {
        premiumButton.disabled = true;
        premiumButton.innerHTML = '<span class="spinner"></span> Membuat invoice…';
      }
    });
  }

  var firstPremium = $(".premium-service");
  if (firstPremium) firstPremium.click();

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

  document.addEventListener("click", function (event) {
    var button = event.target.closest ? event.target.closest("[data-copy]") : null;
    if (!button) return;
    var text = button.getAttribute("data-copy") || "";
    copyText(text).then(function (ok) {
      var old = button.textContent;
      button.textContent = ok ? "Tersalin ✓" : "Gagal salin";
      window.setTimeout(function () { button.textContent = old; }, 1800);
    });
  });

  var copyInvoiceAccount = $("#copy-invoice-account");
  if (copyInvoiceAccount) {
    copyInvoiceAccount.addEventListener("click", function () {
      var output = $("#invoice-account");
      if (!output) return;
      copyText(output.textContent || "").then(function (ok) {
        copyInvoiceAccount.textContent = ok ? "Tersalin ✓" : "Gagal salin";
        window.setTimeout(function () { copyInvoiceAccount.textContent = "Salin akun"; }, 1800);
      });
    });
  }

  var invoiceHistory = $("#invoice-history");

  function readInvoiceHistory() {
    try {
      var data = JSON.parse(window.localStorage.getItem("hits_invoices_v1") || "[]");
      return Array.isArray(data) ? data.slice(0, 8) : [];
    } catch (e) {
      return [];
    }
  }

  function writeInvoiceHistory(items) {
    try {
      window.localStorage.setItem("hits_invoices_v1", JSON.stringify(items.slice(0, 8)));
    } catch (e) {}
  }

  function saveInvoiceHistory(data) {
    if (!data || !data.invoice) return;
    var items = readInvoiceHistory().filter(function (item) {
      return item && item.invoice !== data.invoice;
    });
    items.unshift({
      invoice: data.invoice,
      status: data.status || "PENDING",
      total: Number(data.total || 0),
      label: data.label || ""
    });
    writeInvoiceHistory(items);
  }

  function invoiceStatusLabel(status) {
    return {
      PENDING: "Menunggu bayar",
      PAID: "Sudah dibayar",
      PROVISIONING: "Menyiapkan",
      COMPLETED: "Selesai",
      FAILED: "Gagal akun",
      EXPIRED: "Kedaluwarsa"
    }[status] || status;
  }

  function renderInvoiceHistory() {
    if (!invoiceHistory) return;
    var items = readInvoiceHistory();
    invoiceHistory.innerHTML = "";
    if (!items.length) {
      var empty = document.createElement("p");
      empty.className = "invoice-history-empty";
      empty.textContent = invoiceHistory.getAttribute("data-empty") || "Belum ada invoice tersimpan.";
      invoiceHistory.appendChild(empty);
      return;
    }
    items.forEach(function (item) {
      var link = document.createElement("a");
      link.href = "/invoice/" + encodeURIComponent(item.invoice);
      var code = document.createElement("code");
      code.textContent = item.invoice;
      var meta = document.createElement("span");
      meta.textContent = invoiceStatusLabel(item.status) + (item.total ? " · " + premiumRp(item.total) : "");
      link.appendChild(code);
      link.appendChild(meta);
      invoiceHistory.appendChild(link);
    });
  }

  if (invoiceHistory) renderInvoiceHistory();

  var invoiceData = readJson("invoice-data");
  if (invoiceData && invoiceData.invoice) {
    saveInvoiceHistory(invoiceData);
    var invoiceDialog = $("#invoice-dialog");
    if (invoiceDialog && typeof invoiceDialog.showModal === "function") {
      invoiceDialog.showModal();
    }
    var dialogClose = $("#invoice-dialog-close");
    if (dialogClose && invoiceDialog) {
      dialogClose.addEventListener("click", function () { invoiceDialog.close(); });
    }

    var invoiceCountdown = $("#invoice-countdown");
    if (invoiceCountdown) {
      var expires = Number(invoiceCountdown.getAttribute("data-expires")) * 1000;
      var updateInvoiceCountdown = function () {
        var diff = Math.max(0, expires - Date.now());
        var total = Math.floor(diff / 1000);
        var m = Math.floor(total / 60);
        var s = total % 60;
        invoiceCountdown.textContent = diff > 0 ? ("Sisa " + String(m).padStart(2, "0") + ":" + String(s).padStart(2, "0")) : "Waktu habis";
      };
      updateInvoiceCountdown();
      window.setInterval(updateInvoiceCountdown, 1000);
    }

    var pollInvoice = function () {
      fetch("/api/invoice/" + encodeURIComponent(invoiceData.invoice), { cache: "no-store" })
        .then(function (r) { return r.json(); })
        .then(function (data) {
          if (!data || !data.ok) return;
          if (data.status !== invoiceData.status) {
            window.clearInterval(invoicePollTimer);
            window.location.reload();
          }
        })
        .catch(function () {});
    };
    var invoicePollTimer = null;
    if (["PENDING", "PAID", "PROVISIONING", "EXPIRED"].indexOf(invoiceData.status) >= 0) {
      invoicePollTimer = window.setInterval(pollInvoice, 5000);
    }
  }

  $$(".cf-turnstile").forEach(function (widget) {
    var status = widget.parentElement ? widget.parentElement.querySelector("[data-turnstile-status]") : null;
    if (!status) return;
    var tries = 0;
    var timer = window.setInterval(function () {
      var input = widget.querySelector('input[name="cf-turnstile-response"]');
      if (input && input.value) {
        status.textContent = "Verifikasi keamanan selesai ✓";
        status.classList.add("ok");
        status.classList.remove("bad");
        window.clearInterval(timer);
      } else if (++tries > 40) {
        status.textContent = "Verifikasi belum selesai. Muat ulang halaman atau matikan pemblokir.";
        status.classList.add("bad");
        window.clearInterval(timer);
      }
    }, 500);
  });

  var logoInput = $("#brand-logo-input");
  if (logoInput) {
    logoInput.addEventListener("change", function () {
      var file = logoInput.files && logoInput.files[0];
      if (!file) return;
      if (file.size > 2 * 1024 * 1024) {
        window.alert("Logo maksimal 2 MB. Kompres file terlebih dahulu.");
        logoInput.value = "";
        return;
      }
      var reader = new FileReader();
      reader.onload = function (event) {
        var image = new Image();
        image.onload = function () {
          if (image.width < 128 || image.height < 128) {
            window.alert("Logo minimal 128×128 piksel. Pilih gambar yang lebih besar.");
            logoInput.value = "";
            return;
          }
          var side = Math.min(image.width, image.height);
          var sx = Math.floor((image.width - side) / 2);
          var sy = Math.floor((image.height - side) / 2);
          var canvas = document.createElement("canvas");
          canvas.width = 256;
          canvas.height = 256;
          var context = canvas.getContext("2d");
          context.clearRect(0, 0, 256, 256);
          context.drawImage(image, sx, sy, side, side, 0, 0, 256, 256);
          var data = canvas.toDataURL("image/webp", 0.9);
          if (data.indexOf("data:image/webp") !== 0) {
            data = canvas.toDataURL("image/png");
          }
          var hidden = $("#brand-logo-data");
          if (hidden) hidden.value = data;
          var preview = $("#brand-logo-preview");
          if (preview) preview.src = data;
          var label = $("#brand-logo-name");
          if (label) {
            label.textContent = file.name + " · " + image.width + "×" + image.height + " → 256×256";
          }
        };
        image.onerror = function () {
          window.alert("File tidak bisa dibaca sebagai gambar.");
          logoInput.value = "";
        };
        image.src = event.target.result;
      };
      reader.readAsDataURL(file);
    });
  }

  $$("button[data-confirm]").forEach(function (button) {
    button.addEventListener("click", function (event) {
      var message = button.getAttribute("data-confirm") || "Lanjutkan?";
      if (!window.confirm(message)) event.preventDefault();
    });
  });

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
        target.scrollIntoView({ block: "start" });
      }
    });
  });
})();
