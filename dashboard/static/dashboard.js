// Dashboard client behaviour. Loaded from 'self' so it satisfies the strict
// Content Security Policy (no inline executable scripts). Chart input is read
// from a non-executable JSON data block emitted by index.html.
(function () {
    "use strict";

    var LEVEL_COLORS = {
        CRITICAL: "#ef4444",
        ERROR: "#f97316",
        WARNING: "#f59e0b",
        INFO: "#38bdf8",
        DEBUG: "#64748b"
    };

    function renderEventsByLevelChart() {
        var canvas = document.getElementById("events-by-level-chart");
        if (!canvas || typeof Chart === "undefined") {
            return;
        }

        var dataElement = document.getElementById("audit-level-data");
        var counts = {};
        if (dataElement) {
            try {
                counts = JSON.parse(dataElement.textContent) || {};
            } catch (error) {
                counts = {};
            }
        }

        var labels = Object.keys(counts);
        if (labels.length === 0) {
            return;
        }

        var values = labels.map(function (label) {
            return counts[label];
        });
        var colors = labels.map(function (label) {
            return LEVEL_COLORS[label] || "#6366f1";
        });

        new Chart(canvas, {
            type: "bar",
            data: {
                labels: labels,
                datasets: [{
                    label: "Events",
                    data: values,
                    backgroundColor: colors,
                    borderRadius: 6,
                    maxBarThickness: 64
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: { duration: 600 },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: "#0f172a",
                        borderColor: "#1e293b",
                        borderWidth: 1
                    }
                },
                scales: {
                    x: {
                        ticks: { color: "#94a3b8" },
                        grid: { display: false }
                    },
                    y: {
                        beginAtZero: true,
                        ticks: { color: "#94a3b8", precision: 0 },
                        grid: { color: "rgba(148, 163, 184, 0.1)" }
                    }
                }
            }
        });
    }

    function dismissToasts() {
        var toasts = document.querySelectorAll("[data-toast]");
        toasts.forEach(function (toast) {
            window.setTimeout(function () {
                toast.classList.add("opacity-0", "translate-x-4");
                window.setTimeout(function () {
                    toast.remove();
                }, 500);
            }, 5000);
        });
    }

    function initLiveFeed() {
        if (!window.EventSource) return;
        var badge = document.getElementById("live-badge");
        var tableBody = document.querySelector("tbody");
        if (!tableBody) return;

        var source = new EventSource("/events/stream");

        source.onopen = function () {
            if (badge) badge.classList.remove("hidden");
        };

        source.onmessage = function (e) {
            try {
                var event = JSON.parse(e.data);
                var levelColors = {
                    "CRITICAL": "bg-red-500/15 text-red-300 ring-1 ring-red-500/30",
                    "ERROR":    "bg-orange-500/15 text-orange-300 ring-1 ring-orange-500/30",
                    "WARNING":  "bg-amber-500/15 text-amber-300 ring-1 ring-amber-500/30",
                    "INFO":     "bg-cyan-500/15 text-cyan-300 ring-1 ring-cyan-500/30",
                };
                var colorClass = levelColors[event.level] || "bg-slate-500/15 text-slate-300 ring-1 ring-slate-500/30";
                var row = document.createElement("tr");
                row.className = "transition-colors duration-150 hover:bg-slate-800/40 animate-pulse-once";
                row.innerHTML = [
                    '<td class="whitespace-nowrap px-6 py-3 font-mono text-xs text-slate-400">' + (event.timestamp || "") + "</td>",
                    '<td class="whitespace-nowrap px-6 py-3"><span class="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium ' + colorClass + '">' + (event.level || "") + "</span></td>",
                    '<td class="whitespace-nowrap px-6 py-3 text-slate-300">' + (event.module_source || "") + "</td>",
                    '<td class="px-6 py-3 text-slate-300">' + (event.message || "") + "</td>",
                ].join("");
                tableBody.prepend(row);
            } catch (_) {}
        };

        source.onerror = function () {
            if (badge) badge.classList.add("hidden");
        };
    }

    function init() {
        renderEventsByLevelChart();
        dismissToasts();
        initLiveFeed();
    }

    if (document.readyState === "loading") {
        document.addEventListener("DOMContentLoaded", init);
    } else {
        init();
    }
})();
