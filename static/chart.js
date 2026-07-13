/* =========================================================
   HEXA SHIELD - AI PHISHING EMAIL DETECTOR
   FINAL CHART.JS
========================================================= */

"use strict";

document.addEventListener("DOMContentLoaded", () => {
    initDashboardCharts();
});


/* =========================================================
   DASHBOARD CHARTS
========================================================= */

function initDashboardCharts() {

    if (typeof Chart === "undefined") {

        console.warn("Chart.js library not loaded.");

        return;

    }

    createVerdictChart();

    createMonthlyChart();

}


/* =========================================================
   SAFE / SUSPICIOUS / PHISHING CHART
========================================================= */

function createVerdictChart() {

    const canvas = document.getElementById(
        "verdictChart"
    );

    if (!canvas) return;

    const safe = Number(
        canvas.dataset.safe || 0
    );

    const suspicious = Number(
        canvas.dataset.suspicious || 0
    );

    const phishing = Number(
        canvas.dataset.phishing || 0
    );

    new Chart(canvas, {

        type: "doughnut",

        data: {

            labels: [
                "Safe",
                "Suspicious",
                "Phishing"
            ],

            datasets: [

                {

                    data: [
                        safe,
                        suspicious,
                        phishing
                    ],

                    backgroundColor: [
                        "#16a34a",
                        "#d97706",
                        "#dc2626"
                    ],

                    borderWidth: 0,

                    hoverOffset: 8

                }

            ]

        },

        options: {

            responsive: true,

            maintainAspectRatio: false,

            cutout: "70%",

            plugins: {

                legend: {

                    position: "bottom",

                    labels: {

                        usePointStyle: true,

                        padding: 20

                    }

                },

                tooltip: {

                    callbacks: {

                        label: function(context) {

                            const value =
                                context.raw || 0;

                            return (
                                context.label +
                                ": " +
                                value +
                                " scans"
                            );

                        }

                    }

                }

            }

        }

    });

}


/* =========================================================
   MONTHLY SCAN CHART
========================================================= */

function createMonthlyChart() {

    const canvas = document.getElementById(
        "monthlyChart"
    );

    if (!canvas) return;

    const labels = parseChartData(
        canvas.dataset.labels
    );

    const values = parseChartData(
        canvas.dataset.values
    );

    new Chart(canvas, {

        type: "line",

        data: {

            labels: labels,

            datasets: [

                {

                    label: "Monthly Scans",

                    data: values,

                    borderColor: "#2563eb",

                    backgroundColor:
                        "rgba(37, 99, 235, 0.15)",

                    fill: true,

                    tension: 0.4,

                    pointRadius: 4,

                    pointHoverRadius: 7,

                    borderWidth: 3

                }

            ]

        },

        options: {

            responsive: true,

            maintainAspectRatio: false,

            interaction: {

                intersect: false,

                mode: "index"

            },

            scales: {

                y: {

                    beginAtZero: true,

                    ticks: {

                        precision: 0

                    },

                    grid: {

                        color:
                            "rgba(148, 163, 184, 0.15)"

                    }

                },

                x: {

                    grid: {

                        display: false

                    }

                }

            },

            plugins: {

                legend: {

                    display: false

                },

                tooltip: {

                    callbacks: {

                        label: function(context) {

                            return (
                                "Scans: " +
                                context.raw
                            );

                        }

                    }

                }

            }

        }

    });

}


/* =========================================================
   PARSE DATA
========================================================= */

function parseChartData(data) {

    if (!data) {

        return [];

    }

    try {

        const parsed = JSON.parse(data);

        if (Array.isArray(parsed)) {

            return parsed;

        }

        return [];

    } catch (error) {

        console.error(
            "Chart Data Parse Error:",
            error
        );

        return [];

    }

}


/* =========================================================
   UPDATE CHART THEME
========================================================= */

function updateChartTheme() {

    if (typeof Chart === "undefined") {

        return;

    }

    const darkMode =
        document.body.classList.contains(
            "dark-mode"
        );

    Chart.defaults.color = darkMode
        ? "#cbd5e1"
        : "#475569";

    Chart.defaults.borderColor = darkMode
        ? "rgba(148, 163, 184, 0.15)"
        : "rgba(100, 116, 139, 0.15)";

}


/* =========================================================
   GLOBAL CHART FUNCTIONS
========================================================= */

window.HexaCharts = {

    initDashboardCharts,

    createVerdictChart,

    createMonthlyChart,

    updateChartTheme

};


/* =========================================================
   END CHART.JS
========================================================= */