/* =========================================================
   HEXA SHIELD - AI PHISHING EMAIL DETECTOR
   FINAL SCRIPT.JS
========================================================= */

"use strict";

document.addEventListener("DOMContentLoaded", () => {
    initTheme();
    initAlerts();
    initPasswordToggle();
    initFormLoading();
    initDeleteConfirm();
    initClearHistory();
    initRiskDisplay();
    initCopyButtons();
    initCharacterCounters();
    initTooltips();
});


/* =========================================================
   DARK / LIGHT THEME
========================================================= */

function initTheme() {

    const themeToggle = document.querySelector(
        "#themeToggle, [data-theme-toggle]"
    );

    const savedTheme = localStorage.getItem("hexa-theme");

    if (savedTheme === "dark") {
        applyTheme("dark");
    }

    if (savedTheme === "light") {
        applyTheme("light");
    }

    if (!themeToggle) return;

    themeToggle.addEventListener("click", () => {

        const isDark = document.body.classList.contains(
            "dark-mode"
        );

        const theme = isDark ? "light" : "dark";

        applyTheme(theme);

        localStorage.setItem(
            "hexa-theme",
            theme
        );

    });

}


function applyTheme(theme) {

    const dark = theme === "dark";

    document.body.classList.toggle(
        "dark-mode",
        dark
    );

    document.documentElement.setAttribute(
        "data-theme",
        dark ? "dark" : "light"
    );

}


/* =========================================================
   AUTO DISMISS ALERT
========================================================= */

function initAlerts() {

    const alerts = document.querySelectorAll(".alert");

    alerts.forEach((alert) => {

        if (alert.dataset.persist === "true") {
            return;
        }

        setTimeout(() => {

            if (
                window.bootstrap &&
                bootstrap.Alert
            ) {

                bootstrap.Alert
                    .getOrCreateInstance(alert)
                    .close();

                return;

            }

            alert.style.opacity = "0";

            alert.style.transform =
                "translateY(-10px)";

            setTimeout(() => {

                alert.remove();

            }, 300);

        }, 5000);

    });

}


/* =========================================================
   PASSWORD SHOW / HIDE
========================================================= */

function initPasswordToggle() {

    const buttons = document.querySelectorAll(
        "[data-password-toggle]"
    );

    buttons.forEach((button) => {

        button.addEventListener("click", () => {

            const selector =
                button.dataset.passwordToggle;

            const input =
                document.querySelector(selector);

            if (!input) return;

            if (input.type === "password") {

                input.type = "text";

            } else {

                input.type = "password";

            }

        });

    });

}


/* =========================================================
   FORM LOADING
========================================================= */

function initFormLoading() {

    const forms = document.querySelectorAll("form");

    forms.forEach((form) => {

        form.addEventListener("submit", () => {

            if (!form.checkValidity()) {
                return;
            }

            const button = form.querySelector(
                'button[type="submit"]'
            );

            if (!button) return;

            if (
                button.dataset.noLoading === "true"
            ) {
                return;
            }

            button.disabled = true;

            button.dataset.originalText =
                button.innerHTML;

            button.innerHTML = `
                <span
                    class="spinner-border spinner-border-sm me-2"
                ></span>
                Processing...
            `;

        });

    });

}


/* =========================================================
   DELETE CONFIRMATION
========================================================= */

function initDeleteConfirm() {

    const deleteForms = document.querySelectorAll(
        ".delete-form, [data-confirm-delete]"
    );

    deleteForms.forEach((element) => {

        const form = element.tagName === "FORM"
            ? element
            : element.closest("form");

        if (!form) return;

        form.addEventListener(
            "submit",
            (event) => {

                const confirmDelete = confirm(
                    "Are you sure you want to delete this item?"
                );

                if (!confirmDelete) {

                    event.preventDefault();

                }

            }
        );

    });

}


/* =========================================================
   CLEAR HISTORY CONFIRMATION
========================================================= */

function initClearHistory() {

    const forms = document.querySelectorAll(
        'form[action*="/history/clear"]'
    );

    forms.forEach((form) => {

        form.addEventListener(
            "submit",
            (event) => {

                const confirmed = confirm(
                    "Clear all scan history? This action cannot be undone."
                );

                if (!confirmed) {

                    event.preventDefault();

                }

            }
        );

    });

}


/* =========================================================
   RISK SCORE PROGRESS BAR
========================================================= */

function initRiskDisplay() {

    const riskElements = document.querySelectorAll(
        "[data-risk-score]"
    );

    riskElements.forEach((element) => {

        let score = Number(
            element.dataset.riskScore
        );

        score = Math.max(
            0,
            Math.min(100, score || 0)
        );

        const selector =
            element.dataset.progressTarget;

        if (!selector) return;

        const progress =
            document.querySelector(selector);

        if (!progress) return;

        progress.style.width = score + "%";

        progress.setAttribute(
            "aria-valuenow",
            score
        );

        progress.classList.remove(
            "bg-success",
            "bg-warning",
            "bg-danger"
        );

        if (score <= 30) {

            progress.classList.add(
                "bg-success"
            );

        } else if (score <= 60) {

            progress.classList.add(
                "bg-warning"
            );

        } else {

            progress.classList.add(
                "bg-danger"
            );

        }

    });

}


/* =========================================================
   COPY BUTTON
========================================================= */

function initCopyButtons() {

    const buttons = document.querySelectorAll(
        "[data-copy-target]"
    );

    buttons.forEach((button) => {

        button.addEventListener(
            "click",
            async () => {

                const selector =
                    button.dataset.copyTarget;

                const target =
                    document.querySelector(selector);

                if (!target) return;

                const text =
                    target.value ||
                    target.textContent ||
                    "";

                try {

                    await navigator.clipboard.writeText(
                        text.trim()
                    );

                    const oldText =
                        button.textContent;

                    button.textContent =
                        "Copied!";

                    setTimeout(() => {

                        button.textContent =
                            oldText;

                    }, 1500);

                } catch (error) {

                    console.error(
                        "Copy Error:",
                        error
                    );

                }

            }
        );

    });

}


/* =========================================================
   CHARACTER COUNTER
========================================================= */

function initCharacterCounters() {

    const inputs = document.querySelectorAll(
        "[data-counter-target]"
    );

    inputs.forEach((input) => {

        const selector =
            input.dataset.counterTarget;

        const counter =
            document.querySelector(selector);

        if (!counter) return;

        function updateCounter() {

            counter.textContent =
                input.value.length;

        }

        input.addEventListener(
            "input",
            updateCounter
        );

        updateCounter();

    });

}


/* =========================================================
   BOOTSTRAP TOOLTIP
========================================================= */

function initTooltips() {

    if (
        !window.bootstrap ||
        !bootstrap.Tooltip
    ) {
        return;
    }

    const elements = document.querySelectorAll(
        '[data-bs-toggle="tooltip"]'
    );

    elements.forEach((element) => {

        new bootstrap.Tooltip(element);

    });

}


/* =========================================================
   DASHBOARD API
========================================================= */

async function fetchDashboardData() {

    try {

        const response = await fetch(
            "/api/dashboard",
            {
                headers: {
                    Accept: "application/json"
                },

                credentials: "same-origin"
            }
        );

        if (!response.ok) {

            throw new Error(
                "Dashboard API Error"
            );

        }

        return await response.json();

    } catch (error) {

        console.error(
            "Dashboard Error:",
            error
        );

        return null;

    }

}


/* =========================================================
   SCAN DETAILS API
========================================================= */

async function getScanDetails(scanId) {

    if (!scanId) {
        return null;
    }

    try {

        const response = await fetch(

            `/scan/${encodeURIComponent(scanId)}`,

            {

                headers: {

                    Accept: "application/json"

                },

                credentials: "same-origin"

            }

        );

        if (!response.ok) {

            throw new Error(
                "Scan API Error"
            );

        }

        return await response.json();

    } catch (error) {

        console.error(
            "Scan Error:",
            error
        );

        return null;

    }

}


/* =========================================================
   SYSTEM STATUS API
========================================================= */

async function checkSystemStatus() {

    try {

        const response = await fetch(
            "/api/status"
        );

        if (!response.ok) {

            throw new Error(
                "Status API Error"
            );

        }

        return await response.json();

    } catch (error) {

        console.error(
            "System Status Error:",
            error
        );

        return null;

    }

}


/* =========================================================
   GLOBAL APP FUNCTIONS
========================================================= */

window.HexaShield = {

    fetchDashboardData,

    getScanDetails,

    checkSystemStatus,

    applyTheme

};


/* =========================================================
   END SCRIPT.JS
========================================================= */