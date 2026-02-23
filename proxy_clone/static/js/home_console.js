(function () {
    "use strict";

    class ProxyHomeController {
        constructor(root) {
            this.root = root;
            this.apiQueryUrl = root.dataset.apiQueryUrl;
            this.apiTablesUrl = root.dataset.apiTablesUrl;
            this.shouldLoadSchema = root.dataset.loadSchema === "true";
            this.queryInput = document.getElementById("queryInput");
            this.resultsContainer = document.getElementById("resultsContainer");
            this.resultCount = document.getElementById("resultCount");
            this.queryStatus = document.getElementById("queryStatus");
            this.schemaContainer = document.getElementById("schemaContainer");
            this.executeButton = document.getElementById("executeQueryBtn");
            this.clearButton = document.getElementById("clearQueryBtn");
        }

        init() {
            this.bindEvents();
            if (this.shouldLoadSchema) {
                void this.loadSchema();
            }
        }

        bindEvents() {
            if (this.executeButton) {
                this.executeButton.addEventListener("click", () => {
                    void this.executeQuery();
                });
            }
            if (this.clearButton) {
                this.clearButton.addEventListener("click", () => this.clearAll());
            }

            this.root.addEventListener("click", (event) => {
                const target = event.target;
                if (!(target instanceof Element)) {
                    return;
                }
                const button = target.closest("[data-sample-table]");
                if (!(button instanceof HTMLElement)) {
                    return;
                }
                this.loadSampleQuery(button.dataset.sampleTable || "");
            });

            if (this.queryInput) {
                this.queryInput.addEventListener("keydown", (event) => {
                    if (event.ctrlKey && event.key === "Enter") {
                        event.preventDefault();
                        void this.executeQuery();
                    }
                });
            }
        }

        escapeHtml(value) {
            return String(value)
                .replace(/&/g, "&amp;")
                .replace(/</g, "&lt;")
                .replace(/>/g, "&gt;")
                .replace(/"/g, "&quot;")
                .replace(/'/g, "&#39;");
        }

        renderCellValue(value) {
            if (value === null || value === undefined) {
                return '<span class="text-muted">null</span>';
            }
            return this.escapeHtml(value);
        }

        loadSampleQuery(table) {
            if (!this.queryInput || !table) {
                return;
            }
            const queries = {
                employees: "SELECT * FROM employees ORDER BY salary DESC LIMIT 10",
                departments: "SELECT * FROM departments ORDER BY budget DESC",
                projects: "SELECT * FROM projects WHERE status = 'active'",
            };
            this.queryInput.value = queries[table] || `SELECT * FROM ${table}`;
        }

        clearAll() {
            if (!this.queryInput || !this.resultsContainer || !this.resultCount || !this.queryStatus) {
                return;
            }
            this.queryInput.value = "";
            this.resultsContainer.innerHTML = `
                <div class="text-center py-5 text-muted">
                    <i class="bi bi-inbox fs-1 d-block mb-3"></i>
                    <p>Execute a query to see results here</p>
                </div>
            `;
            this.resultCount.textContent = "0 rows";
            this.queryStatus.textContent = "";
            this.queryStatus.className = "text-muted small";
        }

        async executeQuery() {
            if (!this.queryInput || !this.resultsContainer || !this.resultCount || !this.queryStatus) {
                return;
            }
            const query = this.queryInput.value.trim();
            if (!query) {
                alert("Please enter a query");
                return;
            }

            this.queryStatus.textContent = "Executing...";
            this.queryStatus.className = "text-warning small";
            const startTime = performance.now();

            try {
                const response = await fetch(this.apiQueryUrl, {
                    method: "POST",
                    headers: {"Content-Type": "application/json"},
                    body: JSON.stringify({query}),
                });
                const data = await response.json();
                const duration = (performance.now() - startTime).toFixed(0);

                if (data.success) {
                    this.queryStatus.textContent = `Completed in ${duration}ms`;
                    this.queryStatus.className = "text-success small";
                    this.resultCount.textContent = `${data.row_count} rows`;
                    this.renderResults(data);
                    return;
                }

                this.queryStatus.textContent = "Error";
                this.queryStatus.className = "text-danger small";
                this.resultsContainer.innerHTML = `
                    <div class="alert alert-danger">
                        <i class="bi bi-exclamation-triangle me-2"></i>
                        <strong>Error:</strong> ${this.escapeHtml(data.error || "Unknown error")}
                    </div>
                `;
            } catch (error) {
                const message = error instanceof Error ? error.message : String(error);
                this.queryStatus.textContent = "Error";
                this.queryStatus.className = "text-danger small";
                this.resultsContainer.innerHTML = `
                    <div class="alert alert-danger">
                        <i class="bi bi-exclamation-triangle me-2"></i>
                        <strong>Error:</strong> ${this.escapeHtml(message)}
                    </div>
                `;
            }
        }

        renderResults(data) {
            if (!this.resultsContainer) {
                return;
            }

            if (!data.data || data.data.length === 0) {
                this.resultsContainer.innerHTML = `
                    <div class="text-center py-4 text-muted">
                        <i class="bi bi-inbox fs-3 d-block mb-2"></i>
                        Query executed successfully. No rows returned.
                    </div>
                `;
                return;
            }

            const columns = data.columns || [];
            this.resultsContainer.innerHTML = `
                <div class="table-responsive">
                    <table class="table table-hover mb-0">
                        <thead>
                            <tr>${columns.map((col) => `<th>${this.escapeHtml(col)}</th>`).join("")}</tr>
                        </thead>
                        <tbody>
                            ${data.data.map((row) => `
                                <tr>${columns.map((col) => `<td>${this.renderCellValue(row[col])}</td>`).join("")}</tr>
                            `).join("")}
                        </tbody>
                    </table>
                </div>
            `;
        }

        async loadSchema() {
            if (!this.schemaContainer) {
                return;
            }
            try {
                const response = await fetch(this.apiTablesUrl);
                const data = await response.json();

                if (!data.tables) {
                    return;
                }

                this.schemaContainer.innerHTML = data.tables.map((table) => `
                    <div class="schema-card" data-sample-table="${this.escapeHtml(table.name)}" role="button" tabindex="0">
                        <div class="d-flex justify-content-between align-items-center">
                            <h6><i class="bi bi-table me-2"></i>${this.escapeHtml(table.name)}</h6>
                            <span class="badge bg-secondary">${this.escapeHtml(table.row_count)} rows</span>
                        </div>
                        <small class="text-muted">
                            ${table.columns.map((column) => this.escapeHtml(column.name)).join(", ")}
                        </small>
                    </div>
                `).join("");

                this.schemaContainer.querySelectorAll("[data-sample-table]").forEach((card) => {
                    card.addEventListener("keydown", (event) => {
                        if (!(event instanceof KeyboardEvent)) {
                            return;
                        }
                        if (event.key === "Enter" || event.key === " ") {
                            event.preventDefault();
                            this.loadSampleQuery(card.getAttribute("data-sample-table") || "");
                        }
                    });
                });
            } catch (_error) {
                this.schemaContainer.innerHTML = `
                    <div class="text-center text-muted py-3">
                        Failed to load schema
                    </div>
                `;
            }
        }
    }

    document.addEventListener("DOMContentLoaded", () => {
        const root = document.getElementById("proxy-home-app");
        if (!(root instanceof HTMLElement)) {
            return;
        }
        new ProxyHomeController(root).init();
    });
})();
