(function () {
    "use strict";

    class DatabaseQueryConsoleController {
        constructor(root) {
            this.root = root;
            this.apiTablesUrl = root.dataset.apiTablesUrl;
            this.apiQueryUrl = root.dataset.apiQueryUrl;
            this.queryInput = document.getElementById("queryInput");
            this.resultsContainer = document.getElementById("resultsContainer");
            this.resultCount = document.getElementById("resultCount");
            this.queryStatus = document.getElementById("queryStatus");
            this.schemaAccordion = document.getElementById("schemaAccordion");
            this.executeButton = document.getElementById("executeQueryBtn");
            this.clearButton = document.getElementById("clearQueryBtn");
        }

        init() {
            if (!this.queryInput || !this.resultsContainer || !this.resultCount || !this.queryStatus) {
                return;
            }

            this.bindEvents();
            void this.loadSchema();
        }

        bindEvents() {
            if (this.executeButton) {
                this.executeButton.addEventListener("click", () => {
                    void this.executeQuery();
                });
            }

            if (this.clearButton) {
                this.clearButton.addEventListener("click", () => this.clearQuery());
            }

            this.root.querySelectorAll("[data-sample-table]").forEach((button) => {
                button.addEventListener("click", () => {
                    this.insertSample(button.getAttribute("data-sample-table") || "");
                });
            });

            if (this.schemaAccordion) {
                this.schemaAccordion.addEventListener("click", (event) => {
                    const target = event.target;
                    if (!(target instanceof Element)) {
                        return;
                    }
                    const button = target.closest("[data-sample-table]");
                    if (!(button instanceof HTMLElement)) {
                        return;
                    }
                    this.insertSample(button.dataset.sampleTable || "");
                });
            }

            this.queryInput.addEventListener("keydown", (event) => {
                if (event.ctrlKey && event.key === "Enter") {
                    event.preventDefault();
                    void this.executeQuery();
                }
            });
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

        insertSample(table) {
            if (!this.queryInput || !table) {
                return;
            }
            this.queryInput.value = `SELECT * FROM ${table} LIMIT 10`;
        }

        clearQuery() {
            if (!this.queryInput || !this.resultsContainer || !this.resultCount || !this.queryStatus) {
                return;
            }
            this.queryInput.value = "";
            this.resultsContainer.innerHTML = `
                <div class="text-center text-muted py-5">
                    <i class="bi bi-inbox fs-1 d-block mb-2"></i>
                    Execute a query to see results
                </div>
            `;
            this.resultCount.textContent = "0 rows";
            this.queryStatus.textContent = "";
            this.queryStatus.className = "text-muted";
        }

        async loadSchema() {
            if (!this.schemaAccordion || !this.apiTablesUrl) {
                return;
            }

            try {
                const response = await fetch(this.apiTablesUrl);
                const data = await response.json();

                if (!data.tables) {
                    return;
                }

                this.schemaAccordion.innerHTML = data.tables.map((table, index) => `
                    <div class="accordion-item">
                        <h2 class="accordion-header">
                            <button class="accordion-button collapsed" type="button"
                                    data-bs-toggle="collapse" data-bs-target="#table${index}">
                                <i class="bi bi-table me-2"></i>${this.escapeHtml(table.name)}
                                <span class="badge bg-secondary ms-2">${this.escapeHtml(table.row_count)}</span>
                            </button>
                        </h2>
                        <div id="table${index}" class="accordion-collapse collapse">
                            <div class="accordion-body p-2">
                                <ul class="list-unstyled mb-2 small">
                                    ${table.columns.map((col) => `
                                        <li class="py-1 px-2 border-bottom">
                                            <code>${this.escapeHtml(col.name)}</code>
                                            <span class="text-muted float-end">${this.escapeHtml(col.type)}</span>
                                        </li>
                                    `).join("")}
                                </ul>
                                <button type="button" class="btn btn-sm btn-outline-primary w-100"
                                        data-sample-table="${this.escapeHtml(table.name)}">
                                    <i class="bi bi-eye"></i> Preview Data
                                </button>
                            </div>
                        </div>
                    </div>
                `).join("");
            } catch (error) {
                console.error("Failed to load schema:", error);
            }
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
            this.queryStatus.className = "text-muted";
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
                    this.queryStatus.className = "text-success";
                    this.resultCount.textContent = `${data.row_count} rows`;
                    this.renderResultsTable(data);
                    return;
                }

                this.queryStatus.textContent = "Error";
                this.queryStatus.className = "text-danger";
                this.resultsContainer.innerHTML = `
                    <div class="alert alert-danger mb-0">
                        <i class="bi bi-exclamation-triangle me-2"></i>${this.escapeHtml(data.error || "Unknown error")}
                    </div>
                `;
            } catch (error) {
                const message = error instanceof Error ? error.message : String(error);
                this.queryStatus.textContent = "Error";
                this.queryStatus.className = "text-danger";
                this.resultsContainer.innerHTML = `
                    <div class="alert alert-danger mb-0">
                        <i class="bi bi-exclamation-triangle me-2"></i>${this.escapeHtml(message)}
                    </div>
                `;
            }
        }

        renderResultsTable(data) {
            if (!this.resultsContainer) {
                return;
            }
            if (!data.data || data.data.length === 0) {
                this.resultsContainer.innerHTML = `
                    <div class="text-center text-muted py-4">
                        <i class="bi bi-inbox fs-3 d-block mb-2"></i>
                        No results returned
                    </div>
                `;
                return;
            }

            this.resultsContainer.innerHTML = `
                <div class="table-responsive">
                    <table class="table table-sm table-hover mb-0">
                        <thead>
                            <tr>${data.columns.map((col) => `<th>${this.escapeHtml(col)}</th>`).join("")}</tr>
                        </thead>
                        <tbody>
                            ${data.data.map((row) => `
                                <tr>${data.columns.map((col) => `<td>${this.renderCellValue(row[col])}</td>`).join("")}</tr>
                            `).join("")}
                        </tbody>
                    </table>
                </div>
            `;
        }
    }

    document.addEventListener("DOMContentLoaded", () => {
        const root = document.getElementById("db-query-console");
        if (!(root instanceof HTMLElement)) {
            return;
        }
        new DatabaseQueryConsoleController(root).init();
    });
})();
