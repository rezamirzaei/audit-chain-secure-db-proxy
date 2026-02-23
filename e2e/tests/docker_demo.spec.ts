import { expect, test, type APIRequestContext, type Page } from "@playwright/test";

const DB_BASE_URL = process.env.DB_BASE_URL ?? "https://localhost:5002";
const PROXY_BASE_URL = process.env.PROXY_BASE_URL ?? "https://localhost:8080";
const ADMIN_USER = process.env.E2E_ADMIN_USER ?? "admin";
const ADMIN_PASSWORD = process.env.E2E_ADMIN_PASSWORD ?? "SecurePass123!";
const ADMIN_SECURITY_ANSWER = process.env.E2E_ADMIN_SECURITY_ANSWER ?? "blue";

async function fetchTotpToken(request: APIRequestContext, username: string) {
  const response = await request.get(`${DB_BASE_URL}/api/totp/current?username=${encodeURIComponent(username)}`);
  expect(response.ok()).toBeTruthy();
  const payload = await response.json();
  expect(typeof payload.totp_token).toBe("string");
  return String(payload.totp_token);
}

async function completeDatabaseLoginUi(
  page: Page,
  request: APIRequestContext,
) {
  await page.goto(`${DB_BASE_URL}/login`);
  await page.fill('input[name="username"]', ADMIN_USER);
  await page.fill('input[name="password"]', ADMIN_PASSWORD);
  await page.getByRole("button", { name: /sign in/i }).click();

  await expect(page).toHaveURL(/verify-2fa/);
  const totpToken = await fetchTotpToken(request, ADMIN_USER);
  await page.fill('input[name="totp_code"]', totpToken);
  await page.getByRole("button", { name: /verify code/i }).click();

  await expect(page).toHaveURL(/verify-security/);
  await page.fill('input[name="security_answer"]', ADMIN_SECURITY_ANSWER);
  await page.getByRole("button", { name: /complete login/i }).click();
  await expect(page).toHaveURL(/dashboard/);
}

async function completeProxyConnectUi(
  page: Page,
  request: APIRequestContext,
) {
  await page.goto(`${PROXY_BASE_URL}/connect`);
  await page.fill('input[name="username"]', ADMIN_USER);
  await page.fill('input[name="password"]', ADMIN_PASSWORD);
  await page.getByRole("button", { name: /continue/i }).click();

  await expect(page).toHaveURL(/step=totp/);
  const totpToken = await fetchTotpToken(request, ADMIN_USER);
  await page.fill('input[name="totp_code"]', totpToken);
  await page.getByRole("button", { name: /verify code/i }).click();

  await expect(page).toHaveURL(/step=security/);
  await page.fill('input[name="security_answer"]', ADMIN_SECURITY_ANSWER);
  await page.getByRole("button", { name: /complete login/i }).click();
  await expect(page).toHaveURL(new RegExp(`${PROXY_BASE_URL}/?$`));
}

test.describe("Docker browser E2E", () => {
  test("database UI login and query console flow", async ({ page, request }) => {
    await completeDatabaseLoginUi(page, request);

    await page.goto(`${DB_BASE_URL}/query`);
    await page.fill("#queryInput", "SELECT COUNT(*) AS cnt FROM departments");
    await page.getByRole("button", { name: /execute/i }).click();

    await expect(page.locator("#resultCount")).toContainText("1 rows");
    await expect(page.locator("#resultsContainer")).toContainText("cnt");
  });

  test("proxy UI connect and query flow", async ({ page, request }) => {
    await completeProxyConnectUi(page, request);

    await page.fill("#queryInput", "SELECT COUNT(*) AS cnt FROM employees");
    await page.getByRole("button", { name: /execute query/i }).click();

    await expect(page.locator("#resultCount")).toContainText("1 rows");
    await expect(page.locator("#resultsContainer")).toContainText("cnt");
  });
});
