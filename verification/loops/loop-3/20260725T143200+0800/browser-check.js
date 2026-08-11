async (page) => {
  await page.reload();
  await page.bringToFront();
  await page.getByRole("link", { name: "跳到主要内容" }).waitFor();
  await page.evaluate(() => {
    document.body.tabIndex = -1;
    document.body.focus();
    document.body.removeAttribute("tabindex");
  });
  await page.keyboard.press("Tab");
  const firstFocus = await page.evaluate(() => ({
    tag: document.activeElement?.tagName,
    text: document.activeElement?.textContent?.trim(),
    href: document.activeElement?.getAttribute("href"),
  }));
  await page.keyboard.press("Enter");
  const focusAfterEnter = await page.evaluate(() => ({
    tag: document.activeElement?.tagName,
    id: document.activeElement?.id,
  }));
  await page.emulateMedia({ reducedMotion: "reduce" });
  const transitionDuration = await page
    .getByRole("button", { name: "开始审核" })
    .evaluate((element) => getComputedStyle(element).transitionDuration);
  const jobCount = await page.locator("section.task-center li").count();
  return {
    firstFocus,
    focusAfterEnter,
    transitionDuration,
    jobCount,
  };
}
