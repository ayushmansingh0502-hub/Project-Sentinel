import asyncio
from playwright.async_api import async_playwright

async def main():
    async with async_playwright() as p:
        browser = await p.chromium.launch()
        page = await browser.new_page()
        
        # Capture console logs
        page.on("console", lambda msg: print(f"CONSOLE: {msg.text}"))
        page.on("pageerror", lambda exc: print(f"ERROR: {exc}"))
        
        print("Navigating to dashboard...")
        await page.goto("http://localhost:8000/dashboard")
        
        print("Waiting a bit...")
        await asyncio.sleep(2)
        
        print("Clicking Run...")
        await page.click("#btnRun")
        
        await asyncio.sleep(5)
        print("Done.")
        await browser.close()

if __name__ == "__main__":
    asyncio.run(main())
