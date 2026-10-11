import asyncio
from playwright.async_api import async_playwright

async def get_ary_stream_info(url):
    """
    Directly extracts the official native HLS stream URL (.m3u8) 
    and episode metadata from aryplus.tv using headless Playwright browser interception.
    """
    stream_info = {}
    
    async with async_playwright() as p:
        browser = None
        for launch_kwargs in [{}, {"channel": "msedge"}, {"channel": "chrome"}]:
            try:
                browser = await p.chromium.launch(headless=True, **launch_kwargs)
                if browser:
                    break
            except Exception:
                continue
        
        if not browser:
            raise RuntimeError("Browser launch failed. Please ensure Microsoft Edge, Chrome, or Chromium is available.")
        try:
            context = await browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
            )
            page = await context.new_page()

            # Block heavy images & trackers to speed up ARY page load (2-5s)
            await page.route("**/*", lambda route: 
                route.abort() if route.request.resource_type in ["image"] 
                or any(t in route.request.url for t in ["google-analytics", "facebook", "doubleclick", "googletagservices"])
                else route.continue_()
            )

            async def handle_response(response):
                if "/api/cdn/ep/" in response.url or "/api/cdn/" in response.url:
                    try:
                        data = await response.json()
                        ep = data.get('episode')
                        if isinstance(ep, list) and ep:
                            ep = ep[0]
                        if isinstance(ep, dict):
                            if ep.get('videoSource'):
                                stream_info['video_url'] = ep.get('videoSource')
                            if ep.get('title'):
                                ep_num = ep.get('videoEpNumber', '')
                                stream_info['title'] = f"Episode {ep_num} - {ep.get('title')}" if ep_num else ep.get('title')
                            if ep.get('imagePath'):
                                stream_info['thumbnail'] = f"https://images.aryplus.tv/{ep.get('imagePath')}"
                    except Exception:
                        pass
                elif ".m3u8" in response.url and "vod.aryzap.com" in response.url:
                    if not stream_info.get('video_url'):
                        stream_info['video_url'] = response.url

            page.on("response", handle_response)

            try:
                await page.goto(url, wait_until="domcontentloaded", timeout=12000)
                for _ in range(24):
                    if stream_info.get('video_url'):
                        break
                    await asyncio.sleep(0.25)
            except Exception:
                pass
        finally:
            await browser.close()
            
    return stream_info

def extract_ary_stream_sync(url):
    return asyncio.run(get_ary_stream_info(url))
