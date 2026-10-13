"""CDP 视觉特效 demo：在调试 Chrome 的页面里注入 CSS 动画横幅 + 高亮输入框。
证明 CDP 能通过 Runtime.evaluate 跑任意 JS → 改颜色 / 加 DOM / 加动画。
注入是临时的，刷新/导航即消失；只作用于 HackMate 的调试 Chrome 实例。

跑法（项目根目录）：python cdp_fx_demo.py
"""
import sys
import time
sys.path.insert(0, ".")
from hackmate.config import load_config
from hackmate.cdp import ensure_cdp

cfg = load_config()
c = ensure_cdp(cfg["cdp_host"], int(cfg["cdp_port"]))
if not c:
    print("CDP 未就绪（先确认靶场在跑、Chrome 能起）")
    sys.exit(1)

tab = c.list_tabs()[0]
ws = tab["ws"]

# 1) 导航到一关（换成你在跑的靶场 URL）
c.navigate("http://localhost:8080/level1.php?name=demo", index=0)
time.sleep(1.2)

# 2) 注入：绿色 CONFIRMED 横幅（滑入 + 脉冲动画）+ 高亮所有输入框
js = r"""
(function(){
  const css = document.createElement('style');
  css.textContent = `
    @keyframes hmSlide { from{transform:translateY(-120%);opacity:0} to{transform:translateY(0);opacity:1} }
    @keyframes hmPulse { 0%,100%{box-shadow:0 0 0 0 rgba(34,197,94,.7)} 50%{box-shadow:0 0 0 12px rgba(34,197,94,0)} }
    #hmBanner{position:fixed;top:0;left:0;right:0;z-index:999999;
      background:#16a34a;color:#fff;font:600 18px/1.4 system-ui,sans-serif;
      padding:14px 20px;text-align:center;letter-spacing:.5px;
      animation:hmSlide .4s ease-out, hmPulse 1.6s ease-in-out infinite .4s}
    .hmHot{outline:3px solid #f59e0b !important;transition:outline .3s}
  `;
  document.head.appendChild(css);
  const b = document.createElement('div');
  b.id='hmBanner';
  b.textContent='✓ XSS CONFIRMED — HackMate';
  document.body.appendChild(b);
  document.querySelectorAll('input,textarea').forEach(e=>e.classList.add('hmHot'));
  return 'injected';
})()
"""
print(c._cdp_eval(ws, js))  # 去看调试 Chrome：顶部绿横幅脉冲，输入框橙色高亮
