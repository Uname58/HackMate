"""CDP 引导光标 demo：在调试 Chrome 的页面里注入一个缓慢移动的「AI 光标」+ 说明气泡，
一步一步把光标滑到目标元素上、讲解怎么学/打这关。纯页面注入（假光标，不动你真鼠标），
刷新即消失，只作用于 HackMate 的调试 Chrome 实例。

跑法（项目根目录）：python cdp_guide_demo.py
"""
import sys
import json
import time
sys.path.insert(0, ".")
from hackmate.config import load_config
from hackmate.cdp import ensure_cdp

# —— 引导步骤：(目标选择器, 说明文字, 停留毫秒)。选择器找不到则指向屏幕中央 ——
STEPS = [
    ("input", "① 这是输入点：页面会在这里接收你输入的内容", 4000),
    ("h2", "② 看——你输入的内容原样出现在这里（被“反射”回页面）", 4500),
    ("h2", "③ 关键：页面没做任何过滤/编码，所以输入 <script> 会被当成代码", 5000),
    ("input", "④ 试着输入  <script>alert(1)</script>  并提交", 4500),
    ("body", "⑤ 弹出 alert = JavaScript 真的执行了 = 反射型 XSS 成立 ✓", 4500),
]

cfg = load_config()
c = ensure_cdp(cfg["cdp_host"], int(cfg["cdp_port"]))
if not c:
    print("CDP 未就绪（先确认靶场在跑、Chrome 能起）")
    sys.exit(1)

tab = c.list_tabs()[0]
ws = tab["ws"]
c.navigate("http://localhost:8080/level1.php?name=demo", index=0)
time.sleep(1.2)

JS = r"""
(function(){
  for(const id of ['hmCur','hmTip','hmStyle']){ const e=document.getElementById(id); if(e)e.remove(); }
  const st=document.createElement('style'); st.id='hmStyle';
  st.textContent=`
    #hmCur{position:fixed;z-index:1000000;width:28px;height:28px;left:50%;top:50%;
      pointer-events:none;transition:left 1.3s cubic-bezier(.4,0,.2,1),top 1.3s cubic-bezier(.4,0,.2,1);
      filter:drop-shadow(0 2px 4px rgba(0,0,0,.4))}
    #hmTip{position:fixed;z-index:1000000;max-width:300px;background:#111827;color:#f9fafb;
      font:500 14px/1.5 system-ui,sans-serif;padding:10px 14px;border-radius:10px;
      box-shadow:0 8px 24px rgba(0,0,0,.35);opacity:0;transition:opacity .4s,left 1.3s,top 1.3s;
      border-left:3px solid #22c55e}
    .hmHot{outline:3px solid #f59e0b !important;outline-offset:2px;transition:outline .3s}
  `;
  document.head.appendChild(st);
  const cur=document.createElement('div'); cur.id='hmCur';
  cur.innerHTML='<svg viewBox="0 0 24 24" width="28" height="28"><path d="M4 2l16 7-6 2-2 6z" fill="#22c55e" stroke="#065f46" stroke-width="1.2"/></svg>';
  document.body.appendChild(cur);
  const tip=document.createElement('div'); tip.id='hmTip'; document.body.appendChild(tip);
  const STEPS=__STEPS__;
  const sleep=ms=>new Promise(r=>setTimeout(r,ms));
  const q=s=>{try{return s?document.querySelector(s):null}catch(e){return null}};
  (async()=>{
    for(const [sel,text,dur] of STEPS){
      const el=q(sel); let x=innerWidth/2,y=innerHeight/2;
      if(el){const r=el.getBoundingClientRect();x=r.left+r.width/2;y=r.top+r.height/2;
        el.classList.add('hmHot'); el.scrollIntoView({block:'center',behavior:'smooth'});}
      cur.style.left=x+'px'; cur.style.top=y+'px';
      tip.textContent=text;
      tip.style.left=Math.max(12,Math.min(x+20,innerWidth-320))+'px';
      tip.style.top=Math.min(y+24,innerHeight-80)+'px';
      tip.style.opacity='1';
      await sleep(dur);
      tip.style.opacity='0';
      if(el)el.classList.remove('hmHot');
      await sleep(600);
    }
    tip.textContent='引导结束 ✓ 现在轮到你动手';
    tip.style.left=(innerWidth/2-100)+'px'; tip.style.top=(innerHeight/2)+'px'; tip.style.opacity='1';
    await sleep(2500); tip.style.opacity='0';
  })();
  return 'tour started';
})()
""".replace("__STEPS__", json.dumps(STEPS, ensure_ascii=False))

print(c._cdp_eval(ws, JS))
print("引导已在调试 Chrome 里开始播放（约 %d 秒）。去看那个窗口。" %
      (sum(s[2] for s in STEPS) // 1000 + len(STEPS)))
