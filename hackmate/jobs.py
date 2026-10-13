"""后台 Job 模型 —— v2 的「解卡死」核心。

v1 的 improve_skill 在主线程同步跑 35–53 次串行 LLM 调用，input() 全程阻塞 18–45 分钟，
用户分不清「在跑还是断了」。v2 把慢活（eval 判分 / improve_skill）丢进一个后台 worker 线程：

- 主线程 REPL 永不阻塞，可继续对话 / 打下一关 / 查进度 / 中断。
- 一个慢任务 = 一个 Job（id / kind / status / progress / result / cancel 标志）。
- 单 worker 线程串行执行 Job（避免并发烧爆 API），线程安全更新 Job 记录。
- 协作式取消：Job 的执行函数在每次 LLM 调用之间检查 job.cancelled，不强杀线程
  （Python 杀不干净），最多残留一个在途请求、被 LLM 超时兜住。

纯标准库：threading + queue。
"""

import queue
import threading
import time

from . import log

QUEUED = "queued"
RUNNING = "running"
DONE = "done"
FAILED = "failed"
CANCELLED = "cancelled"

_FINISHED = {DONE, FAILED, CANCELLED}


class Job:
    def __init__(self, job_id: int, kind: str, title: str = ""):
        self.id = job_id
        self.kind = kind
        self.title = title or kind
        self.status = QUEUED
        self.progress = ""
        self.result = ""
        self.error = ""
        self.created = time.time()
        self.updated = self.created
        self._cancel = threading.Event()
        self._surfaced = False  # 完成后是否已向用户冒泡过

    # --- 供执行函数调用 ---
    def set_progress(self, text: str) -> None:
        self.progress = text
        self.updated = time.time()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def check_cancel(self) -> None:
        """执行函数在关键点调用：若已请求取消则抛 JobCancelled 退出。"""
        if self._cancel.is_set():
            raise JobCancelled()

    # --- 展示 ---
    @property
    def finished(self) -> bool:
        return self.status in _FINISHED

    def age(self) -> float:
        return time.time() - self.created

    def summary(self) -> str:
        bits = [f"#{self.id}", self.title, self.status]
        if self.status == RUNNING and self.progress:
            bits.append(self.progress)
        elif self.status == DONE and self.result:
            bits.append(self.result)
        elif self.status == FAILED and self.error:
            bits.append(self.error)
        return "  ".join(bits)


class JobCancelled(Exception):
    """执行函数内部用于协作式退出。"""


class JobManager:
    """单 worker 线程 + 线程安全 registry。"""

    def __init__(self):
        self._q = queue.Queue()
        self._jobs = {}            # id -> Job
        self._lock = threading.Lock()
        self._counter = 0
        self._worker = threading.Thread(target=self._run, daemon=True)
        self._worker.start()

    def submit(self, kind: str, fn, title: str = "") -> Job:
        """提交一个后台任务。fn 签名 fn(job) -> result_str（可抛异常 / JobCancelled）。"""
        with self._lock:
            self._counter += 1
            job = Job(self._counter, kind, title)
            self._jobs[job.id] = job
        self._q.put((job, fn))
        log.record("job", job=job.id, status=QUEUED, note=job.title)
        return job

    def _run(self):
        while True:
            job, fn = self._q.get()
            if job.cancelled:
                job.status = CANCELLED
                job.updated = time.time()
                log.record("job", job=job.id, status=CANCELLED, note="取消（未开始）")
                self._q.task_done()
                continue
            job.status = RUNNING
            job.updated = time.time()
            try:
                result = fn(job)
                if job.cancelled:
                    job.status = CANCELLED
                else:
                    job.status = DONE
                    job.result = str(result) if result is not None else ""
            except JobCancelled:
                job.status = CANCELLED
            except Exception as e:  # 执行函数任何异常都兜住，不拖垮 worker
                job.status = FAILED
                job.error = f"{type(e).__name__}: {e}"
            job.updated = time.time()
            log.record("job", job=job.id, status=job.status,
                       note=(job.result or job.error or "")[:200])
            self._q.task_done()

    # --- 查询 / 控制 ---
    def get(self, job_id: int):
        with self._lock:
            return self._jobs.get(job_id)

    def list_jobs(self):
        with self._lock:
            return sorted(self._jobs.values(), key=lambda j: j.id)

    def active(self):
        return [j for j in self.list_jobs() if not j.finished]

    def cancel(self, job_id: int) -> bool:
        j = self.get(job_id)
        if j is None or j.finished:
            return False
        j._cancel.set()
        return True

    def drain_finished(self):
        """返回自上次调用以来「新完成、尚未冒泡」的 Job，并标记已冒泡。"""
        out = []
        with self._lock:
            for j in sorted(self._jobs.values(), key=lambda j: j.id):
                if j.finished and not j._surfaced:
                    j._surfaced = True
                    out.append(j)
        return out
