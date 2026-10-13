"""后台 Job 模型测试：生命周期 / 进度 / 协作式取消 / 异常兜底。

跑法：cd HackMate-v2 && python tests/test_jobs.py
"""
import sys
import time
import threading
from pathlib import Path

BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))

from hackmate.jobs import JobManager, DONE, FAILED, CANCELLED  # noqa: E402


def _wait(job, timeout=5.0):
    t0 = time.time()
    while not job.finished and time.time() - t0 < timeout:
        time.sleep(0.02)
    return job.finished


def test_lifecycle():
    jm = JobManager()
    def fn(job):
        job.set_progress("step 1")
        return "ok-result"
    job = jm.submit("test", fn, title="t1")
    assert _wait(job), "任务应在超时内完成"
    assert job.status == DONE and job.result == "ok-result", job.summary()
    print("✓ 生命周期（queued → running → done，结果回填）")


def test_failure_isolated():
    jm = JobManager()
    def boom(job):
        raise ValueError("炸了")
    job = jm.submit("test", boom)
    assert _wait(job)
    assert job.status == FAILED and "炸了" in job.error, job.summary()
    # worker 没死：还能继续跑下一个
    job2 = jm.submit("test", lambda j: "still-alive")
    assert _wait(job2) and job2.status == DONE and job2.result == "still-alive"
    print("✓ 异常兜底（单任务异常不拖垮 worker）")


def test_cancel():
    jm = JobManager()
    started = threading.Event()
    def long_fn(job):
        started.set()
        for _ in range(500):
            job.check_cancel()   # 协作式取消点
            time.sleep(0.01)
        return "finished-without-cancel"
    job = jm.submit("test", long_fn)
    assert started.wait(2.0), "任务应已开始"
    assert jm.cancel(job.id), "cancel 应返回 True"
    assert _wait(job), "取消后应尽快结束"
    assert job.status == CANCELLED, job.summary()
    print("✓ 协作式取消（check_cancel 在关键点退出 → CANCELLED）")


def test_drain_surface():
    jm = JobManager()
    job = jm.submit("test", lambda j: "r")
    assert _wait(job)
    first = jm.drain_finished()
    assert len(first) == 1 and first[0].id == job.id
    second = jm.drain_finished()
    assert second == [], "已冒泡过的任务不应再次冒泡"
    print("✓ 完成冒泡（drain_finished 只冒泡一次）")


if __name__ == "__main__":
    test_lifecycle()
    test_failure_isolated()
    test_cancel()
    test_drain_surface()
    print("\n✅ 全部 Job 测试通过")
