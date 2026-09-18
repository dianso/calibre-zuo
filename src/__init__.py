# -*- coding: utf-8 -*-
"""
Calibre-ZUO 数据源客户端 + 请求签名复刻。

背景
----
目标站点（zuo.cc）的公开只读接口（/api/novel/search、/api/novel 等）虽允许匿名访问，
但会被动态签名校验拦截。zuo 后端已切换为「动态签名方案」（shared/src/utils/api-sign.ts）：
    - 先经免签端点 GET /api/security/seed 握得三段式 seed（base64url(safeIp|ts|ver).mac）
    - 由 seed 无状态解包绑定的算法版本 v0~v3（30 分钟棘轮轮换）
    - 单请求头 zuo-cc-auth: {seed}:{ts}:{nonce}:{sign}
    - sign = hex(HMAC-SHA256(key=seed, canonical))，canonical 由六段按版本拼装
    - 服务端经 zuo-cc-seed / zuo-cc-time 响应头顺风车下发新种子与高精度时间戳
    - 401 且 detail 为 SIGN_EXPIRED / SIGN_IP_MISMATCH 时重新握手 seed 静默重试一次

实现逐字符照抄 shared/src/utils/api-sign.ts，禁止「随手改动」小写十六进制等常量。
"""
import base64
import gzip
import hashlib
import hmac
import json
import os
import time
from functools import cmp_to_key
from threading import Lock
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

# ---------------------------------------------------------------------------
# 请求头/协议常量（与 shared/src/utils/api-sign.ts 对齐）
# ---------------------------------------------------------------------------
API_AUTH_HEADER = "zuo-cc-auth"                 # 单请求头，紧凑四要素 seed:ts:nonce:sign
API_SEED_HEADER = "zuo-cc-seed"                 # 服务端顺风车下发的下一次新种子响应头
API_SERVER_TIME_HEADER = "zuo-cc-time"          # 服务端高精度时间戳响应头（毫秒）

API_SEED_TTL_MS = 15 * 60 * 1000                # 种子默认存活有效期：15 分钟（毫秒）
API_SIGN_WINDOW_MS = 5 * 60 * 1000              # 时间戳允许窗口：±5 分钟（毫秒）
API_ALGO_ROTATION_INTERVAL_MS = 30 * 60 * 1000  # 算法轮换时间槽：30 分钟（毫秒）
API_ALGO_VERSIONS_COUNT = 4                     # 动态算法变体数量：v0 ~ v3

SEED_ENDPOINT = "/api/security/seed"            # 免签的种子交换端点

# 空串的 SHA-256 hex：公开接口无请求体，body 哈希双端固定为此常量
API_SIGN_EMPTY_BODY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# 401 details 前缀与可自愈白名单
_SIGN_DETAIL_PREFIX = "SIGN_"
_SIGN_SELF_HEAL_DETAILS = ("SIGN_EXPIRED", "SIGN_IP_MISMATCH")


class ZuoApiError(Exception):
    """封装站点 API 的稳定可读错误。"""

    def __init__(self, message, sign_detail=None):
        super().__init__(message)
        self.sign_detail = sign_detail


# ---------------------------------------------------------------------------
# 动态签名算法实现（与 shared/src/utils/api-sign.ts 逐字节一致）
# ---------------------------------------------------------------------------

def get_current_algo_version(now_ms):
    """按毫秒时间戳计算 30 分钟时间槽对应的算法版本号（0~3），兼容负值槽位。"""
    slot = now_ms // API_ALGO_ROTATION_INTERVAL_MS
    return ((slot % API_ALGO_VERSIONS_COUNT) + API_ALGO_VERSIONS_COUNT) % API_ALGO_VERSIONS_COUNT


def _b64url_decode_bytes(base64_payload):
    """base64url 解码为字节串（- -> +、_ -> /，补齐填充）。"""
    s = base64_payload.replace("-", "+").replace("_", "/")
    pad = len(s) % 4
    if pad:
        s += "=" * (4 - pad)
    return base64.b64decode(s, validate=True)


def extract_algo_version_from_seed(seed):
    """从三段式 seed（base64url(safeIp|ts|ver).mac）无状态解包算法版本号（0~3）。

    格式不符/非法/越界时安全回退至 0（与 TS extractAlgoVersionFromSeed 一致）。
    """
    if not seed or not isinstance(seed, str):
        return 0
    dot = seed.find(".")
    if dot <= 0:
        return 0
    base64_payload = seed[:dot]
    try:
        raw = _b64url_decode_bytes(base64_payload)
    except Exception:
        return 0
    parts = raw.split(b"|")
    if len(parts) != 3:
        return 0
    ver_part = parts[2]
    if ver_part is not None:
        try:
            ver = int(ver_part)
        except (TypeError, ValueError):
            ver = None
        if ver is not None and 0 <= ver < API_ALGO_VERSIONS_COUNT:
            return ver
    return 0


def generate_api_sign_nonce():
    """生成 16 字节随机数的 hex 字符串（32 字符）。"""
    return os.urandom(16).hex()


def fnv1a32(s):
    """32 位 FNV-1a 纯同步哈希，用于 v3 键名确定性加权排序。"""
    h = 0x811C9DC5
    for ch in s:
        h ^= ord(ch)
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


def normalize_query_pairs(pairs):
    """规范化 query 键名：剥掉 key 尾部 []（axios 数组序列化产物，如 tags[]=a）。"""
    normalized = []
    for raw_key, value in pairs:
        key = raw_key[:-2] if raw_key.endswith("[]") else raw_key
        normalized.append((key, value))
    return normalized


def _cmp_v0(a, b):
    """v0: key code-unit 升序；同 key 按 value 升序。"""
    if a[0] != b[0]:
        return -1 if a[0] < b[0] else 1
    if a[1] < b[1]:
        return -1
    if a[1] > b[1]:
        return 1
    return 0


def _cmp_v1(a, b):
    """v1: key 长度降序；同长按 key 倒序；同 key 按 value 升序。"""
    len_diff = len(b[0]) - len(a[0])
    if len_diff != 0:
        return len_diff
    if a[0] != b[0]:
        return 1 if a[0] < b[0] else -1
    if a[1] < b[1]:
        return -1
    if a[1] > b[1]:
        return 1
    return 0


def _cmp_v2(a, b):
    """v2: key code-unit 降序；同 key 按 value 降序。"""
    if a[0] != b[0]:
        return 1 if a[0] < b[0] else -1
    if a[1] < b[1]:
        return 1
    if a[1] > b[1]:
        return -1
    return 0


def _cmp_v3(a, b):
    """v3: key 按 FNV-1a 哈希数值升序；同哈希按 key 升序；同 key 按 value 升序。"""
    hash_diff = fnv1a32(a[0]) - fnv1a32(b[0])
    if hash_diff != 0:
        return hash_diff
    if a[0] != b[0]:
        return -1 if a[0] < b[0] else 1
    if a[1] < b[1]:
        return -1
    if a[1] > b[1]:
        return 1
    return 0


_CMP_BY_VERSION = {0: _cmp_v0, 1: _cmp_v1, 2: _cmp_v2, 3: _cmp_v3}


def build_canonical_query_by_version(version, pairs):
    """按算法版本拼装规范化 query 字符串（逐字符对齐 TS buildCanonicalQueryByVersion）。"""
    lst = normalize_query_pairs(pairs)
    if not lst:
        return ""
    cmp_fn = _CMP_BY_VERSION.get(version, _cmp_v0)
    lst = sorted(lst, key=cmp_to_key(cmp_fn))
    if version == 1:
        return "#".join(f"{k}:{v}" for k, v in lst)
    if version == 2:
        return "$".join(f"{v}@{k}" for k, v in lst)
    if version == 3:
        return "--".join(f"[{k}][{v}]" for k, v in lst)
    return "&".join(f"{k}={v}" for k, v in lst)


def build_canonical_query(pairs):
    """v0 规范的向后兼容包装。"""
    return build_canonical_query_by_version(0, pairs)


def build_api_sign_canonical_string(method, path, query_pairs, body_hash, ts, nonce,
                                    seed=None, version=None):
    """多版本 canonical 六段组装（逐字符对齐 TS buildApiSignCanonicalString）。"""
    ver = version if version is not None else (extract_algo_version_from_seed(seed) if seed else 0)
    query_str = build_canonical_query_by_version(ver, query_pairs)
    if ver == 1:
        return "|".join([ts, method, path, query_str, nonce, body_hash])
    if ver == 2:
        return "~".join([path, nonce, method, ts, query_str, body_hash])
    if ver == 3:
        return ";;".join(["V3", nonce, ts, body_hash, path, method, query_str])
    return "\n".join([method, path, query_str, body_hash, ts, nonce])


class ZuoApiClient:
    """连接 zuo.cc 的轻量只读客户端：负责签名、发送与统一信封解包。"""

    def __init__(self, base_url: str, timeout: float = 20.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self._seed = None
        self._seed_version = 0
        self._seed_expires_at = 0.0        # 本地对齐时钟后的 epoch 毫秒
        self._seed_lock = Lock()
        self._clock_offset_ms = 0          # 服务端时间 - 本地时间（毫秒），用 zuo-cc-time 校准

    # ------------------------------------------------------------------
    # 对外业务方法
    # ------------------------------------------------------------------
    def search_books(self, keyword: str, page: int = 1, page_size: int = 5):
        """按关键词搜索，返回 (items, total)。"""
        params = [("keyword", keyword), ("page", page), ("page_size", page_size)]
        payload = self.request("/api/novel/search", params)
        data = payload.get("data") or {}
        return data.get("items") or [], data.get("total") or 0

    def get_book(self, novel_id):
        """按作品 ID 拉取详情，返回 novel 对象或 None。"""
        payload = self.request("/api/novel", [("id", novel_id)])
        data = payload.get("data") or {}
        return data.get("novel")

    def download_cover(self, url: str) -> Optional[bytes]:
        """下载封面二进制；失败返回 None。

        站点返回的 cover 可能是相对路径（如 /data/images/...），需拼上 base_url；
        urlopen 无法打开相对 URL 会抛 ValueError，一并视为下载失败跳过。
        """
        if not url:
            return None
        if not url.startswith(("http://", "https://")):
            url = self.base_url + url
        try:
            req = Request(url, headers={"User-Agent": self._user_agent()})
            with urlopen(req, timeout=self.timeout) as resp:
                return resp.read()
        except (HTTPError, URLError, ValueError) as _e:
            self._trace("DLCOVER_FAIL url=%r err=%r" % (url, _e))
            return None

    # ------------------------------------------------------------------
    # 底层请求
    # ------------------------------------------------------------------
    def request(self, path: str, query_params=None, method: str = "GET"):
        """携带动态签名头发起请求，返回解包成功信封后的 payload。

        401 且 detail 为 SIGN_EXPIRED / SIGN_IP_MISMATCH 时重拉 seed 并静默重试一次。
        """
        query_params = list(query_params or [])
        for attempt in (0, 1):
            headers = {
                "Accept": "application/json",
                "User-Agent": self._user_agent(),
                **self._build_auth_header(method, path, query_params),
            }
            query_string = urlencode({k: v for k, v in query_params if v not in (None, "")})
            url = f"{self.base_url}{path}"
            if query_string:
                url = f"{url}?{query_string}"
            req = Request(url, headers=headers, method=method)
            try:
                return self._open(req)
            except ZuoApiError as err:
                if attempt == 0 and err.sign_detail in _SIGN_SELF_HEAL_DETAILS:
                    self._invalidate_seed()
                    continue
                raise

    def _build_auth_header(self, method, path, query_params):
        """生成单请求头 zuo-cc-auth: {seed}:{ts}:{nonce}:{sign}。"""
        seed = self._get_seed()
        ts = str(self._now_ms())
        nonce = generate_api_sign_nonce()
        canonical = build_api_sign_canonical_string(
            method, path, query_params, API_SIGN_EMPTY_BODY_HASH, ts, nonce, seed
        )
        signature = hmac.new(seed.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()
        return {API_AUTH_HEADER: ":".join([seed, ts, nonce, signature])}

    # ------------------------------------------------------------------
    # seed 握手与时钟
    # ------------------------------------------------------------------
    def _now_ms(self):
        return int(time.time() * 1000) + self._clock_offset_ms

    def _get_seed(self):
        with self._seed_lock:
            if self._seed and self._seed_version is not None and self._now_ms() < self._seed_expires_at:
                return self._seed
            self._fetch_seed()
            return self._seed

    def _invalidate_seed(self):
        with self._seed_lock:
            self._seed = None
            self._seed_version = None
            self._seed_expires_at = 0.0

    def _fetch_seed(self):
        """GET /api/security/seed（免签）握得 seed；解析 {seed, expiresIn}，
        zuo-cc-seed 响应头作 fallback；缓存 seed + 算法版本 + 过期时间。"""
        url = f"{self.base_url}{SEED_ENDPOINT}"
        req = Request(url, headers={"Accept": "application/json",
                                    "User-Agent": self._user_agent()}, method="GET")
        payload, headers = self._send(req)
        body = payload
        if isinstance(payload, dict) and isinstance(payload.get("data"), dict):
            body = payload["data"]
        body = body if isinstance(body, dict) else {}
        seed = body.get("seed") or headers.get(API_SEED_HEADER)
        if not seed:
            raise ZuoApiError("seed 握手失败：响应缺少 seed")
        expires_ms = body.get("expiresIn")
        try:
            expires_ms = int(expires_ms) if expires_ms not in (None, "") else API_SEED_TTL_MS
        except (TypeError, ValueError):
            expires_ms = API_SEED_TTL_MS
        self._seed = seed
        self._seed_version = extract_algo_version_from_seed(seed)
        self._seed_expires_at = self._now_ms() + expires_ms

    def _calibrate_clock(self, headers):
        """读取 zuo-cc-time 响应头校准本地与服务端时钟偏移（毫秒，最小实现）。"""
        st = headers.get(API_SERVER_TIME_HEADER)
        if not st:
            return
        try:
            self._clock_offset_ms = int(st) - int(time.time() * 1000)
        except (TypeError, ValueError):
            pass

    # ------------------------------------------------------------------
    # 底层收发与信封
    # ------------------------------------------------------------------
    def _send(self, req):
        """发送请求返回 (payload, headers)；HTTP 错误若带 SIGN_ details 抛带 sign_detail 的错误。"""
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                headers = resp.headers
                self._calibrate_clock(headers)
                data = resp.read()
                if headers.get("Content-Encoding") == "gzip":
                    data = gzip.decompress(data)
                charset = headers.get_content_charset() or "utf-8"
                payload = json.loads(data.decode(charset))
                return payload, headers
        except HTTPError as err:
            detail = self._read_sign_detail(err)
            if detail:
                raise ZuoApiError("签名校验失败: " + detail, sign_detail=detail)
            raise ZuoApiError(f"HTTP 错误: {err.code}")
        except URLError as err:
            raise ZuoApiError(f"网络错误: {err.reason}")
        except json.JSONDecodeError as err:
            raise ZuoApiError(f"解析响应失败: {err.msg}")

    @staticmethod
    def _read_sign_detail(err):
        """从 HTTPError 响应体提取 SIGN_ 开头的 details（供自愈判定）。"""
        try:
            body = err.read().decode("utf-8", "replace")
        except Exception:
            return None
        try:
            obj = json.loads(body)
        except Exception:
            return None
        if not isinstance(obj, dict):
            return None
        e = obj.get("error")
        if not isinstance(e, dict):
            return None
        details = e.get("details")
        return details if isinstance(details, str) and details.startswith(_SIGN_DETAIL_PREFIX) else None

    def _open(self, req):
        payload, _headers = self._send(req)
        # 统一信封解包：成功 { success:true, data }；失败 { success:false, error }
        if isinstance(payload, dict):
            if payload.get("success") is False:
                error = payload.get("error") or {}
                raise ZuoApiError(f"{error.get('message') or '请求失败'} (code={error.get('code')})")
            return payload
        raise ZuoApiError("未知响应格式")

    @staticmethod
    def _user_agent() -> str:
        return "calibre-zuo/1.0 (+https://zuo.cc)"
# -*- coding: utf-8 -*-
"""
Calibre-ZUO：从 zuo.cc 抓取网文元数据与封面的 Calibre 刮削插件。

插件能力
    * identify  : 按「书名 / 书名+作者」搜索，返回候选书籍的标题、作者、封面、
                 简介、标签、评分、出版信息等。
    * cover     : 独立下载封面。
    * 自定义列   : 通过 get_extended_metadata 回填网文字数、连载状态码、首发站、首订数。

数据源
    复用站点现有只读 API（/api/novel/search、/api/novel），由上方 ZuoApiClient 负责
    动态签名（seed 握手 + zuo-cc-auth 单头签名）。请勿改动其中的签名算法常量。
"""
import time
from collections import deque
from datetime import datetime
from threading import Lock

from calibre.ebooks.metadata.book.base import Metadata
from calibre.ebooks.metadata.sources.base import Option, Source
from calibre.utils.localization import _



PROVIDER_NAME = "Calibre-ZUO Catalog"
PROVIDER_ID = "calibre_zuo"
PROVIDER_VERSION = (1, 1, 0)
DEFAULT_BASE_URL = "https://zuo.cc"
DEFAULT_TIMEOUT = 20
BUCKET_WINDOW_SECONDS = 600

# 可署名的作品标识符，用于识别阶段精确回填与二次刮削去重
IDENTIFIER_KEY = "zuo-novel-id"


class HourBucketRateLimiter:
    """小时 + 分桶双窗口限速器：防止脚本式请求触达站点负载。"""

    def __init__(self, hour_limit, bucket_limit, bucket_window=BUCKET_WINDOW_SECONDS):
        self.hour_limit = max(int(hour_limit or 1), 1)
        fallback_bucket = max(self.hour_limit // 6, 1)
        self.bucket_limit = max(int(bucket_limit or fallback_bucket), 1)
        self.bucket_window = max(int(bucket_window), 1)
        self.hour_window = 3600
        self.timestamps = deque()
        self.lock = Lock()

    def wait_for_slot(self):
        while True:
            with self.lock:
                now = time.time()
                self._trim(now)
                if self._has_capacity(now):
                    self.timestamps.append(now)
                    return
                delay = self._next_delay(now)
            if delay <= 0:
                continue
            time.sleep(delay)

    def _trim(self, now):
        while self.timestamps and now - self.timestamps[0] >= self.hour_window:
            self.timestamps.popleft()

    def _has_capacity(self, now):
        if len(self.timestamps) < self.hour_limit:
            bucket_count, _ = self._bucket_info(now)
            return bucket_count < self.bucket_limit
        return False

    def _bucket_info(self, now):
        count = 0
        oldest = None
        for ts in reversed(self.timestamps):
            if now - ts <= self.bucket_window:
                count += 1
                oldest = ts
            else:
                break
        return count, oldest

    def _next_delay(self, now):
        delay = 0.0
        if len(self.timestamps) >= self.hour_limit:
            delay = max(delay, self.hour_window - (now - self.timestamps[0]))
        bucket_count, oldest = self._bucket_info(now)
        if bucket_count >= self.bucket_limit and oldest is not None:
            delay = max(delay, self.bucket_window - (now - oldest))
        return max(delay, 0.01)


class CalibreZuo(Source):
    name = PROVIDER_NAME
    description = _("从 zuo.cc 下载网文元数据和封面")
    supported_platforms = ["windows", "osx", "linux"]
    author = "zuo"
    version = PROVIDER_VERSION
    minimum_calibre_version = (5, 0, 0)
    capabilities = frozenset(["identify", "cover"])
    touched_fields = frozenset(
        [
            "title", "authors", "publisher", "comments", "tags", "rating",
            "identifier:" + IDENTIFIER_KEY,
        ]
    )
    options = (
        Option("base_url", "string", DEFAULT_BASE_URL,
               _("API 地址"), _("站点根地址，默认 https://zuo.cc")),
        Option("requests_per_hour", "number", 60,
               _("每小时请求上限"), _("插件会自动按 1/6 设置 10 分钟小桶限速。")),
        Option("page_size", "number", 5,
               _("单次拉取数量"), _("识别时单次检索的最大候选条数。")),
        Option("request_timeout", "number", DEFAULT_TIMEOUT,
               _("请求超时(秒)"), _("HTTP 请求超时时间。")),
    )

    def __init__(self, *args, **kwargs):
        Source.__init__(self, *args, **kwargs)
        self.client = None
        self.rate_limiter = None
        self.page_size = 5
        self.timeout = DEFAULT_TIMEOUT
        self._init_client_from_prefs()

    # ------------------------------------------------------------------
    # 初始化：从配置构建客户端与限速器
    # ------------------------------------------------------------------
    def _init_client_from_prefs(self):
        hour_limit = max(int(self.prefs.get("requests_per_hour") or 60), 1)
        self.page_size = max(int(self.prefs.get("page_size") or 5), 1)
        self.timeout = max(int(self.prefs.get("request_timeout") or DEFAULT_TIMEOUT), 5)
        self.rate_limiter = HourBucketRateLimiter(hour_limit, max(hour_limit // 6, 1))
        base_url = (self.prefs.get("base_url") or DEFAULT_BASE_URL).strip()
        self.client = ZuoApiClient(base_url, self.timeout)

    # ------------------------------------------------------------------
    # identify：识别候选书籍
    # ------------------------------------------------------------------
    def identify(self, log, result_queue, abort, title=None, authors=None,
                 identifiers=None, timeout=DEFAULT_TIMEOUT):
        identifiers = identifiers or {}
        if abort.is_set():
            return

        novel_id = self._get_identifier(identifiers)
        if novel_id:
            record = self._safe_load_detail(novel_id, log)
            if record:
                self._emit_metadata(record, result_queue, log, abort)
                return

        for query in self._build_keywords(title):
            if abort.is_set():
                return
            try:
                items, _total = self.client.search_books(query, page=self._use_page(), page_size=self.page_size)
            except ZuoApiError as err:
                log.error(f"Calibre-ZUO: 搜索失败，原因: {err}")
                return
            records = items[: self.page_size]
            for record in records:
                if abort.is_set():
                    break
                rec_id = record.get("id")
                if not rec_id:
                    continue
                detail = self._safe_load_detail(rec_id, log)
                if detail:
                    # 用详情富字段覆盖/补全候选记录
                    for key in ("cover", "description", "summary", "tags",
                                "avg_rating", "rating_count", "word_count",
                                "status", "publisher", "publish_date"):
                        if detail.get(key) not in (None, ""):
                            record[key] = detail[key]
                    self._emit_metadata(record, result_queue, log, abort)

    # ------------------------------------------------------------------
    # cover：独立下载封面
    # ------------------------------------------------------------------
    @staticmethod
    def _trace(msg):
        # 磁盘调试追踪：固定落在本项目目录(便于直接读取)，同时写 %TEMP%
        import os, tempfile
        paths = ["D:/ss/calibre-zuo/trace.log",
                 os.path.join(tempfile.gettempdir(), "calibre_zuo_trace.log")]
        for path in paths:
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True) if os.path.dirname(path) else None
                with open(path, "a", encoding="utf-8") as f:
                    f.write(f"{msg}\n")
            except Exception:
                pass

    def download_cover(self, log, result_queue, abort, title=None, authors=None,
                       identifiers=None, timeout=DEFAULT_TIMEOUT, get_best_cover=False):
        # 全量加固：任何异常都打明细日志，避免 Calibre 只显示“0.0s 失败”而无从排查
        try:
            self._trace("CALL download_cover title=%r identifiers=%r" % (title, identifiers))
            log.info("Calibre-ZUO: download_cover 命中 (title=%s, identifiers=%s)", title, identifiers)
            identifiers = identifiers or {}
            novel_id = self._get_identifier(identifiers)
            cover_url = None

            # 优先按标识符直接拉封面
            if novel_id:
                record = self._safe_load_detail(novel_id, log)
                if record:
                    cover_url = record.get("cover")
                    log.info("Calibre-ZUO: 按标识符定位到封面 %s (novel_id=%s)", cover_url, novel_id)

            # 无标识符（单独下载封面时）退回到按书名搜索拿封面
            if not cover_url:
                for query in self._build_keywords(title):
                    log.info("Calibre-ZUO: 无标识符，按书名搜索封面 query=%s", query)
                    try:
                        items, _total = self.client.search_books(query, page=1, page_size=self.page_size)
                    except ZuoApiError as err:
                        log.error(f"Calibre-ZUO: 封面搜索失败，原因: {err}")
                        return
                    log.info("Calibre-ZUO: 书名 %s 命中 %s 条", query, len(items))
                    for item in items:
                        cover_url = item.get("cover")
                        log.info("Calibre-ZUO: 候选 id=%s cover=%s", item.get("id"), cover_url)
                        if cover_url:
                            novel_id = item.get("id")
                            break
                    if cover_url:
                        break

            if not cover_url or novel_id is None:
                log.warning("Calibre-ZUO: 未找到可用封面 cover_url=%s novel_id=%s", cover_url, novel_id)
                return
            log.info("Calibre-ZUO: 开始下载封面 %s", cover_url)
            data = self.client.download_cover(cover_url)
            log.info("Calibre-ZUO: 封面下载完成，字节数=%s", len(data) if data else 0)
            if data:
                result_queue.put((self, self._to_readable_image(data)))
        except Exception as err:  # 兜底：不放过任何异常，写追踪并打堆栈
            import traceback as _tb
            self._trace("EXC download_cover: %r\n%s" % (err, _tb.format_exc()))
            log.exception("Calibre-ZUO: download_cover 未捕获异常: %r", err)

    # ------------------------------------------------------------------
    # 自定义列定义与回填
    # ------------------------------------------------------------------
    def get_custom_column_definitions(self):
        return {
            "#zuo_word_count": {"label": _("网文字数"), "column_type": "int"},
            "#zuo_status": {"label": _("连载状态码"), "column_type": "text"},
            "#zuo_original_site": {"label": _("首发站"), "column_type": "text"},
            "#zuo_first_order": {"label": _("首订数"), "column_type": "int"},
            "#zuo_rating_count": {"label": _("评分人数"), "column_type": "int"},
            "#zuo_read_count": {"label": _("在读人数"), "column_type": "int"},
            "#zuo_fans_count": {"label": _("粉丝数"), "column_type": "int"},
            "#zuo_recommended_count": {"label": _("推荐票"), "column_type": "int"},
            "#zuo_favorited_count": {"label": _("收藏数"), "column_type": "int"},
            "#zuo_average_sub": {"label": _("均订"), "column_type": "int"},
            "#zuo_max_sub": {"label": _("最高订"), "column_type": "int"},
            "#zuo_booklist_count": {"label": _("书单收录"), "column_type": "int"},
            "#zuo_complete_date": {"label": _("完结日期"), "column_type": "text"},
        }

    def get_extended_metadata(self, identifiers):
        identifiers = identifiers or {}
        novel_id = self._get_identifier(identifiers)
        if not novel_id:
            return {}
        record = self._safe_load_detail(novel_id, self._temp_log())
        if not record:
            return {}
        result = {}
        # 数值类指标统一走 _cast_int 安全转换（详情字段可能以字符串/数字两种类型出现）
        stats = {
            "#zuo_word_count": "word_count",
            "#zuo_first_order": "first_order",
            "#zuo_rating_count": "rating_count",
            "#zuo_read_count": "read_count",
            "#zuo_fans_count": "fans_count",
            "#zuo_recommended_count": "recommended_count",
            "#zuo_favorited_count": "favorited_count",
            "#zuo_average_sub": "average_sub",
            "#zuo_max_sub": "max_sub",
            "#zuo_booklist_count": "booklist_count",
        }
        for column, field in stats.items():
            value = self._cast_int(record.get(field))
            if value is not None:
                result[column] = value
        if record.get("status") is not None:
            result["#zuo_status"] = str(record["status"])
        if record.get("original_site") not in (None, ""):
            result["#zuo_original_site"] = str(record["original_site"])
        if record.get("complete_date") not in (None, ""):
            result["#zuo_complete_date"] = str(record["complete_date"])
        return result

    # ------------------------------------------------------------------
    # 内部工具
    # ------------------------------------------------------------------
    def _safe_load_detail(self, novel_id, log):
        """带限速与容错的详情拉取，失败返回 None。"""
        try:
            if self.rate_limiter:
                self.rate_limiter.wait_for_slot()
            return self.client.get_book(novel_id)
        except ZuoApiError as err:
            log.error(f"Calibre-ZUO: 加载详情失败 id={novel_id}: {err}")
            return None


    @staticmethod
    def _to_readable_image(data):
        # Calibre 8.x 的 covers.py 无法解析部分 WebP（读不出尺寸），统一用 Pillow 转成 PNG 再交给 Calibre。
        # Pillow 在 Calibre 嵌入式 Python 中验证可正常读取该 WebP 并转 PNG。
        if not data:
            return None
        try:
            from io import BytesIO
            from PIL import Image
            with Image.open(BytesIO(data)) as im:
                out = BytesIO()
                im.convert('RGB').save(out, format='PNG')
                return out.getvalue()
        except Exception:
            # 转换失败则原样回传，避免额外报错
            return data
    def _emit_metadata(self, record, result_queue, log, abort):
        book_id = record.get("id")
        if not book_id:
            return
        # 写入 zuo-novel-id 标识符：Calibre 单独“下载封面”走 get_cover，只能拿 identifiers 匹配书，
        # 没有该 id 则封面无法关联到本书；它会显示在书的标识符栏中
        mi = Metadata(record.get("title") or _("(未命名)"))
        mi.set_identifier(IDENTIFIER_KEY, str(book_id))

        authors = self._split_authors(record.get("pen_name") or record.get("author"))
        if authors:
            mi.authors = authors

        desc = record.get("description")
        if not desc:
            summary = record.get("summary") or []
            if summary:
                desc = "\n".join(summary)
        desc = self._clean_description(desc)
        if desc:
            mi.comments = desc

        tags = self._extract_tags(record.get("tags") or [])
        if tags:
            mi.tags = tags

        rating = self._normalize_rating(record.get("avg_rating"))
        if rating is not None:
            mi.rating = rating

        publisher = record.get("publisher") or record.get("producer")
        if publisher:
            mi.publisher = publisher

        pubdate = self._parse_date(record.get("publish_date"))
        if pubdate:
            mi.pubdate = pubdate

        isbn = record.get("isbn")
        if isinstance(isbn, str) and isbn.strip():
            mi.isbn = isbn.strip()

        translators = record.get("translators")
        if isinstance(translators, list) and translators:
            valid = [tr for tr in translators if isinstance(tr, str) and tr.strip()]
            if valid:
                mi.translators = valid

        original_title = record.get("original_title")
        if isinstance(original_title, str) and original_title.strip():
            mi.original_title = original_title.strip()


        result_queue.put(mi)

    # ------------------------------------------------------------------
    # 字段处理辅助
    # ------------------------------------------------------------------
    @staticmethod
    def _get_identifier(identifiers):
        val = identifiers.get(IDENTIFIER_KEY)
        return str(val) if val not in (None, "") else None

    @staticmethod
    def _split_authors(text):
        if not isinstance(text, str) or not text.strip():
            return []
        import re
        parts = [p.strip() for p in re.split(r"[、,/，]", text) if p.strip()]
        return parts or []

    @staticmethod
    def _extract_tags(tags):
        names = []
        for tag in tags:
            if isinstance(tag, dict):
                name = tag.get("name")
            else:
                name = tag
            if isinstance(name, str) and name.strip():
                names.append(name.strip())
        return names

    @staticmethod
    def _clean_description(desc):
        """剥掉简介常见的“简介 |/：”式标签前缀，保留正文。"""
        if not isinstance(desc, str) or not desc.strip():
            return None
        import re
        cleaned = re.sub(r"^\s*(内容简介|简介)\s*[:：|｜]?\s*", "", desc).strip()
        return cleaned or None

    @staticmethod
    def _cast_int(value):
        """把详情数值（int/str）安全转 int，空值或非法返回 None。"""
        if value is None or value == "":
            return None
        try:
            return int(value)
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _normalize_rating(value):
        """归一化评分到 0-5 星（站点若为 0-10 分则除以 2），非法值返回 None。"""
        if value is None:
            return None
        try:
            v = float(value)
        except (TypeError, ValueError):
            return None
        if v <= 0:
            return None
        if v > 5:
            v = v / 2.0
        return round(max(0.0, min(5.0, v)), 1)

    @staticmethod
    def _parse_date(value):
        # 健壮解析发布日期：源站为完整年月日，尽量保留日；仅有年月时退化为该月 1 日。
        # Calibre 的 mi.pubdate 需为 datetime 而非 date，否则合并结果时比较类型会崩。
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        if not isinstance(value, str):
            return None
        s = value.strip()
        if not s:
            return None
        # 中文日期：2026年2月15日 / 2026年2月 -> 2026-2-15 / 2026-2
        s = s.replace("年", "-").replace("月", "-").replace("日", "")
        s = s.rstrip("-")
        # 带时间戳：2016-12-31T16:00:00+00:00 -> 2016-12-31
        t = s.find("T")
        if t > 0:
            s = s[:t].rstrip("-")
        for fmt in ("%Y-%m-%d", "%Y-%m", "%Y"):
            try:
                return datetime.strptime(s, fmt)
            except ValueError:
                continue
        return None

    def _build_keywords(self, title):
        """Calibre 下载元数据按作品名称匹配：仅用书名作关键词（搜索为 ILIKE 子串匹配）。"""
        t = title.strip() if isinstance(title, str) and title.strip() else None
        return [t] if t else []

    def _use_page(self):
        return 1

    # 自定义列回填需要 log 参数但调用链无 log，提供临时占位 logger
    def _temp_log(self):
        class _NullLog:
            def debug(self, *a, **k):
                pass
            def info(self, *a, **k):
                pass
            def error(self, *a, **k):
                pass
        return _NullLog()

    # ------------------------------------------------------------------
    # 配置界面
    # ------------------------------------------------------------------
    def is_customizable(self):
        return True

    def config_widget(self):
        from calibre.gui2 import ConfigWidgetBase  # noqa: F401  # 延迟导入避免头部依赖 GUI
        QtWidgets = self._load_qt_widgets()

        class ConfigWidget(QtWidgets.QWidget):
            def __init__(self, plugin):
                QtWidgets.QWidget.__init__(self)
                self.backup = {}
                self.plugin = plugin
                self.prefs = plugin.prefs

                layout = QtWidgets.QFormLayout(self)
                self.base_edit = QtWidgets.QLineEdit(str(self.prefs.get("base_url") or DEFAULT_BASE_URL))
                layout.addRow(_("API 地址"), self.base_edit)

                self.hour_spin = QtWidgets.QSpinBox()
                self.hour_spin.setRange(1, 100000)
                self.hour_spin.setValue(int(self.prefs.get("requests_per_hour") or 60))
                layout.addRow(_("每小时请求上限"), self.hour_spin)

                self.page_spin = QtWidgets.QSpinBox()
                self.page_spin.setRange(1, 100)
                self.page_spin.setValue(int(self.prefs.get("page_size") or 5))
                layout.addRow(_("单次拉取数量"), self.page_spin)


                self.timeout_spin = QtWidgets.QSpinBox()
                self.timeout_spin.setRange(5, 300)
                self.timeout_spin.setValue(int(self.prefs.get("request_timeout") or DEFAULT_TIMEOUT))
                layout.addRow(_("请求超时(秒)"), self.timeout_spin)

            def commit(self):
                self.prefs["base_url"] = str(self.base_edit.text()).strip()
                self.prefs["requests_per_hour"] = self.hour_spin.value()
                self.prefs["page_size"] = self.page_spin.value()
                self.prefs["request_timeout"] = self.timeout_spin.value()
                # 配置提交后使新的客户端/限速器生效
                self.plugin._init_client_from_prefs()

        return ConfigWidget(self)

    @staticmethod
    def _load_qt_widgets():
        try:
            from calibre.gui2 import QtWidgets
            return QtWidgets
        except Exception:  # pragma: no cover
            from PyQt5.QtWidgets import QWidget, QFormLayout, QLineEdit, QSpinBox, QCheckBox
            return type("QtWidgets", (), {
                "QWidget": QWidget, "QFormLayout": QFormLayout, "QLineEdit": QLineEdit,
                "QSpinBox": QSpinBox, "QCheckBox": QCheckBox,
            })