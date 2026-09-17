# -*- coding: utf-8 -*-
"""
Calibre-ZUO 数据源客户端 + 请求签名复刻。

背景
----
目标站点（zuo.cc）的公开只读接口（/api/novel/search、/api/novel 等）虽然登录层面允许
匿名访问，但被列在其「API 签名白名单」内：任何请求缺 zuo-cc-ts / zuo-cc-nonce /
zuo-cc-sign 三个头都会返回 401 SIGN_MISSING。

签名算法来自后端 shared 源码（shared/src/utils/api-sign.ts）：
    canonical = METHOD\nPATH\n排序后 query\n空 body 哈希\nts\nonce
    密钥 key  = hex(SHA-256(素材以 "|" 拼接))
    签名      = hex(HMAC-SHA256(key, canonical))
其中密钥素材由公开字面量常量派生（并非真正机密，定位仅是抬高简单脚本抓取门槛）。

!!! 耦合警告 !!!
本文件中的 SIGNED_API_PATHS 必须与后端 shared/src/utils/api-sign.ts 保持完全一致
（顺序、内容都不能变，因为密钥由它派生）。后端每改动一次白名单，本插件都必须
同步更新并重新打包，否则签名失配。

小写十六进制常量均直接取自后端源码，禁止「随手改动」。
"""
import gzip
import hashlib
import hmac
import json
import os
import time
from typing import Optional
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlparse
from urllib.request import Request, urlopen

# ---------------------------------------------------------------------------
# 请求头常量（与 shared/src/utils/api-sign.ts 对齐）
# ---------------------------------------------------------------------------
API_SIGN_TS_HEADER = "zuo-cc-ts"
API_SIGN_NONCE_HEADER = "zuo-cc-nonce"
API_SIGN_HEADER = "zuo-cc-sign"

# 时间戳窗口：±5 分钟（毫秒）
API_SIGN_WINDOW_MS = 300000

# ---------------------------------------------------------------------------
# 密钥派生素材（三段独立随机 hex，取自 shared 源码；命名与后端对齐，无 secret 字样）
# ---------------------------------------------------------------------------
_API_SIGN_MATERIAL_SEGMENT_A = "277381cbe01c08f85a2dd8eca1ffbb62"
_API_SIGN_MATERIAL_SEGMENT_B = "67e7903c3da43115b688155a8b05998c"
_API_SIGN_MATERIAL_SEGMENT_C = "5fe1e16a010dbf2b64032dcfcc710678"

# 空串的 SHA-256 hex：白名单接口全部为 GET 无请求体
API_SIGN_EMPTY_BODY_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"

# ---------------------------------------------------------------------------
# 签名白名单（!! 必须与后端 shared/src/utils/api-sign.ts 的 SIGNED_API_PATHS 完全一致 !!）
# ---------------------------------------------------------------------------
SIGNED_API_PATHS = [
    "/api/novel",
    "/api/novel/massive",
    "/api/novel/badge",
    "/api/novel/tag/:slug",
    "/api/novel/achievements",
    "/api/novel/fans-count",
    "/api/novel/rating",
    "/api/novel/read-count",
    "/api/novel/word-count",
    "/api/novel/first-order",
    "/api/novel/recommended-count",
    "/api/novel/favorited-count",
    "/api/novel/average-sub",
    "/api/novel/max-sub",
    "/api/novel/fanqie-read-count",
    "/api/system-booklist/novels",
    "/api/author",
    "/api/novel/wanding-authors",
    "/api/novel/origin",
    "/api/novel/date",
    "/api/novel/date/years",
    "/api/author/:penName/novels",
    "/api/novel/search",
    "/api/novel/advanced-search",
    "/api/author/search",
    "/api/wiki/search",
    "/api/author/vintage",
    "/api/author/tomato",
    "/api/author/yuewen",
    "/api/author/multi-open",
    "/api/author/most-words",
    "/api/author/eunuch",
    "/api/author/deceased",
    "/api/author/alias",
    "/api/plagiarism",
    "/api/timeline",
    "/api/timeline/stats",
    "/api/activities",
    "/api/wiki/entities",
    "/api/wiki/entity-names",
]


class ZuoApiError(Exception):
    """封装站点 API 的稳定可读错误。"""


# ---------------------------------------------------------------------------
# 签名算法实现（与前端 computed 结果逐字节一致）
# ---------------------------------------------------------------------------

def derive_sign_key() -> str:
    """按后端算法派生签名密钥：返回 SHA-256(素材以"|"拼接) 的 hex 小写串。"""
    material = "|".join(
        [
            _API_SIGN_MATERIAL_SEGMENT_A,
            "\n".join(SIGNED_API_PATHS),
            _API_SIGN_MATERIAL_SEGMENT_B,
            API_SIGN_EMPTY_BODY_HASH,
            str(API_SIGN_WINDOW_MS),
            _API_SIGN_MATERIAL_SEGMENT_C,
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def build_canonical_query(pairs):
    """规范化 query：剥掉 key 尾部 []、按 key 排序、以原始值拼 k=v&k=v。"""
    normalized = []
    for raw_key, value in pairs:
        key = raw_key[:-2] if raw_key.endswith("[]") else raw_key
        normalized.append((key, value))
    # sorted 默认按第一个元素（key）按 Unicode 码点排序，与 JS toSorted 对齐
    normalized.sort(key=lambda item: item[0])
    return "&".join(f"{k}={v}" for k, v in normalized)


def sign_request(method, path, query_params):
    """为指定 path 与 query 计算三芝麻认证头部（ts/nonce/sign）。"""
    canonical_query = build_canonical_query(query_params)
    ts = str(int(time.time() * 1000))
    nonce = os.urandom(16).hex()
    canonical = "\n".join([method, path, canonical_query, API_SIGN_EMPTY_BODY_HASH, ts, nonce])
    key = derive_sign_key().encode("utf-8")
    signature = hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()
    return {
        API_SIGN_TS_HEADER: ts,
        API_SIGN_NONCE_HEADER: nonce,
        API_SIGN_HEADER: signature,
    }


class ZuoApiClient:
    """连接 zuo.cc 的轻量只读客户端：负责签名、发送与统一信封解包。"""

    def __init__(self, base_url: str, timeout: float = 20.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout

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
    def request(self, path: str, query_params):
        """携带签名头发起 GET，返回解包成功信封后的 data 下的原始 payload。"""
        headers = {
            "Accept": "application/json",
            "User-Agent": self._user_agent(),
            **sign_request("GET", path, query_params),
        }
        query_string = urlencode({k: v for k, v in query_params if v not in (None, "")})
        url = f"{self.base_url}{path}"
        if query_string:
            url = f"{url}?{query_string}"
        req = Request(url, headers=headers, method="GET")
        return self._open(req)

    def _open(self, req):
        try:
            with urlopen(req, timeout=self.timeout) as resp:
                data = resp.read()
                if resp.info().get("Content-Encoding") == "gzip":
                    data = gzip.decompress(data)
                charset = resp.headers.get_content_charset() or "utf-8"
                payload = json.loads(data.decode(charset))
        except HTTPError as err:
            raise ZuoApiError(f"HTTP 错误: {err.code}")
        except URLError as err:
            raise ZuoApiError(f"网络错误: {err.reason}")
        except json.JSONDecodeError as err:
            raise ZuoApiError(f"解析响应失败: {err.msg}")

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
    复用站点现有只读 API（/api/novel/search、/api/novel），由 src/api.py 负责
    HMAC 签名（站点签名白名单要求）。请勿改动 src/api.py 中的签名常量。
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
PROVIDER_VERSION = (1, 0, 9)
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