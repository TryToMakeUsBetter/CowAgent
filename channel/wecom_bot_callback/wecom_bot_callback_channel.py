"""
WeCom (企业微信) AI Bot Callback Channel - URL接入(被动回调)模式

基于企业微信智能机器人回调接口实现，通过 HTTP 回调接收和回复消息，
适配大公司关闭 WebSocket 长连接通道的安全合规要求。

Supports:
- URL 验证 (GET echostr)
- 加密消息解密 (AES + WXBizMsgCrypt)
- 文本消息接收与异步回复 (通过 WeCom API)
- 群聊和单聊支持

Config keys required:
    wecom_corp_id          - 企业微信 CorpID
    wecom_bot_token        - 回调 Token
    wecom_bot_encoding_aes_key - 回调 EncodingAESKey
    wecom_bot_callback_port - HTTP 服务端口 (默认 9892)
"""

import threading
import time
import xml.etree.ElementTree as ET

import requests
import web

from bridge.context import Context, ContextType
from bridge.reply import Reply, ReplyType
from channel.chat_channel import ChatChannel, check_prefix
from channel.wecom_bot_callback.wecom_bot_callback_message import WecomBotCallbackMessage
from common.expired_dict import ExpiredDict
from common.log import logger
from common.singleton import singleton
from config import conf

try:
    from wechatpy.crypto import WeChatCrypto
except ImportError:
    WeChatCrypto = None

# XML reply template for passive reply (used when reply is fast enough)
XML_TEXT_TMPL = """<xml>
<ToUserName><![CDATA[{to_user}]]></ToUserName>
<FromUserName><![CDATA[{from_user}]]></FromUserName>
<CreateTime>{create_time}</CreateTime>
<MsgType><![CDATA[text]]></MsgType>
<Content><![CDATA[{content}]]></Content>
</xml>"""

WECOM_API_BASE = "https://qyapi.weixin.qq.com"


@singleton
class WecomBotCallbackChannel(ChatChannel):
    """企业微信智能机器人回调通道 (URL接入模式)."""

    NOT_SUPPORT_REPLYTYPE = []

    def __init__(self):
        super().__init__()
        self.corp_id = ""
        self.bot_token = ""
        self.encoding_aes_key = ""
        self.crypto = None  # WeChatCrypto instance
        self._http_server = None
        self._access_token = None
        self._access_token_expires_at = 0
        self._access_token_lock = threading.Lock()
        self.received_msgs = ExpiredDict(60 * 60 * 7.1)
        conf()["group_name_white_list"] = ["ALL_GROUP"]
        conf()["single_chat_prefix"] = [""]

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def startup(self):
        self.corp_id = conf().get("wecom_corp_id", "")
        self.bot_token = conf().get("wecom_bot_token", "")
        self.encoding_aes_key = conf().get("wecom_bot_encoding_aes_key", "")

        if not self.corp_id or not self.bot_token or not self.encoding_aes_key:
            err = (
                "[WecomBotCallback] wecom_corp_id, wecom_bot_token, and "
                "wecom_bot_encoding_aes_key are required. "
                "Please configure them in config.json."
            )
            logger.error(err)
            self.report_startup_error(err)
            return

        if WeChatCrypto is None:
            err = "[WecomBotCallback] wechatpy is required for callback mode. Please install: pip install wechatpy"
            logger.error(err)
            self.report_startup_error(err)
            return

        try:
            self.crypto = WeChatCrypto(self.bot_token, self.encoding_aes_key, self.corp_id)
        except Exception as e:
            err = f"[WecomBotCallback] Failed to initialize WeChatCrypto: {e}"
            logger.error(err)
            self.report_startup_error(err)
            return

        logger.info("[WecomBotCallback] Starting HTTP callback server...")
        urls = ("/wecom_bot", "channel.wecom_bot_callback.wecom_bot_callback_channel.WecomBotCallbackController")
        app = web.application(urls, globals(), autoreload=False)
        port = conf().get("wecom_bot_callback_port", 9892)
        func = web.httpserver.StaticMiddleware(app.wsgifunc())
        func = web.httpserver.LogMiddleware(func)
        server = web.httpserver.WSGIServer(("0.0.0.0", port), func)
        self._http_server = server
        self.report_startup_success()
        logger.info(f"[WecomBotCallback] HTTP server started on port {port}")
        try:
            server.start()
        except (KeyboardInterrupt, SystemExit):
            server.stop()

    def stop(self):
        logger.info("[WecomBotCallback] stop() called")
        if self._http_server:
            try:
                self._http_server.stop()
                logger.info("[WecomBotCallback] HTTP server stopped")
            except Exception as e:
                logger.warning(f"[WecomBotCallback] Error stopping HTTP server: {e}")
            self._http_server = None

    # ------------------------------------------------------------------
    # Access Token (for async reply via WeCom API)
    # ------------------------------------------------------------------

    def _get_access_token(self) -> str:
        """Get a valid WeCom API access_token, refreshing if expired."""
        now = time.time()
        with self._access_token_lock:
            if self._access_token and now < self._access_token_expires_at - 60:
                return self._access_token

        corp_secret = conf().get("wecom_bot_secret", "")
        if not corp_secret:
            logger.error("[WecomBotCallback] wecom_bot_secret is required for async reply via API")
            return ""

        try:
            url = f"{WECOM_API_BASE}/cgi-bin/gettoken"
            resp = requests.get(url, params={
                "corpid": self.corp_id,
                "corpsecret": corp_secret,
            }, timeout=10)
            data = resp.json()
            if data.get("errcode") == 0:
                with self._access_token_lock:
                    self._access_token = data["access_token"]
                    self._access_token_expires_at = now + data.get("expires_in", 7200)
                logger.debug("[WecomBotCallback] Access token refreshed")
                return self._access_token
            else:
                logger.error(f"[WecomBotCallback] Failed to get access_token: {data}")
                return ""
        except Exception as e:
            logger.error(f"[WecomBotCallback] Error getting access_token: {e}")
            return ""

    # ------------------------------------------------------------------
    # Message handling entry point (called from HTTP controller)
    # ------------------------------------------------------------------

    def handle_callback_message(self, xml_body: str, msg_signature: str,
                                 timestamp: str, nonce: str) -> str:
        """
        Decrypt and process an incoming WeCom bot callback message.
        Returns XML reply string for the HTTP response (may be empty).
        """
        try:
            # 1. Decrypt
            decrypted_xml = self.crypto.decrypt_message(
                xml_body, msg_signature, timestamp, nonce
            )
            logger.debug(f"[WecomBotCallback] Decrypted XML: {decrypted_xml}")

            # 2. Parse XML
            root = ET.fromstring(decrypted_xml)
            msg_type = root.findtext("MsgType", "")
            logger.info(f"[WecomBotCallback] Received msg_type={msg_type}")

            # 3. Handle based on msg_type
            if msg_type == "text":
                self._handle_text_message(root)
            elif msg_type == "image":
                self._handle_media_message(root, ContextType.IMAGE)
            elif msg_type == "voice":
                self._handle_media_message(root, ContextType.VOICE)
            elif msg_type == "event":
                self._handle_event_message(root)
            else:
                logger.debug(f"[WecomBotCallback] Unhandled msg_type: {msg_type}")

        except Exception as e:
            logger.error(f"[WecomBotCallback] Error handling callback message: {e}", exc_info=True)

        # Always return success (empty string) to WeCom — actual reply is sent
        # asynchronously via API because agent processing may exceed the 5s timeout.
        return ""

    # ------------------------------------------------------------------
    # Message type handlers
    # ------------------------------------------------------------------

    def _handle_text_message(self, root: ET.Element):
        """Handle a text message from the XML payload."""
        from_user = root.findtext("FromUserName", "")
        to_user = root.findtext("ToUserName", "")
        content = root.findtext("Content", "")
        msg_id = root.findtext("MsgId", "")
        create_time = root.findtext("CreateTime", "")

        if not content:
            return

        # Idempotency
        if self.received_msgs.get(msg_id):
            logger.debug(f"[WecomBotCallback] Duplicate msg filtered: {msg_id}")
            return
        self.received_msgs[msg_id] = True

        # Determine if group chat
        # In WeCom callback, FromUserName for group chat is "chat:xxx" or similar
        is_group = "@chatroom" in from_user or from_user.startswith("chat:")
        chat_id = from_user if is_group else None

        # Build message object
        wecom_msg = WecomBotCallbackMessage(
            msg_type="text",
            content=content,
            msg_id=msg_id,
            from_user=from_user,
            to_user=to_user,
            create_time=create_time,
            is_group=is_group,
            chat_id=chat_id or from_user,
        )
        self._process_message(wecom_msg)

    def _handle_media_message(self, root: ET.Element, ctype: ContextType):
        """Handle image/voice/file messages."""
        from_user = root.findtext("FromUserName", "")
        to_user = root.findtext("ToUserName", "")
        msg_id = root.findtext("MsgId", "")
        create_time = root.findtext("CreateTime", "")
        media_id = root.findtext("MediaId", "")
        pic_url = root.findtext("PicUrl", "")  # image URL

        if self.received_msgs.get(msg_id):
            return
        self.received_msgs[msg_id] = True

        is_group = "@chatroom" in from_user or from_user.startswith("chat:")
        chat_id = from_user if is_group else None

        wecom_msg = WecomBotCallbackMessage(
            msg_type=ctype.name.lower(),
            content=pic_url if ctype == ContextType.IMAGE else "",
            msg_id=msg_id,
            from_user=from_user,
            to_user=to_user,
            create_time=create_time,
            is_group=is_group,
            chat_id=chat_id or from_user,
            media_id=media_id,
        )

        if ctype == ContextType.IMAGE:
            from channel.file_cache import get_file_cache
            session_id = chat_id if is_group else from_user
            if pic_url:
                get_file_cache().add(session_id, pic_url, file_type="image")
                logger.info(f"[WecomBotCallback] Image cached for session {session_id}")
            return
        elif ctype == ContextType.VOICE:
            # Voice reply via voice recognition
            self._process_message(wecom_msg)

    def _handle_event_message(self, root: ET.Element):
        """Handle event messages (e.g., subscribe, unsubscribe)."""
        event = root.findtext("Event", "")
        logger.info(f"[WecomBotCallback] Event received: {event}")

    # ------------------------------------------------------------------
    # Common message processing
    # ------------------------------------------------------------------

    def _process_message(self, wecom_msg: WecomBotCallbackMessage):
        """Process a parsed WeCom message through the standard ChatChannel pipeline."""
        is_group = wecom_msg.is_group

        if is_group:
            if conf().get("group_shared_session", True):
                session_id = wecom_msg.chat_id
            else:
                session_id = wecom_msg.from_user_id + "_" + wecom_msg.chat_id
        else:
            session_id = wecom_msg.from_user_id

        # Attach cached files if present
        if wecom_msg.ctype == ContextType.TEXT:
            from channel.file_cache import get_file_cache
            file_cache = get_file_cache()
            cached_files = file_cache.get(session_id)
            if cached_files:
                file_refs = []
                for fi in cached_files:
                    ftype = fi["type"]
                    fpath = fi["path"]
                    if ftype == "image":
                        file_refs.append(f"[图片: {fpath}]")
                    elif ftype == "video":
                        file_refs.append(f"[视频: {fpath}]")
                    else:
                        file_refs.append(f"[文件: {fpath}]")
                wecom_msg.content = wecom_msg.content + "\n" + "\n".join(file_refs)
                logger.info(f"[WecomBotCallback] Attached {len(cached_files)} cached file(s)")
                file_cache.clear(session_id)

        context = self._compose_context(
            wecom_msg.ctype,
            wecom_msg.content,
            isgroup=is_group,
            msg=wecom_msg,
            no_need_at=True,
        )
        if context:
            self.produce(context)

    # ------------------------------------------------------------------
    # _compose_context (same pattern as wecom_bot / feishu)
    # ------------------------------------------------------------------

    def _compose_context(self, ctype: ContextType, content, **kwargs):
        context = Context(ctype, content)
        context.kwargs = kwargs
        if "channel_type" not in context:
            context["channel_type"] = self.channel_type
        if "origin_ctype" not in context:
            context["origin_ctype"] = ctype

        cmsg = context["msg"]

        if cmsg.is_group:
            if conf().get("group_shared_session", True):
                context["session_id"] = cmsg.other_user_id
            else:
                context["session_id"] = f"{cmsg.from_user_id}:{cmsg.other_user_id}"
        else:
            context["session_id"] = cmsg.from_user_id

        context["receiver"] = cmsg.other_user_id

        if ctype == ContextType.TEXT:
            img_match_prefix = check_prefix(content, conf().get("image_create_prefix"))
            if img_match_prefix:
                content = content.replace(img_match_prefix, "", 1)
                context.type = ContextType.IMAGE_CREATE
            else:
                context.type = ContextType.TEXT
            context.content = content.strip()
            if "desire_rtype" not in context and conf().get("always_reply_voice"):
                context["desire_rtype"] = ReplyType.VOICE

        return context

    # ------------------------------------------------------------------
    # Send reply — async via WeCom API (not websocket, no req_id)
    # ------------------------------------------------------------------

    def send(self, reply: Reply, context: Context):
        """Send reply to WeCom user via REST API (async, no req_id)."""
        msg = context.get("msg")
        is_group = context.get("isgroup", False)
        receiver = context.get("receiver", "")

        if reply.type == ReplyType.TEXT:
            self._send_text_via_api(reply.content, receiver, is_group)
        elif reply.type in (ReplyType.IMAGE_URL, ReplyType.IMAGE):
            self._send_text_via_api(f"[Image: {reply.content}]", receiver, is_group)
        elif reply.type == ReplyType.FILE:
            # Send text note for files via API (file upload not supported in callback mode)
            file_info = reply.content if reply.content else "a file"
            self._send_text_via_api(f"[File: {file_info}]", receiver, is_group)
        elif reply.type == ReplyType.VOICE:
            self._send_text_via_api(str(reply.content), receiver, is_group)
        elif reply.type == ReplyType.ERROR or reply.type == ReplyType.INFO:
            self._send_text_via_api(str(reply.content), receiver, is_group)
        else:
            logger.warning(f"[WecomBotCallback] Unsupported reply type via API: {reply.type}")
            self._send_text_via_api(str(reply.content), receiver, is_group)

    def _send_text_via_api(self, content: str, receiver: str, is_group: bool):
        """Send text/markdown message to a user/group via WeCom API.

        Uses the WeCom app message/send API with access_token.
        For AI bots, we try both the regular message send and the bot-specific API.
        """
        if not content or not receiver:
            return

        access_token = self._get_access_token()
        if not access_token:
            logger.error("[WecomBotCallback] Cannot send reply: no access_token")
            return

        # Try: send via app message API (works for both bot and app)
        # For group chat, receiver is the chat_id; for single chat, it's the user_id
        url = f"{WECOM_API_BASE}/cgi-bin/message/send?access_token={access_token}"

        if is_group:
            body = {
                "touser": receiver,
                "msgtype": "text",
                "agentid": conf().get("wecom_agent_id", 0),
                "text": {"content": content},
            }
        else:
            body = {
                "touser": receiver,
                "msgtype": "text",
                "agentid": conf().get("wecom_agent_id", 0),
                "text": {"content": content},
            }

        try:
            resp = requests.post(url, json=body, timeout=10)
            data = resp.json()
            if data.get("errcode") == 0:
                logger.info(f"[WecomBotCallback] Reply sent to {receiver}")
            else:
                logger.error(f"[WecomBotCallback] Failed to send reply: {data}")
        except Exception as e:
            logger.error(f"[WecomBotCallback] Error sending reply: {e}")


class WecomBotCallbackController:
    """HTTP controller for WeCom bot callback URL (web.py).

    Routes:
        GET  /wecom_bot  → URL verification (echostr)
        POST /wecom_bot  → Message callback
    """

    def GET(self):
        try:
            channel = WecomBotCallbackChannel()
            args = web.input()
            msg_signature = args.get("msg_signature", "")
            timestamp = args.get("timestamp", "")
            nonce = args.get("nonce", "")
            echostr = args.get("echostr", "")

            if not channel.crypto:
                logger.error("[WecomBotCallback] Crypto not initialized for URL verification")
                raise web.Forbidden("Crypto not initialized")

            # echostr is already encrypted — decrypt it
            # WeChatCrypto.check_signature verifies and decrypts echostr
            decrypted_echostr = channel.crypto.check_signature(
                msg_signature, timestamp, nonce, echostr
            )
            logger.info("[WecomBotCallback] URL verification succeeded")
            return decrypted_echostr
        except Exception as e:
            logger.error(f"[WecomBotCallback] URL verification failed: {e}")
            raise web.Forbidden(str(e))

    def POST(self):
        try:
            channel = WecomBotCallbackChannel()
            args = web.input()
            msg_signature = args.get("msg_signature", "")
            timestamp = args.get("timestamp", "")
            nonce = args.get("nonce", "")

            xml_body = web.data().decode("utf-8")
            logger.debug(f"[WecomBotCallback] POST body: {xml_body[:200]}...")

            if not channel.crypto:
                logger.error("[WecomBotCallback] Crypto not initialized for message processing")
                return ""

            # Process message asynchronously — return empty to avoid timeout
            reply_xml = channel.handle_callback_message(
                xml_body, msg_signature, timestamp, nonce
            )
            return reply_xml

        except Exception as e:
            logger.error(f"[WecomBotCallback] POST handling error: {e}", exc_info=True)
            return ""
