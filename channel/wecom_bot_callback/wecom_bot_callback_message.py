"""
WeCom Bot Callback Message Parser

Parses WeCom bot callback XML messages into the unified ChatMessage format.
"""

from bridge.context import ContextType
from channel.chat_message import ChatMessage


class WecomBotCallbackMessage(ChatMessage):
    """
    Message wrapper for WeCom bot callback (URL接入) mode.

    Attributes follow the ChatMessage interface.
    """

    def __init__(
        self,
        msg_type: str,
        content: str = "",
        msg_id: str = "",
        from_user: str = "",
        to_user: str = "",
        create_time: str = "",
        is_group: bool = False,
        chat_id: str = "",
        media_id: str = "",
    ):
        """
        Initialize a WeCom bot callback message.

        :param msg_type: Message type (text, image, voice, etc.)
        :param content: Message text content (or media URL for images)
        :param msg_id: Unique message ID
        :param from_user: Sender's WeCom user ID
        :param to_user: Receiver's WeCom user ID (bot's ID)
        :param create_time: Unix timestamp string
        :param is_group: Whether this is a group chat message
        :param chat_id: Chat ID (group or user)
        :param media_id: Media ID for file/image/voice messages
        """
        raw_msg = {
            "msg_type": msg_type,
            "msg_id": msg_id,
            "from_user": from_user,
            "to_user": to_user,
            "create_time": create_time,
            "chat_id": chat_id,
            "media_id": media_id,
        }
        super().__init__(raw_msg)

        self.msg_id = msg_id
        self.is_group = is_group

        # Map to common ContextType
        msg_type_lower = msg_type.lower()
        if msg_type_lower == "text":
            self.ctype = ContextType.TEXT
        elif msg_type_lower == "image":
            self.ctype = ContextType.IMAGE
        elif msg_type_lower == "voice":
            self.ctype = ContextType.VOICE
        elif msg_type_lower == "file":
            self.ctype = ContextType.FILE
        else:
            self.ctype = ContextType.TEXT

        self.content = content
        self.from_user_id = from_user
        self.from_user_nickname = from_user
        self.to_user_id = to_user
        self.to_user_nickname = to_user
        self.other_user_id = from_user
        self.other_user_nickname = from_user
        self.actual_user_id = from_user
        self.actual_user_nickname = from_user
        self.chat_id = chat_id
        self.media_id = media_id

        # For group chat, other_user_id is the group chat_id
        if is_group:
            self.other_user_id = chat_id
            self.other_user_nickname = chat_id

        # Convert create_time
        if create_time:
            try:
                self.create_time = int(create_time)
            except (ValueError, TypeError):
                self.create_time = 0
