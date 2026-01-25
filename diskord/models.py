import uuid
from datetime import datetime
from sqlalchemy import Column, String, DateTime, ForeignKey, Text, UniqueConstraint
from sqlalchemy.orm import relationship
from db import Base

def uid() -> str:
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"
    id = Column(String, primary_key=True, default=uid)
    username = Column(String, unique=True, index=True, nullable=False)
    password_hash = Column(String, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class Friendship(Base):
    __tablename__ = "friendships"
    id = Column(String, primary_key=True, default=uid)
    requester_id = Column(String, ForeignKey("users.id"), index=True, nullable=False)
    addressee_id = Column(String, ForeignKey("users.id"), index=True, nullable=False)
    status = Column(String, nullable=False, default="pending")
    created_at = Column(DateTime, default=datetime.utcnow)

    requester = relationship("User", foreign_keys=[requester_id])
    addressee = relationship("User", foreign_keys=[addressee_id])

    __table_args__ = (UniqueConstraint("requester_id", "addressee_id", name="uq_friendship_pair"),)

class Conversation(Base):
    __tablename__ = "conversations"
    id = Column(String, primary_key=True, default=uid)
    type = Column(String, nullable=False)  # dm|group
    name = Column(String, nullable=True)
    dm_key = Column(String, unique=True, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class ConversationMember(Base):
    __tablename__ = "conversation_members"
    id = Column(String, primary_key=True, default=uid)
    conversation_id = Column(String, ForeignKey("conversations.id"), index=True, nullable=False)
    user_id = Column(String, ForeignKey("users.id"), index=True, nullable=False)
    role = Column(String, nullable=False, default="member")
    joined_at = Column(DateTime, default=datetime.utcnow)

    user = relationship("User")
    conversation = relationship("Conversation")

    __table_args__ = (UniqueConstraint("conversation_id", "user_id", name="uq_conversation_member"),)

class Message(Base):
    __tablename__ = "messages"
    id = Column(String, primary_key=True, default=uid)
    conversation_id = Column(String, ForeignKey("conversations.id"), index=True, nullable=False)
    user_id = Column(String, ForeignKey("users.id"), index=True, nullable=False)
    content = Column(Text, nullable=False)
    attachment_name = Column(String, nullable=True)
    attachment_path = Column(String, nullable=True)
    attachment_mime = Column(String, nullable=True)
    attachment_size = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)

    user = relationship("User")
    conversation = relationship("Conversation")
