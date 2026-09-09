"""
models.py — SQLAlchemy ORM models (database table definitions).
"""

from sqlalchemy import Column, Integer, String, DateTime, Boolean, ForeignKey, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from database import Base


class User(Base):
    """Users table — stores registered account credentials."""
    __tablename__ = "users"

    id            = Column(Integer, primary_key=True, index=True, autoincrement=True)
    full_name     = Column(String(120), nullable=False)
    email         = Column(String(255), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    is_active     = Column(Boolean, default=True)
    created_at    = Column(DateTime(timezone=True), server_default=func.now())

    login_history = relationship("LoginHistory", back_populates="user", cascade="all, delete-orphan")
    scan_history  = relationship("ScanHistory", back_populates="user", cascade="all, delete-orphan")


class LoginHistory(Base):
    """Login history table — records authentication events per user."""
    __tablename__ = "login_history"

    id           = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id      = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    timestamp    = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    ip_address   = Column(String(64), nullable=True)
    user_agent   = Column(String(255), nullable=True)
    session_type = Column(String(64), default="Web Session")

    user = relationship("User", back_populates="login_history")


class ScanHistory(Base):
    """Scan history table — stores completed target scans and JSON output per user."""
    __tablename__ = "scan_history"

    id          = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id     = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    target      = Column(String(255), nullable=False, index=True)
    mode        = Column(String(32), default="detailed")
    module      = Column(String(64), nullable=True)
    timestamp   = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    result_json = Column(Text, nullable=False)

    user = relationship("User", back_populates="scan_history")
    batch_scan = relationship("BatchScan", back_populates="parent_scan", uselist=False)


class BatchScan(Base):
    """Batch scan table — parent record for bulk subdomain scanning."""
    __tablename__ = "batch_scans"

    id                    = Column(Integer, primary_key=True, index=True, autoincrement=True)
    parent_scan_id        = Column(Integer, ForeignKey("scan_history.id"), nullable=False, index=True)
    status                = Column(String(32), default="pending")
    total_subdomains      = Column(Integer, default=0)
    completed_scans       = Column(Integer, default=0)
    failed_scans          = Column(Integer, default=0)
    created_at            = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    started_at            = Column(DateTime(timezone=True), nullable=True)
    completed_at          = Column(DateTime(timezone=True), nullable=True)

    parent_scan = relationship("ScanHistory", back_populates="batch_scan")
    subdomain_scans = relationship("SubdomainScan", back_populates="batch_scan", cascade="all, delete-orphan")


class SubdomainScan(Base):
    """Subdomain scan table — individual scan results for each unique subdomain."""
    __tablename__ = "subdomain_scans"

    id              = Column(Integer, primary_key=True, index=True, autoincrement=True)
    batch_scan_id   = Column(Integer, ForeignKey("batch_scans.id"), nullable=False, index=True)
    subdomain       = Column(String(255), nullable=False, index=True)
    resolved_ips    = Column(Text, nullable=True)
    status          = Column(String(32), default="pending")
    error_message   = Column(Text, nullable=True)
    result_json     = Column(Text, nullable=True)
    started_at      = Column(DateTime(timezone=True), nullable=True)
    completed_at    = Column(DateTime(timezone=True), nullable=True)

    batch_scan = relationship("BatchScan", back_populates="subdomain_scans")


class FullScanBatch(Base):
    """Full-scan batch table — parent record for a user-submitted list of up
    to 20 targets, each run through a full Standard/Deep scan. Distinct from
    BatchScan (which batches subdomains discovered by one prior scan): this
    has no parent scan, so it carries its own user_id directly."""
    __tablename__ = "full_scan_batches"

    id                  = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id             = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    mode                = Column(String(32), nullable=False)
    include_reputation  = Column(Boolean, default=True)
    status              = Column(String(32), default="pending")
    total_targets       = Column(Integer, default=0)
    completed_scans     = Column(Integer, default=0)
    failed_scans        = Column(Integer, default=0)
    created_at          = Column(DateTime(timezone=True), server_default=func.now(), index=True)
    started_at          = Column(DateTime(timezone=True), nullable=True)
    completed_at        = Column(DateTime(timezone=True), nullable=True)

    targets = relationship("FullScanBatchTarget", back_populates="batch", cascade="all, delete-orphan")


class FullScanBatchTarget(Base):
    """Individual target result within a FullScanBatch."""
    __tablename__ = "full_scan_batch_targets"

    id            = Column(Integer, primary_key=True, index=True, autoincrement=True)
    batch_id      = Column(Integer, ForeignKey("full_scan_batches.id"), nullable=False, index=True)
    target        = Column(String(255), nullable=False, index=True)
    status        = Column(String(32), default="pending")
    error_message = Column(Text, nullable=True)
    result_json   = Column(Text, nullable=True)
    started_at    = Column(DateTime(timezone=True), nullable=True)
    completed_at  = Column(DateTime(timezone=True), nullable=True)

    batch = relationship("FullScanBatch", back_populates="targets")

