"""
AegisForge CTF - SQLAlchemy Database Models

This module defines the database models for the AegisForge CTF platform
using SQLAlchemy ORM. Models include challenges, user progress tracking,
solves, hints, achievements, and leaderboard functionality.

Models:
    - Challenge: CTF challenge definitions
    - UserChallenge: User progress on challenges
    - Solve: Successful challenge completions
    - HintUsed: Hint usage tracking
    - Achievement: User achievements and badges
    - LeaderboardEntry: Aggregated leaderboard data

Author: AegisForge CTF Platform
"""

from datetime import datetime
from typing import Dict, List, Optional
from sqlalchemy import (
    Column, String, Integer, Text, Boolean, DateTime, 
    ForeignKey, CheckConstraint, UniqueConstraint, Index
)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, Session
from sqlalchemy.sql import func

Base = declarative_base()


class Challenge(Base):
    """
    Represents a CTF challenge with all its metadata.
    
    Attributes:
        id: Unique challenge identifier
        name: Challenge display name
        category: Challenge category (ai-detection, web, crypto, etc.)
        difficulty: Difficulty level (easy, medium, hard, expert)
        points: Base points awarded for solving
        description: Full challenge description
        flag_template: Template for generating user-specific flags
        hints: JSON string containing array of hints
        files: JSON string containing array of file URLs
        author: Challenge author name
        tags: JSON string containing searchable tags
        created_at: Creation timestamp
        updated_at: Last update timestamp
    """
    __tablename__ = 'challenges'
    
    id = Column(String(50), primary_key=True)
    name = Column(String(200), nullable=False)
    category = Column(String(50), nullable=False)
    difficulty = Column(String(20), nullable=False)
    points = Column(Integer, nullable=False)
    description = Column(Text, nullable=False)
    flag_template = Column(String(500), nullable=False)
    hints = Column(Text)  # JSON array
    files = Column(Text)  # JSON array
    author = Column(String(100), default='AegisForge Team')
    tags = Column(Text)  # JSON array
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user_challenges = relationship('UserChallenge', back_populates='challenge', cascade='all, delete-orphan')
    solves = relationship('Solve', back_populates='challenge', cascade='all, delete-orphan')
    hints_used = relationship('HintUsed', back_populates='challenge', cascade='all, delete-orphan')
    
    # Constraints
    __table_args__ = (
        CheckConstraint(
            "difficulty IN ('easy', 'medium', 'hard', 'expert')", 
            name='check_difficulty'
        ),
        CheckConstraint('points > 0', name='check_points_positive'),
        Index('idx_challenges_category', 'category'),
        Index('idx_challenges_difficulty', 'difficulty'),
        Index('idx_challenges_points', 'points'),
    )
    
    def to_dict(self) -> Dict:
        """
        Convert challenge to dictionary representation.
        
        Returns:
            Dictionary with all challenge fields
        """
        import json
        return {
            'id': self.id,
            'name': self.name,
            'category': self.category,
            'difficulty': self.difficulty,
            'points': self.points,
            'description': self.description,
            'flag_template': self.flag_template,
            'hints': json.loads(self.hints) if self.hints else [],
            'files': json.loads(self.files) if self.files else [],
            'author': self.author,
            'tags': json.loads(self.tags) if self.tags else [],
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def __repr__(self) -> str:
        return f"<Challenge(id='{self.id}', name='{self.name}', difficulty='{self.difficulty}', points={self.points})>"


class UserChallenge(Base):
    """
    Tracks a user's progress on a specific challenge.
    
    Attributes:
        id: Primary key
        user_id: User identifier
        challenge_id: Foreign key to challenges
        flag: User-specific generated flag
        state: Current state (not_started, in_progress, solved)
        started_at: When user started the challenge
        solved_at: When user solved the challenge
        attempts: Number of flag submission attempts
        hints_used: Number of hints unlocked
        points_earned: Points earned from solving
        points_spent: Points spent on hints
        created_at: Record creation timestamp
        updated_at: Last update timestamp
    """
    __tablename__ = 'user_challenges'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(100), nullable=False)
    challenge_id = Column(String(50), ForeignKey('challenges.id', ondelete='CASCADE'), nullable=False)
    flag = Column(String(500))
    state = Column(String(20), nullable=False, default='not_started')
    started_at = Column(DateTime)
    solved_at = Column(DateTime)
    attempts = Column(Integer, default=0)
    hints_used = Column(Integer, default=0)
    points_earned = Column(Integer, default=0)
    points_spent = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    challenge = relationship('Challenge', back_populates='user_challenges')
    
    # Constraints
    __table_args__ = (
        UniqueConstraint('user_id', 'challenge_id', name='uq_user_challenge'),
        CheckConstraint(
            "state IN ('not_started', 'in_progress', 'solved')", 
            name='check_state'
        ),
        CheckConstraint('attempts >= 0', name='check_attempts_positive'),
        CheckConstraint('hints_used >= 0', name='check_hints_positive'),
        CheckConstraint('points_earned >= 0', name='check_points_earned_positive'),
        CheckConstraint('points_spent >= 0', name='check_points_spent_positive'),
        Index('idx_user_challenges_user', 'user_id'),
        Index('idx_user_challenges_challenge', 'challenge_id'),
        Index('idx_user_challenges_state', 'state'),
        Index('idx_user_challenges_solved', 'user_id', 'solved_at'),
    )
    
    def to_dict(self) -> Dict:
        """
        Convert user challenge progress to dictionary.
        
        Returns:
            Dictionary with all progress fields
        """
        return {
            'id': self.id,
            'user_id': self.user_id,
            'challenge_id': self.challenge_id,
            'flag': self.flag,
            'state': self.state,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'solved_at': self.solved_at.isoformat() if self.solved_at else None,
            'attempts': self.attempts,
            'hints_used': self.hints_used,
            'points_earned': self.points_earned,
            'points_spent': self.points_spent,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def time_taken(self) -> Optional[int]:
        """
        Calculate time taken to solve in seconds.
        
        Returns:
            Seconds between start and solve, or None if not solved
        """
        if self.started_at and self.solved_at:
            return int((self.solved_at - self.started_at).total_seconds())
        return None
    
    def __repr__(self) -> str:
        return f"<UserChallenge(user_id='{self.user_id}', challenge_id='{self.challenge_id}', state='{self.state}')>"


class Solve(Base):
    """
    Records a successful challenge solve with timing information.
    
    Attributes:
        id: Primary key
        user_id: User who solved the challenge
        challenge_id: Foreign key to challenges
        solve_time: When the challenge was solved
        time_taken: Seconds from start to solve
        points: Points awarded for the solve
        first_blood: True if this was the first solve
    """
    __tablename__ = 'solves'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(100), nullable=False)
    challenge_id = Column(String(50), ForeignKey('challenges.id', ondelete='CASCADE'), nullable=False)
    solve_time = Column(DateTime, nullable=False, default=datetime.utcnow)
    time_taken = Column(Integer)  # Seconds
    points = Column(Integer, nullable=False)
    first_blood = Column(Boolean, default=False)
    
    # Relationships
    challenge = relationship('Challenge', back_populates='solves')
    
    # Constraints
    __table_args__ = (
        UniqueConstraint('user_id', 'challenge_id', name='uq_user_solve'),
        CheckConstraint('points >= 0', name='check_points_positive'),
        Index('idx_solves_user', 'user_id'),
        Index('idx_solves_challenge', 'challenge_id'),
        Index('idx_solves_time', 'solve_time'),
        Index('idx_solves_first_blood', 'challenge_id', 'solve_time'),
    )
    
    def to_dict(self) -> Dict:
        """
        Convert solve to dictionary representation.
        
        Returns:
            Dictionary with all solve fields
        """
        return {
            'id': self.id,
            'user_id': self.user_id,
            'challenge_id': self.challenge_id,
            'solve_time': self.solve_time.isoformat() if self.solve_time else None,
            'time_taken': self.time_taken,
            'points': self.points,
            'first_blood': self.first_blood
        }
    
    def __repr__(self) -> str:
        fb = " [FIRST BLOOD]" if self.first_blood else ""
        return f"<Solve(user_id='{self.user_id}', challenge_id='{self.challenge_id}', points={self.points}{fb})>"


class HintUsed(Base):
    """
    Tracks hint usage by users for penalty calculation.
    
    Attributes:
        id: Primary key
        user_id: User who unlocked the hint
        challenge_id: Foreign key to challenges
        hint_level: Which hint (1, 2, 3, etc.)
        points_spent: Cost of the hint
        used_at: When the hint was unlocked
    """
    __tablename__ = 'hints_used'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(100), nullable=False)
    challenge_id = Column(String(50), ForeignKey('challenges.id', ondelete='CASCADE'), nullable=False)
    hint_level = Column(Integer, nullable=False)
    points_spent = Column(Integer, nullable=False)
    used_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    
    # Relationships
    challenge = relationship('Challenge', back_populates='hints_used')
    
    # Constraints
    __table_args__ = (
        UniqueConstraint('user_id', 'challenge_id', 'hint_level', name='uq_user_hint'),
        CheckConstraint('hint_level > 0', name='check_hint_level_positive'),
        CheckConstraint('points_spent >= 0', name='check_points_spent_positive'),
        Index('idx_hints_user', 'user_id'),
        Index('idx_hints_challenge', 'challenge_id'),
        Index('idx_hints_time', 'used_at'),
    )
    
    def to_dict(self) -> Dict:
        """
        Convert hint usage to dictionary representation.
        
        Returns:
            Dictionary with all hint usage fields
        """
        return {
            'id': self.id,
            'user_id': self.user_id,
            'challenge_id': self.challenge_id,
            'hint_level': self.hint_level,
            'points_spent': self.points_spent,
            'used_at': self.used_at.isoformat() if self.used_at else None
        }
    
    def __repr__(self) -> str:
        return f"<HintUsed(user_id='{self.user_id}', challenge_id='{self.challenge_id}', hint_level={self.hint_level})>"


class Achievement(Base):
    """
    Records user achievements and badges earned during CTF.
    
    Attributes:
        id: Primary key
        user_id: User who earned the achievement
        achievement_key: Unique identifier for achievement type
        earned_at: When the achievement was earned
        points_awarded: Bonus points for achievement
        achievement_metadata: JSON string with additional context
    """
    __tablename__ = 'achievements'
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(String(100), nullable=False)
    achievement_key = Column(String(100), nullable=False)
    earned_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    points_awarded = Column(Integer, default=0)
    achievement_metadata = Column('metadata', Text)  # JSON, mapped to 'metadata' in DB
    
    # Constraints
    __table_args__ = (
        UniqueConstraint('user_id', 'achievement_key', name='uq_user_achievement'),
        CheckConstraint('points_awarded >= 0', name='check_points_awarded_positive'),
        Index('idx_achievements_user', 'user_id'),
        Index('idx_achievements_key', 'achievement_key'),
        Index('idx_achievements_time', 'earned_at'),
    )
    
    def to_dict(self) -> Dict:
        """
        Convert achievement to dictionary representation.
        
        Returns:
            Dictionary with all achievement fields
        """
        import json
        return {
            'id': self.id,
            'user_id': self.user_id,
            'achievement_key': self.achievement_key,
            'earned_at': self.earned_at.isoformat() if self.earned_at else None,
            'points_awarded': self.points_awarded,
            'metadata': json.loads(self.achievement_metadata) if self.achievement_metadata else {}
        }
    
    def __repr__(self) -> str:
        return f"<Achievement(user_id='{self.user_id}', key='{self.achievement_key}', points={self.points_awarded})>"


class LeaderboardEntry(Base):
    """
    Materialized leaderboard data for performance.
    
    This table contains aggregated statistics for each user to enable
    fast leaderboard queries without expensive joins.
    
    Attributes:
        user_id: Primary key, user identifier
        username: Display name for leaderboard
        total_points: Sum of all points earned
        challenges_solved: Count of solved challenges
        hints_used: Total hints unlocked
        achievements_earned: Total achievements earned
        last_solve_time: Timestamp of most recent solve
        rank: Current leaderboard rank
        updated_at: Last update timestamp
    """
    __tablename__ = 'leaderboard'
    
    user_id = Column(String(100), primary_key=True)
    username = Column(String(100), nullable=False)
    total_points = Column(Integer, default=0)
    challenges_solved = Column(Integer, default=0)
    hints_used = Column(Integer, default=0)
    achievements_earned = Column(Integer, default=0)
    last_solve_time = Column(DateTime)
    rank = Column(Integer)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Constraints
    __table_args__ = (
        CheckConstraint('total_points >= 0', name='check_total_points_positive'),
        CheckConstraint('challenges_solved >= 0', name='check_challenges_solved_positive'),
        CheckConstraint('hints_used >= 0', name='check_hints_used_positive'),
        CheckConstraint('achievements_earned >= 0', name='check_achievements_earned_positive'),
        Index('idx_leaderboard_points', 'total_points'),
        Index('idx_leaderboard_rank', 'rank'),
        Index('idx_leaderboard_last_solve', 'last_solve_time'),
    )
    
    def to_dict(self) -> Dict:
        """
        Convert leaderboard entry to dictionary representation.
        
        Returns:
            Dictionary with all leaderboard fields
        """
        return {
            'user_id': self.user_id,
            'username': self.username,
            'total_points': self.total_points,
            'challenges_solved': self.challenges_solved,
            'hints_used': self.hints_used,
            'achievements_earned': self.achievements_earned,
            'last_solve_time': self.last_solve_time.isoformat() if self.last_solve_time else None,
            'rank': self.rank,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }
    
    def __repr__(self) -> str:
        return f"<LeaderboardEntry(user_id='{self.user_id}', rank={self.rank}, points={self.total_points})>"


# ============================================================================
# Helper Functions
# ============================================================================

def init_db(engine):
    """
    Initialize the database schema.
    
    Args:
        engine: SQLAlchemy engine instance
    """
    Base.metadata.create_all(engine)


def drop_all_tables(engine):
    """
    Drop all tables from the database.
    
    WARNING: This will delete all data!
    
    Args:
        engine: SQLAlchemy engine instance
    """
    Base.metadata.drop_all(engine)


def get_or_create(session: Session, model, defaults=None, **kwargs):
    """
    Get an existing record or create a new one.
    
    Args:
        session: SQLAlchemy session
        model: Model class
        defaults: Dictionary of default values for creation
        **kwargs: Filter criteria
    
    Returns:
        Tuple of (instance, created) where created is True if new record
    """
    instance = session.query(model).filter_by(**kwargs).first()
    if instance:
        return instance, False
    else:
        params = {**kwargs, **(defaults or {})}
        instance = model(**params)
        session.add(instance)
        return instance, True
