"""
Achievement and Badge System for CTF Platform

This module provides a comprehensive achievement tracking system:
- Predefined achievements for various accomplishments
- Automatic achievement detection and awarding
- Badge collection and display
- Progress tracking for incremental achievements
- User achievement history

Author: AegisForge CTF Platform
"""

from typing import Dict, List, Optional, Set, Callable, Tuple
from datetime import datetime
from dataclasses import dataclass, field
from enum import Enum


class AchievementCategory(Enum):
    """Categories for organizing achievements."""
    SPEED = "speed"
    SKILL = "skill"
    COMPLETION = "completion"
    SPECIAL = "special"
    MILESTONE = "milestone"


@dataclass
class Achievement:
    """
    Represents a single achievement/badge.
    
    Attributes:
        id (str): Unique identifier for the achievement
        name (str): Display name
        description (str): What the user needs to do to earn it
        category (AchievementCategory): Achievement category
        icon (str): Icon/emoji representation
        points (int): Bonus points awarded when earned
        hidden (bool): Whether achievement is hidden until earned
    """
    id: str
    name: str
    description: str
    category: AchievementCategory
    icon: str
    points: int = 0
    hidden: bool = False


@dataclass
class UserAchievement:
    """
    Represents an earned achievement for a user.
    
    Attributes:
        achievement_id (str): ID of the earned achievement
        user_id (str): ID of the user who earned it
        timestamp (datetime): When it was earned
        progress (Dict): Progress data for incremental achievements
    """
    achievement_id: str
    user_id: str
    timestamp: datetime
    progress: Dict = field(default_factory=dict)


# Predefined achievements for the CTF platform
ACHIEVEMENTS = {
    # Speed-based achievements
    "first_blood": Achievement(
        id="first_blood",
        name="First Blood",
        description="Be the first to solve any challenge",
        category=AchievementCategory.SPEED,
        icon="🩸",
        points=50
    ),
    "speed_demon": Achievement(
        id="speed_demon",
        name="Speed Demon",
        description="Solve a hard challenge in under 30 minutes",
        category=AchievementCategory.SPEED,
        icon="⚡",
        points=75
    ),
    "lightning_fast": Achievement(
        id="lightning_fast",
        name="Lightning Fast",
        description="Solve 3 challenges in under 1 hour",
        category=AchievementCategory.SPEED,
        icon="⚡⚡",
        points=100
    ),
    
    # Skill-based achievements
    "no_hints": Achievement(
        id="no_hints",
        name="Independent Solver",
        description="Solve a hard challenge without using any hints",
        category=AchievementCategory.SKILL,
        icon="🧠",
        points=50
    ),
    "perfect_score": Achievement(
        id="perfect_score",
        name="Perfect Score",
        description="Solve 5 challenges without using any hints",
        category=AchievementCategory.SKILL,
        icon="💯",
        points=100
    ),
    "cryptographer": Achievement(
        id="cryptographer",
        name="Cryptographer",
        description="Solve all cryptography challenges",
        category=AchievementCategory.SKILL,
        icon="🔐",
        points=150
    ),
    "web_warrior": Achievement(
        id="web_warrior",
        name="Web Warrior",
        description="Solve all web security challenges",
        category=AchievementCategory.SKILL,
        icon="🌐",
        points=150
    ),
    "binary_ninja": Achievement(
        id="binary_ninja",
        name="Binary Ninja",
        description="Solve all binary exploitation challenges",
        category=AchievementCategory.SKILL,
        icon="💻",
        points=150
    ),
    
    # Completion achievements
    "getting_started": Achievement(
        id="getting_started",
        name="Getting Started",
        description="Solve your first challenge",
        category=AchievementCategory.COMPLETION,
        icon="🎯",
        points=10
    ),
    "problem_solver": Achievement(
        id="problem_solver",
        name="Problem Solver",
        description="Solve 10 challenges",
        category=AchievementCategory.COMPLETION,
        icon="🎓",
        points=50
    ),
    "veteran": Achievement(
        id="veteran",
        name="Veteran",
        description="Solve 25 challenges",
        category=AchievementCategory.COMPLETION,
        icon="🏆",
        points=100
    ),
    "completionist": Achievement(
        id="completionist",
        name="Completionist",
        description="Solve all available challenges",
        category=AchievementCategory.COMPLETION,
        icon="👑",
        points=500
    ),
    
    # Special achievements
    "night_owl": Achievement(
        id="night_owl",
        name="Night Owl",
        description="Solve a challenge between 2 AM and 5 AM",
        category=AchievementCategory.SPECIAL,
        icon="🦉",
        points=25
    ),
    "weekend_warrior": Achievement(
        id="weekend_warrior",
        name="Weekend Warrior",
        description="Solve 5 challenges in a weekend",
        category=AchievementCategory.SPECIAL,
        icon="⚔️",
        points=50
    ),
    "comeback_kid": Achievement(
        id="comeback_kid",
        name="Comeback Kid",
        description="Return and solve a challenge after 7 days of inactivity",
        category=AchievementCategory.SPECIAL,
        icon="🔄",
        points=30
    ),
    
    # Milestone achievements
    "top_10": Achievement(
        id="top_10",
        name="Top 10",
        description="Reach top 10 on the leaderboard",
        category=AchievementCategory.MILESTONE,
        icon="🥉",
        points=100
    ),
    "top_5": Achievement(
        id="top_5",
        name="Top 5",
        description="Reach top 5 on the leaderboard",
        category=AchievementCategory.MILESTONE,
        icon="🥈",
        points=200
    ),
    "number_one": Achievement(
        id="number_one",
        name="Number One",
        description="Reach #1 on the leaderboard",
        category=AchievementCategory.MILESTONE,
        icon="🥇",
        points=500
    )
}


class AchievementSystem:
    """
    Manages achievement tracking and awarding for CTF users.
    
    This class handles:
    - Tracking user achievements
    - Checking if users have earned new achievements
    - Managing achievement progress
    - Providing achievement statistics
    
    Attributes:
        achievements (Dict[str, Achievement]): Available achievements
        user_achievements (Dict[str, List[UserAchievement]]): User achievement records
        achievement_progress (Dict[str, Dict]): Tracks progress toward achievements
    """
    
    def __init__(self, custom_achievements: Optional[Dict[str, Achievement]] = None):
        """
        Initialize the achievement system.
        
        Args:
            custom_achievements (Dict, optional): Additional custom achievements
        """
        self.achievements = ACHIEVEMENTS.copy()
        if custom_achievements:
            self.achievements.update(custom_achievements)
        
        # Track which achievements each user has earned
        self.user_achievements: Dict[str, List[UserAchievement]] = {}
        
        # Track progress toward achievements (for incremental ones)
        self.achievement_progress: Dict[str, Dict] = {}
    
    def has_achievement(self, user_id: str, achievement_id: str) -> bool:
        """
        Check if a user has earned a specific achievement.
        
        Args:
            user_id (str): Unique identifier for the user
            achievement_id (str): Unique identifier for the achievement
            
        Returns:
            bool: True if user has earned the achievement
        """
        if user_id not in self.user_achievements:
            return False
        
        return any(ua.achievement_id == achievement_id 
                  for ua in self.user_achievements[user_id])
    
    def award_achievement(
        self,
        user_id: str,
        achievement_id: str,
        timestamp: Optional[datetime] = None,
        progress: Optional[Dict] = None
    ) -> Tuple[bool, str, int]:
        """
        Award an achievement to a user.
        
        Args:
            user_id (str): Unique identifier for the user
            achievement_id (str): Unique identifier for the achievement
            timestamp (datetime, optional): When earned (defaults to now)
            progress (Dict, optional): Progress data for the achievement
            
        Returns:
            Tuple[bool, str, int]:
                - Success status
                - Status message
                - Bonus points awarded
        """
        # Check if achievement exists
        if achievement_id not in self.achievements:
            return False, "Achievement not found", 0
        
        # Check if user already has this achievement
        if self.has_achievement(user_id, achievement_id):
            return False, "Achievement already earned", 0
        
        achievement = self.achievements[achievement_id]
        
        # Create user achievement record
        if user_id not in self.user_achievements:
            self.user_achievements[user_id] = []
        
        user_achievement = UserAchievement(
            achievement_id=achievement_id,
            user_id=user_id,
            timestamp=timestamp or datetime.now(),
            progress=progress or {}
        )
        
        self.user_achievements[user_id].append(user_achievement)
        
        message = f"Achievement unlocked: {achievement.name} {achievement.icon}"
        if achievement.points > 0:
            message += f" (+{achievement.points} points)"
        
        return True, message, achievement.points
    
    def check_achievement(
        self,
        user_id: str,
        achievement_id: str,
        context: Dict
    ) -> Tuple[bool, str]:
        """
        Check if a user has met the conditions for an achievement.
        
        This is the main method for evaluating achievement criteria.
        The context dict should contain relevant data for checking.
        
        Args:
            user_id (str): Unique identifier for the user
            achievement_id (str): Achievement to check
            context (Dict): Context data for evaluation (solves, time, etc.)
            
        Returns:
            Tuple[bool, str]:
                - Whether achievement was earned
                - Status message
        """
        # Don't check if already earned
        if self.has_achievement(user_id, achievement_id):
            return False, "Already earned"
        
        # Define achievement check functions
        checkers = {
            "first_blood": self._check_first_blood,
            "speed_demon": self._check_speed_demon,
            "lightning_fast": self._check_lightning_fast,
            "no_hints": self._check_no_hints,
            "perfect_score": self._check_perfect_score,
            "getting_started": self._check_getting_started,
            "problem_solver": self._check_problem_solver,
            "veteran": self._check_veteran,
            "completionist": self._check_completionist,
            "cryptographer": self._check_category_complete,
            "web_warrior": self._check_category_complete,
            "binary_ninja": self._check_category_complete,
            "night_owl": self._check_night_owl,
            "weekend_warrior": self._check_weekend_warrior,
            "top_10": self._check_leaderboard_position,
            "top_5": self._check_leaderboard_position,
            "number_one": self._check_leaderboard_position,
        }
        
        checker = checkers.get(achievement_id)
        if not checker:
            return False, "No checker defined for this achievement"
        
        earned = checker(user_id, achievement_id, context)
        
        if earned:
            success, message, points = self.award_achievement(user_id, achievement_id)
            return success, message
        
        return False, "Conditions not met"
    
    def get_user_achievements(self, user_id: str) -> List[Dict]:
        """
        Get all achievements earned by a user.
        
        Args:
            user_id (str): Unique identifier for the user
            
        Returns:
            List[Dict]: List of earned achievement details
        """
        if user_id not in self.user_achievements:
            return []
        
        result = []
        for ua in self.user_achievements[user_id]:
            achievement = self.achievements[ua.achievement_id]
            result.append({
                "id": achievement.id,
                "name": achievement.name,
                "description": achievement.description,
                "category": achievement.category.value,
                "icon": achievement.icon,
                "points": achievement.points,
                "earned_at": ua.timestamp.isoformat()
            })
        
        return result
    
    def get_available_achievements(
        self,
        user_id: Optional[str] = None,
        include_hidden: bool = False
    ) -> List[Dict]:
        """
        Get all available achievements, optionally filtered for a user.
        
        Args:
            user_id (str, optional): Show only unearned achievements for this user
            include_hidden (bool): Whether to include hidden achievements
            
        Returns:
            List[Dict]: List of achievement details
        """
        result = []
        
        for achievement in self.achievements.values():
            # Skip hidden achievements unless requested
            if achievement.hidden and not include_hidden:
                continue
            
            # Skip already earned achievements if user_id provided
            if user_id and self.has_achievement(user_id, achievement.id):
                continue
            
            result.append({
                "id": achievement.id,
                "name": achievement.name,
                "description": achievement.description,
                "category": achievement.category.value,
                "icon": achievement.icon,
                "points": achievement.points
            })
        
        return result
    
    def get_achievement_stats(self, user_id: str) -> Dict:
        """
        Get achievement statistics for a user.
        
        Args:
            user_id (str): Unique identifier for the user
            
        Returns:
            Dict: Statistics including total earned, by category, etc.
        """
        earned = self.get_user_achievements(user_id)
        
        # Count by category
        by_category = {}
        total_points = 0
        
        for achievement in earned:
            category = achievement["category"]
            by_category[category] = by_category.get(category, 0) + 1
            total_points += achievement["points"]
        
        return {
            "total_earned": len(earned),
            "total_available": len(self.achievements),
            "by_category": by_category,
            "bonus_points": total_points,
            "completion_percentage": (len(earned) / len(self.achievements) * 100) 
                                    if self.achievements else 0
        }
    
    # Achievement checker methods
    
    def _check_first_blood(self, user_id: str, achievement_id: str, context: Dict) -> bool:
        """Check if user got first blood on any challenge."""
        return context.get("is_first_blood", False)
    
    def _check_speed_demon(self, user_id: str, achievement_id: str, context: Dict) -> bool:
        """Check if user solved hard challenge in under 30 minutes."""
        difficulty = context.get("difficulty", "")
        time_taken_minutes = context.get("time_taken_minutes", float('inf'))
        return difficulty == "hard" and time_taken_minutes < 30
    
    def _check_lightning_fast(self, user_id: str, achievement_id: str, context: Dict) -> bool:
        """Check if user solved 3 challenges in under 1 hour."""
        recent_solves = context.get("recent_solves", [])
        return len(recent_solves) >= 3
    
    def _check_no_hints(self, user_id: str, achievement_id: str, context: Dict) -> bool:
        """Check if user solved hard challenge without hints."""
        difficulty = context.get("difficulty", "")
        hints_used = context.get("hints_used", 0)
        return difficulty == "hard" and hints_used == 0
    
    def _check_perfect_score(self, user_id: str, achievement_id: str, context: Dict) -> bool:
        """Check if user solved 5 challenges without hints."""
        no_hint_solves = context.get("no_hint_solves", 0)
        return no_hint_solves >= 5
    
    def _check_getting_started(self, user_id: str, achievement_id: str, context: Dict) -> bool:
        """Check if user solved their first challenge."""
        total_solves = context.get("total_solves", 0)
        return total_solves >= 1
    
    def _check_problem_solver(self, user_id: str, achievement_id: str, context: Dict) -> bool:
        """Check if user solved 10 challenges."""
        total_solves = context.get("total_solves", 0)
        return total_solves >= 10
    
    def _check_veteran(self, user_id: str, achievement_id: str, context: Dict) -> bool:
        """Check if user solved 25 challenges."""
        total_solves = context.get("total_solves", 0)
        return total_solves >= 25
    
    def _check_completionist(self, user_id: str, achievement_id: str, context: Dict) -> bool:
        """Check if user solved all challenges."""
        total_solves = context.get("total_solves", 0)
        total_challenges = context.get("total_challenges", 0)
        return total_challenges > 0 and total_solves >= total_challenges
    
    def _check_category_complete(self, user_id: str, achievement_id: str, context: Dict) -> bool:
        """Check if user solved all challenges in a category."""
        # Map achievement IDs to categories
        category_map = {
            "cryptographer": "crypto",
            "web_warrior": "web",
            "binary_ninja": "pwn"
        }
        
        category = category_map.get(achievement_id)
        if not category:
            return False
        
        category_solves = context.get(f"{category}_solves", 0)
        category_total = context.get(f"{category}_total", 0)
        return category_total > 0 and category_solves >= category_total
    
    def _check_night_owl(self, user_id: str, achievement_id: str, context: Dict) -> bool:
        """Check if challenge was solved during night hours."""
        solve_hour = context.get("solve_hour", 12)
        return 2 <= solve_hour < 5
    
    def _check_weekend_warrior(self, user_id: str, achievement_id: str, context: Dict) -> bool:
        """Check if user solved 5 challenges in a weekend."""
        weekend_solves = context.get("weekend_solves", 0)
        return weekend_solves >= 5
    
    def _check_leaderboard_position(self, user_id: str, achievement_id: str, context: Dict) -> bool:
        """Check leaderboard position achievement."""
        rank = context.get("user_rank", float('inf'))
        
        position_map = {
            "top_10": 10,
            "top_5": 5,
            "number_one": 1
        }
        
        required_rank = position_map.get(achievement_id, float('inf'))
        return rank <= required_rank


def main():
    """Example usage of the AchievementSystem class."""
    print("=== CTF Achievement System Demo ===\n")
    
    # Initialize achievement system
    achievement_system = AchievementSystem()
    
    user_id = "player_123"
    
    # Show available achievements
    print("Available Achievements:")
    print("-" * 70)
    for ach in achievement_system.get_available_achievements():
        print(f"{ach['icon']} {ach['name']:<25} - {ach['description']}")
        print(f"   Category: {ach['category']:<15} Points: {ach['points']}")
        print()
    
    # Simulate earning some achievements
    print("\n" + "=" * 70)
    print("Simulating Challenge Solves and Achievement Checks")
    print("=" * 70 + "\n")
    
    # First solve
    context = {"total_solves": 1}
    earned, message = achievement_system.check_achievement(user_id, "getting_started", context)
    if earned:
        print(f"✓ {message}")
    
    # First blood
    context = {"is_first_blood": True, "total_solves": 1}
    earned, message = achievement_system.check_achievement(user_id, "first_blood", context)
    if earned:
        print(f"✓ {message}")
    
    # Speed demon
    context = {"difficulty": "hard", "time_taken_minutes": 25}
    earned, message = achievement_system.check_achievement(user_id, "speed_demon", context)
    if earned:
        print(f"✓ {message}")
    
    # No hints on hard challenge
    context = {"difficulty": "hard", "hints_used": 0}
    earned, message = achievement_system.check_achievement(user_id, "no_hints", context)
    if earned:
        print(f"✓ {message}")
    
    # Night owl
    context = {"solve_hour": 3}
    earned, message = achievement_system.check_achievement(user_id, "night_owl", context)
    if earned:
        print(f"✓ {message}")
    
    # Display user's achievements
    print("\n" + "=" * 70)
    print("Player Achievements")
    print("=" * 70 + "\n")
    
    earned_achievements = achievement_system.get_user_achievements(user_id)
    for ach in earned_achievements:
        print(f"{ach['icon']} {ach['name']}")
        print(f"   {ach['description']}")
        print(f"   Earned: {ach['earned_at']}")
        print()
    
    # Show statistics
    stats = achievement_system.get_achievement_stats(user_id)
    print("=" * 70)
    print("Achievement Statistics")
    print("=" * 70)
    print(f"Total Earned: {stats['total_earned']}/{stats['total_available']}")
    print(f"Completion: {stats['completion_percentage']:.1f}%")
    print(f"Bonus Points: {stats['bonus_points']}")
    print(f"\nBy Category:")
    for category, count in stats['by_category'].items():
        print(f"  {category}: {count}")


if __name__ == "__main__":
    main()
