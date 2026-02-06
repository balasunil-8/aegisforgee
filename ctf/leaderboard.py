"""
Scoring and Leaderboard System for CTF Platform

This module provides comprehensive leaderboard and scoring functionality:
- Dynamic point calculation based on difficulty and solve time
- First blood bonuses for first solvers
- Leaderboard rankings and statistics
- Time-based scoring decay
- User performance tracking

Author: AegisForge CTF Platform
"""

from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
import json


@dataclass
class Solve:
    """
    Represents a challenge solve event.
    
    Attributes:
        user_id (str): Unique identifier for the user
        challenge_id (str): Unique identifier for the challenge
        timestamp (datetime): When the challenge was solved
        points_earned (int): Points awarded for this solve
        is_first_blood (bool): Whether this was the first solve
        time_taken (Optional[timedelta]): Time taken to solve (if tracked)
        hints_used (int): Number of hints used
    """
    user_id: str
    challenge_id: str
    timestamp: datetime
    points_earned: int
    is_first_blood: bool = False
    time_taken: Optional[timedelta] = None
    hints_used: int = 0


@dataclass
class UserStats:
    """
    Tracks statistics for a single user.
    
    Attributes:
        user_id (str): Unique identifier for the user
        username (str): Display name
        total_points (int): Total points earned
        solves (List[Solve]): List of solved challenges
        first_bloods (int): Number of first blood solves
        last_solve_time (Optional[datetime]): Timestamp of most recent solve
    """
    user_id: str
    username: str
    total_points: int = 0
    solves: List[Solve] = field(default_factory=list)
    first_bloods: int = 0
    last_solve_time: Optional[datetime] = None
    
    def add_solve(self, solve: Solve) -> None:
        """Add a solve and update statistics."""
        self.solves.append(solve)
        self.total_points += solve.points_earned
        if solve.is_first_blood:
            self.first_bloods += 1
        self.last_solve_time = solve.timestamp


class Leaderboard:
    """
    Manages CTF leaderboard, scoring, and rankings.
    
    This class handles all aspects of the CTF scoring system including:
    - Recording challenge solves
    - Calculating points with various modifiers
    - Maintaining real-time leaderboard rankings
    - Tracking first blood bonuses
    - Managing user statistics
    
    Attributes:
        users (Dict[str, UserStats]): Dictionary of user statistics
        challenge_solves (Dict[str, List[Solve]]): Tracks all solves per challenge
        challenge_base_points (Dict[str, int]): Base point values for challenges
    """
    
    def __init__(self):
        """Initialize the leaderboard system."""
        self.users: Dict[str, UserStats] = {}
        self.challenge_solves: Dict[str, List[Solve]] = {}
        self.challenge_base_points: Dict[str, int] = {}
        self.first_blood_bonus: int = 50  # Bonus points for first blood
    
    def register_user(self, user_id: str, username: str) -> bool:
        """
        Register a new user in the leaderboard system.
        
        Args:
            user_id (str): Unique identifier for the user
            username (str): Display name for the user
            
        Returns:
            bool: True if user was registered, False if already exists
        """
        if user_id in self.users:
            return False
        
        self.users[user_id] = UserStats(user_id=user_id, username=username)
        return True
    
    def set_challenge_points(self, challenge_id: str, base_points: int) -> None:
        """
        Set the base point value for a challenge.
        
        Args:
            challenge_id (str): Unique identifier for the challenge
            base_points (int): Base point value (before modifiers)
        """
        self.challenge_base_points[challenge_id] = base_points
        if challenge_id not in self.challenge_solves:
            self.challenge_solves[challenge_id] = []
    
    def calculate_points(
        self,
        challenge_id: str,
        difficulty: str = "medium",
        time_taken: Optional[timedelta] = None,
        hints_used: int = 0,
        hint_penalty: int = 10
    ) -> int:
        """
        Calculate points for solving a challenge with various modifiers.
        
        Point calculation considers:
        - Base challenge difficulty
        - Time-based bonus (faster solves get more points)
        - Hint penalty (each hint reduces points)
        - First blood bonus (applied separately in record_solve)
        
        Args:
            challenge_id (str): Unique identifier for the challenge
            difficulty (str): Challenge difficulty (easy/medium/hard/expert)
            time_taken (timedelta, optional): Time taken to solve
            hints_used (int): Number of hints used
            hint_penalty (int): Points deducted per hint
            
        Returns:
            int: Calculated point value
        """
        # Get base points from challenge definition or use difficulty-based defaults
        if challenge_id in self.challenge_base_points:
            base_points = self.challenge_base_points[challenge_id]
        else:
            # Default points based on difficulty
            difficulty_points = {
                "easy": 100,
                "medium": 200,
                "hard": 300,
                "expert": 500
            }
            base_points = difficulty_points.get(difficulty.lower(), 200)
        
        points = base_points
        
        # Apply time bonus (faster solves get bonus points)
        if time_taken:
            # Bonus points for solving quickly (up to 20% bonus)
            # Decreases linearly over 24 hours
            hours_taken = time_taken.total_seconds() / 3600
            if hours_taken < 1:
                time_bonus = int(base_points * 0.20)
            elif hours_taken < 24:
                # Linear decay from 20% to 0% over 24 hours
                time_bonus = int(base_points * 0.20 * (1 - hours_taken / 24))
            else:
                time_bonus = 0
            
            points += time_bonus
        
        # Apply hint penalty
        hint_deduction = hints_used * hint_penalty
        points = max(points - hint_deduction, base_points // 2)  # Minimum 50% of base points
        
        return points
    
    def record_solve(
        self,
        user_id: str,
        challenge_id: str,
        timestamp: Optional[datetime] = None,
        time_taken: Optional[timedelta] = None,
        hints_used: int = 0,
        difficulty: str = "medium"
    ) -> Tuple[bool, str, int]:
        """
        Record a challenge solve and update the leaderboard.
        
        This method:
        - Checks if user has already solved the challenge
        - Calculates points with all modifiers
        - Awards first blood bonus if applicable
        - Updates user statistics
        - Records the solve in challenge history
        
        Args:
            user_id (str): Unique identifier for the user
            challenge_id (str): Unique identifier for the challenge
            timestamp (datetime, optional): When solved (defaults to now)
            time_taken (timedelta, optional): Time taken to solve
            hints_used (int): Number of hints used
            difficulty (str): Challenge difficulty level
            
        Returns:
            Tuple[bool, str, int]:
                - Success status
                - Status message
                - Points awarded
        """
        # Ensure user is registered
        if user_id not in self.users:
            return False, "User not registered", 0
        
        # Check if user already solved this challenge
        user_stats = self.users[user_id]
        if any(solve.challenge_id == challenge_id for solve in user_stats.solves):
            return False, "Challenge already solved by this user", 0
        
        # Use current time if not specified
        if timestamp is None:
            timestamp = datetime.now()
        
        # Check if this is the first solve (first blood)
        is_first_blood = challenge_id not in self.challenge_solves or \
                         len(self.challenge_solves[challenge_id]) == 0
        
        # Calculate points
        points = self.calculate_points(
            challenge_id,
            difficulty=difficulty,
            time_taken=time_taken,
            hints_used=hints_used
        )
        
        # Add first blood bonus
        if is_first_blood:
            points += self.first_blood_bonus
        
        # Create solve record
        solve = Solve(
            user_id=user_id,
            challenge_id=challenge_id,
            timestamp=timestamp,
            points_earned=points,
            is_first_blood=is_first_blood,
            time_taken=time_taken,
            hints_used=hints_used
        )
        
        # Update user statistics
        user_stats.add_solve(solve)
        
        # Record solve in challenge history
        if challenge_id not in self.challenge_solves:
            self.challenge_solves[challenge_id] = []
        self.challenge_solves[challenge_id].append(solve)
        
        # Build status message
        message = f"Challenge solved! +{points} points"
        if is_first_blood:
            message += f" (First Blood! +{self.first_blood_bonus} bonus)"
        
        return True, message, points
    
    def get_leaderboard(self, limit: int = 10) -> List[Dict]:
        """
        Get the current leaderboard rankings.
        
        Users are ranked by:
        1. Total points (descending)
        2. Number of solves (descending)
        3. Last solve time (ascending - earlier is better)
        
        Args:
            limit (int): Maximum number of users to return
            
        Returns:
            List[Dict]: List of user rankings with statistics
        """
        # Sort users by total points (desc), then by number of solves (desc),
        # then by last solve time (asc - earlier is better for tiebreaking)
        sorted_users = sorted(
            self.users.values(),
            key=lambda u: (
                -u.total_points,
                -len(u.solves),
                u.last_solve_time or datetime.max
            )
        )
        
        # Build leaderboard entries
        leaderboard = []
        for rank, user in enumerate(sorted_users[:limit], 1):
            leaderboard.append({
                "rank": rank,
                "user_id": user.user_id,
                "username": user.username,
                "points": user.total_points,
                "solves": len(user.solves),
                "first_bloods": user.first_bloods,
                "last_solve": user.last_solve_time.isoformat() if user.last_solve_time else None
            })
        
        return leaderboard
    
    def get_user_rank(self, user_id: str) -> Optional[Dict]:
        """
        Get the rank and statistics for a specific user.
        
        Args:
            user_id (str): Unique identifier for the user
            
        Returns:
            Optional[Dict]: User's rank and stats, or None if not found
        """
        if user_id not in self.users:
            return None
        
        # Get full leaderboard to find user's rank
        full_leaderboard = self.get_leaderboard(limit=len(self.users))
        
        for entry in full_leaderboard:
            if entry["user_id"] == user_id:
                return entry
        
        return None
    
    def get_challenge_stats(self, challenge_id: str) -> Dict:
        """
        Get statistics for a specific challenge.
        
        Args:
            challenge_id (str): Unique identifier for the challenge
            
        Returns:
            Dict: Challenge statistics including solve count and first blood
        """
        if challenge_id not in self.challenge_solves:
            return {
                "challenge_id": challenge_id,
                "total_solves": 0,
                "first_blood": None,
                "average_points": 0
            }
        
        solves = self.challenge_solves[challenge_id]
        first_blood = next((s for s in solves if s.is_first_blood), None)
        
        return {
            "challenge_id": challenge_id,
            "total_solves": len(solves),
            "first_blood": {
                "user_id": first_blood.user_id,
                "timestamp": first_blood.timestamp.isoformat()
            } if first_blood else None,
            "average_points": sum(s.points_earned for s in solves) // len(solves) if solves else 0
        }
    
    def get_user_solves(self, user_id: str) -> List[Dict]:
        """
        Get all solves for a specific user.
        
        Args:
            user_id (str): Unique identifier for the user
            
        Returns:
            List[Dict]: List of solve records
        """
        if user_id not in self.users:
            return []
        
        user = self.users[user_id]
        return [
            {
                "challenge_id": solve.challenge_id,
                "timestamp": solve.timestamp.isoformat(),
                "points": solve.points_earned,
                "is_first_blood": solve.is_first_blood,
                "hints_used": solve.hints_used
            }
            for solve in user.solves
        ]


def main():
    """Example usage of the Leaderboard class."""
    print("=== CTF Leaderboard System Demo ===\n")
    
    # Initialize leaderboard
    leaderboard = Leaderboard()
    
    # Register users
    users = [
        ("user_1", "Alice"),
        ("user_2", "Bob"),
        ("user_3", "Charlie"),
        ("user_4", "Diana")
    ]
    
    for user_id, username in users:
        leaderboard.register_user(user_id, username)
    
    print(f"Registered {len(users)} users\n")
    
    # Set up challenges
    challenges = {
        "web_1": ("easy", 100),
        "crypto_1": ("medium", 200),
        "pwn_1": ("hard", 300)
    }
    
    for challenge_id, (difficulty, points) in challenges.items():
        leaderboard.set_challenge_points(challenge_id, points)
    
    # Simulate some solves
    print("Recording challenge solves:\n")
    
    # Alice solves web_1 (first blood, fast, no hints)
    success, msg, points = leaderboard.record_solve(
        "user_1", "web_1",
        time_taken=timedelta(minutes=15),
        hints_used=0,
        difficulty="easy"
    )
    print(f"Alice: {msg} ({points} points)")
    
    # Bob solves web_1 (with hints)
    success, msg, points = leaderboard.record_solve(
        "user_2", "web_1",
        time_taken=timedelta(hours=2),
        hints_used=2,
        difficulty="easy"
    )
    print(f"Bob: {msg} ({points} points)")
    
    # Alice solves crypto_1 (first blood)
    success, msg, points = leaderboard.record_solve(
        "user_1", "crypto_1",
        time_taken=timedelta(hours=1),
        hints_used=1,
        difficulty="medium"
    )
    print(f"Alice: {msg} ({points} points)")
    
    # Charlie solves web_1
    success, msg, points = leaderboard.record_solve(
        "user_3", "web_1",
        time_taken=timedelta(hours=3),
        hints_used=1,
        difficulty="easy"
    )
    print(f"Charlie: {msg} ({points} points)")
    
    # Diana solves pwn_1 (first blood, expert)
    success, msg, points = leaderboard.record_solve(
        "user_4", "pwn_1",
        time_taken=timedelta(minutes=45),
        hints_used=0,
        difficulty="hard"
    )
    print(f"Diana: {msg} ({points} points)\n")
    
    # Display leaderboard
    print("=" * 70)
    print("LEADERBOARD")
    print("=" * 70)
    print(f"{'Rank':<6} {'Username':<15} {'Points':<10} {'Solves':<10} {'First Bloods':<15}")
    print("-" * 70)
    
    for entry in leaderboard.get_leaderboard():
        print(f"{entry['rank']:<6} {entry['username']:<15} {entry['points']:<10} "
              f"{entry['solves']:<10} {entry['first_bloods']:<15}")
    
    print("=" * 70)
    
    # Show user details
    print("\nAlice's Detailed Stats:")
    user_rank = leaderboard.get_user_rank("user_1")
    if user_rank:
        print(f"  Rank: {user_rank['rank']}")
        print(f"  Total Points: {user_rank['points']}")
        print(f"  Solves: {user_rank['solves']}")
        print(f"  First Bloods: {user_rank['first_bloods']}")
    
    # Show challenge stats
    print("\nChallenge: web_1 Statistics:")
    stats = leaderboard.get_challenge_stats("web_1")
    print(f"  Total Solves: {stats['total_solves']}")
    if stats['first_blood']:
        print(f"  First Blood: User {stats['first_blood']['user_id']}")
    print(f"  Average Points: {stats['average_points']}")


if __name__ == "__main__":
    main()
