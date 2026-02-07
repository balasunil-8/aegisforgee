"""
AegisForge CTF - Comprehensive Challenge Management System

This module coordinates all CTF operations including challenge lifecycle,
flag submission, progress tracking, and integration with supporting systems.

Key Features:
- Challenge state management (not_started, in_progress, solved)
- User progress tracking with timestamps
- Flag generation and validation
- Hint system integration
- Leaderboard and achievement tracking
- Multi-user support with isolated state

Author: AegisForge CTF Platform
"""

import json
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timedelta
from enum import Enum
from dataclasses import dataclass, field, asdict

from .flag_generator import FlagGenerator
from .hint_system import HintSystem
from .leaderboard import Leaderboard, Solve, UserStats
from .achievements import AchievementSystem, AchievementCategory


class ChallengeState(Enum):
    """States a challenge can be in for a user."""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    SOLVED = "solved"


@dataclass
class ChallengeProgress:
    """
    Tracks a user's progress on a specific challenge.
    
    Attributes:
        challenge_id (str): Unique identifier for the challenge
        user_id (str): Unique identifier for the user
        state (ChallengeState): Current state of the challenge
        started_at (Optional[datetime]): When the user started the challenge
        solved_at (Optional[datetime]): When the user solved the challenge
        attempts (int): Number of flag submission attempts
        hints_unlocked (int): Number of hints unlocked by the user
        points_spent (int): Points spent on hints
    """
    challenge_id: str
    user_id: str
    state: ChallengeState = ChallengeState.NOT_STARTED
    started_at: Optional[datetime] = None
    solved_at: Optional[datetime] = None
    attempts: int = 0
    hints_unlocked: int = 0
    points_spent: int = 0
    
    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        data = asdict(self)
        data['state'] = self.state.value
        if self.started_at:
            data['started_at'] = self.started_at.isoformat()
        if self.solved_at:
            data['solved_at'] = self.solved_at.isoformat()
        return data


@dataclass
class Challenge:
    """
    Represents a CTF challenge.
    
    Attributes:
        id (str): Unique identifier
        title (str): Challenge title
        description (str): Challenge description
        category (str): Challenge category (e.g., 'web', 'crypto', 'forensics')
        difficulty (str): Difficulty level (e.g., 'easy', 'medium', 'hard')
        points (int): Base points awarded for solving
        flag_template (str): Template for flag generation
        hints (List[str]): Available hints
        files (List[str]): Associated files/URLs
        author (str): Challenge author
        tags (List[str]): Searchable tags
    """
    id: str
    title: str
    description: str
    category: str
    difficulty: str
    points: int
    flag_template: str
    hints: List[str] = field(default_factory=list)
    files: List[str] = field(default_factory=list)
    author: str = "AegisForge Team"
    tags: List[str] = field(default_factory=list)


class CTFManager:
    """
    Main CTF management system that coordinates all CTF operations.
    
    This class serves as the central coordinator for the CTF platform, managing:
    - Challenge lifecycle and state transitions
    - User progress tracking across all challenges
    - Flag generation and validation
    - Hint system integration
    - Leaderboard and scoring
    - Achievement tracking
    
    The manager maintains separate state for each user and provides a clean
    interface for all CTF operations.
    
    Attributes:
        challenges (Dict[str, Challenge]): All available challenges
        user_progress (Dict[str, Dict[str, ChallengeProgress]]): User progress tracking
        flag_generator (FlagGenerator): Dynamic flag generation system
        hint_system (HintSystem): Progressive hint management
        leaderboard (Leaderboard): Scoring and ranking system
        achievement_system (AchievementSystem): Achievement tracking
    """
    
    def __init__(self, 
                 challenges_file: Optional[str] = None,
                 hints_file: Optional[str] = None,
                 secret_key: Optional[str] = None):
        """
        Initialize the CTF Manager.
        
        Args:
            challenges_file (str, optional): Path to JSON file with challenge definitions
            hints_file (str, optional): Path to JSON file with hints
            secret_key (str, optional): Secret key for flag generation
        """
        self.challenges: Dict[str, Challenge] = {}
        self.user_progress: Dict[str, Dict[str, ChallengeProgress]] = {}
        
        # Initialize subsystems
        self.flag_generator = FlagGenerator(prefix="HQX", secret_key=secret_key)
        self.hint_system = HintSystem(hints_file=hints_file)
        self.leaderboard = Leaderboard()
        self.achievement_system = AchievementSystem()
        
        # Load challenges if file provided
        if challenges_file:
            self.load_challenges(challenges_file)
    
    def load_challenges(self, challenges_file: str) -> bool:
        """
        Load challenges from a JSON file.
        
        Args:
            challenges_file (str): Path to challenges JSON file
            
        Returns:
            bool: True if loaded successfully, False otherwise
            
        Example JSON format:
        [
            {
                "id": "web_sqli_1",
                "title": "SQL Injection Basics",
                "description": "Find the hidden admin password",
                "category": "web",
                "difficulty": "easy",
                "points": 100,
                "flag_template": "admin_password_here",
                "hints": ["Check the login form", "Try SQL injection"],
                "files": ["http://challenge.local:8080"],
                "tags": ["sql", "injection", "web"]
            }
        ]
        """
        try:
            with open(challenges_file, 'r') as f:
                challenges_data = json.load(f)
            
            for challenge_data in challenges_data:
                challenge = Challenge(**challenge_data)
                self.challenges[challenge.id] = challenge
            
            print(f"✓ Loaded {len(self.challenges)} challenges")
            return True
        except Exception as e:
            print(f"✗ Error loading challenges: {e}")
            return False
    
    def get_all_challenges(self) -> List[Dict]:
        """
        Get list of all available challenges.
        
        Returns:
            List[Dict]: List of challenge dictionaries (without flag templates)
        """
        return [
            {
                'id': c.id,
                'title': c.title,
                'description': c.description,
                'category': c.category,
                'difficulty': c.difficulty,
                'points': c.points,
                'author': c.author,
                'tags': c.tags,
                'hints_available': len(c.hints),
                'files': c.files
            }
            for c in self.challenges.values()
        ]
    
    def get_challenge(self, challenge_id: str) -> Optional[Dict]:
        """
        Get details of a specific challenge.
        
        Args:
            challenge_id (str): Challenge identifier
            
        Returns:
            Optional[Dict]: Challenge details or None if not found
        """
        challenge = self.challenges.get(challenge_id)
        if not challenge:
            return None
        
        return {
            'id': challenge.id,
            'title': challenge.title,
            'description': challenge.description,
            'category': challenge.category,
            'difficulty': challenge.difficulty,
            'points': challenge.points,
            'author': challenge.author,
            'tags': challenge.tags,
            'hints_available': len(challenge.hints),
            'files': challenge.files
        }
    
    def start_challenge(self, challenge_id: str, user_id: str) -> Tuple[bool, str, Optional[Dict]]:
        """
        Start a challenge for a user.
        
        This marks the challenge as in-progress and records the start time.
        Users can start a challenge multiple times (resets don't affect the timer).
        
        Args:
            challenge_id (str): Challenge identifier
            user_id (str): User identifier
            
        Returns:
            Tuple[bool, str, Optional[Dict]]: 
                - Success flag
                - Message
                - Challenge progress data
        """
        # Validate challenge exists
        if challenge_id not in self.challenges:
            return False, f"Challenge '{challenge_id}' not found", None
        
        # Initialize user progress if needed
        if user_id not in self.user_progress:
            self.user_progress[user_id] = {}
        
        # Check if already solved
        if challenge_id in self.user_progress[user_id]:
            progress = self.user_progress[user_id][challenge_id]
            if progress.state == ChallengeState.SOLVED:
                return False, "Challenge already solved", progress.to_dict()
        
        # Start or restart the challenge
        if challenge_id not in self.user_progress[user_id]:
            progress = ChallengeProgress(
                challenge_id=challenge_id,
                user_id=user_id,
                state=ChallengeState.IN_PROGRESS,
                started_at=datetime.now()
            )
            self.user_progress[user_id][challenge_id] = progress
            message = "Challenge started successfully"
        else:
            progress = self.user_progress[user_id][challenge_id]
            if progress.state == ChallengeState.NOT_STARTED:
                progress.state = ChallengeState.IN_PROGRESS
                progress.started_at = datetime.now()
            message = "Challenge resumed"
        
        return True, message, progress.to_dict()
    
    def submit_flag(self, challenge_id: str, user_id: str, submitted_flag: str) -> Tuple[bool, str, Optional[Dict]]:
        """
        Submit a flag for verification.
        
        This validates the submitted flag against the user's unique flag,
        updates progress, awards points, checks for achievements, and
        updates the leaderboard.
        
        Args:
            challenge_id (str): Challenge identifier
            user_id (str): User identifier
            submitted_flag (str): Flag submitted by the user
            
        Returns:
            Tuple[bool, str, Optional[Dict]]:
                - Correct flag boolean
                - Message
                - Updated progress/stats data
        """
        # Validate challenge exists
        if challenge_id not in self.challenges:
            return False, f"Challenge '{challenge_id}' not found", None
        
        challenge = self.challenges[challenge_id]
        
        # Initialize user progress if needed
        if user_id not in self.user_progress:
            self.user_progress[user_id] = {}
        
        # Start challenge if not started
        if challenge_id not in self.user_progress[user_id]:
            self.start_challenge(challenge_id, user_id)
        
        progress = self.user_progress[user_id][challenge_id]
        
        # Check if already solved
        if progress.state == ChallengeState.SOLVED:
            return False, "Challenge already solved", progress.to_dict()
        
        # Increment attempts
        progress.attempts += 1
        
        # Generate correct flag for this user
        correct_flag = self.flag_generator.generate_user_flag(
            challenge_id=challenge_id,
            user_id=user_id,
            flag_content=challenge.flag_template
        )
        
        # Validate flag
        if self.flag_generator.verify_flag(submitted_flag, correct_flag):
            # Flag is correct!
            progress.state = ChallengeState.SOLVED
            progress.solved_at = datetime.now()
            
            # Calculate time taken
            time_taken = None
            if progress.started_at:
                time_taken = progress.solved_at - progress.started_at
            
            # Register user if not already registered
            if user_id not in self.leaderboard.users:
                self.leaderboard.register_user(user_id, user_id)
            
            # Check if first blood (before recording solve)
            is_first_blood = (challenge_id not in self.leaderboard.challenge_solves or 
                            len(self.leaderboard.challenge_solves[challenge_id]) == 0)
            
            # Set challenge base points
            self.leaderboard.set_challenge_points(challenge_id, challenge.points)
            
            # Record solve in leaderboard (this calculates points with all modifiers)
            success_solve, message_solve, points_earned = self.leaderboard.record_solve(
                user_id=user_id,
                challenge_id=challenge_id,
                timestamp=progress.solved_at,
                time_taken=time_taken,
                hints_used=progress.hints_unlocked,
                difficulty=challenge.difficulty
            )
            
            # If recording failed, return error
            if not success_solve:
                return False, message_solve, None
            
            # Get the solve object that was just created
            solve = self.leaderboard.challenge_solves[challenge_id][-1]
            
            # Check for achievements (simplified - check common ones)
            user_stats = self.leaderboard.users.get(user_id)
            achievements = []
            if user_stats:
                context = {
                    'user_stats': user_stats,
                    'solve': solve,
                    'is_first_blood': is_first_blood,
                    'hints_used': progress.hints_unlocked
                }
                
                # Check some basic achievements
                achievement_ids = ['first_blood', 'getting_started', 'no_hints']
                for ach_id in achievement_ids:
                    earned, msg = self.achievement_system.check_achievement(user_id, ach_id, context)
                    if earned and ach_id in [a.id for a in self.achievement_system.achievements.values()]:
                        achievement = self.achievement_system.achievements[ach_id]
                        achievements.append(achievement)
                        # Points already added by award_achievement method
            
            return True, "Correct flag! Challenge solved!", {
                'progress': progress.to_dict(),
                'points_earned': points_earned,
                'is_first_blood': is_first_blood,
                'time_taken': str(time_taken) if time_taken else None,
                'new_achievements': [a.id for a in achievements] if user_stats else []
            }
        else:
            # Incorrect flag
            return False, f"Incorrect flag (Attempt {progress.attempts})", {
                'progress': progress.to_dict(),
                'attempts': progress.attempts
            }
    
    def get_user_progress(self, user_id: str) -> Dict:
        """
        Get overall progress for a user across all challenges.
        
        Args:
            user_id (str): User identifier
            
        Returns:
            Dict: Comprehensive user progress statistics
        """
        if user_id not in self.user_progress:
            return {
                'user_id': user_id,
                'challenges_started': 0,
                'challenges_solved': 0,
                'total_points': 0,
                'total_attempts': 0,
                'challenges': {},
                'stats': None
            }
        
        user_challenges = self.user_progress[user_id]
        challenges_started = sum(1 for p in user_challenges.values() 
                                if p.state != ChallengeState.NOT_STARTED)
        challenges_solved = sum(1 for p in user_challenges.values() 
                               if p.state == ChallengeState.SOLVED)
        total_attempts = sum(p.attempts for p in user_challenges.values())
        
        # Get leaderboard stats
        user_stats = self.leaderboard.users.get(user_id)
        
        return {
            'user_id': user_id,
            'challenges_started': challenges_started,
            'challenges_solved': challenges_solved,
            'total_points': user_stats.total_points if user_stats else 0,
            'total_attempts': total_attempts,
            'challenges': {
                cid: progress.to_dict() 
                for cid, progress in user_challenges.items()
            },
            'stats': {
                'rank': self.leaderboard.get_user_rank(user_id),
                'solves': len(user_stats.solves) if user_stats else 0,
                'first_bloods': user_stats.first_bloods if user_stats else 0,
                'hints_used': sum(p.hints_unlocked for p in user_challenges.values())
            } if user_stats else None
        }
    
    def get_challenge_status(self, challenge_id: str, user_id: str) -> Dict:
        """
        Get the status of a specific challenge for a user.
        
        Args:
            challenge_id (str): Challenge identifier
            user_id (str): User identifier
            
        Returns:
            Dict: Challenge status including progress and user's flag
        """
        # Validate challenge exists
        if challenge_id not in self.challenges:
            return {'error': 'Challenge not found'}
        
        challenge = self.challenges[challenge_id]
        
        # Get user progress
        progress = None
        if user_id in self.user_progress and challenge_id in self.user_progress[user_id]:
            progress = self.user_progress[user_id][challenge_id]
        
        # Generate user's unique flag (only show if solved)
        user_flag = None
        if progress and progress.state == ChallengeState.SOLVED:
            user_flag = self.flag_generator.generate_user_flag(
                challenge_id=challenge_id,
                user_id=user_id,
                flag_content=challenge.flag_template
            )
        
        return {
            'challenge': self.get_challenge(challenge_id),
            'progress': progress.to_dict() if progress else None,
            'state': progress.state.value if progress else ChallengeState.NOT_STARTED.value,
            'user_flag': user_flag,
            'hints_unlocked': progress.hints_unlocked if progress else 0,
            'attempts': progress.attempts if progress else 0
        }
    
    def get_hint(self, challenge_id: str, user_id: str, hint_index: int) -> Tuple[bool, str, Optional[str]]:
        """
        Get a specific hint for a challenge.
        
        Args:
            challenge_id (str): Challenge identifier
            user_id (str): User identifier
            hint_index (int): Index of the hint to retrieve
            
        Returns:
            Tuple[bool, str, Optional[str]]:
                - Success flag
                - Message
                - Hint text if successful
        """
        # Validate challenge exists
        if challenge_id not in self.challenges:
            return False, "Challenge not found", None
        
        challenge = self.challenges[challenge_id]
        
        # Check hint index is valid
        if hint_index < 0 or hint_index >= len(challenge.hints):
            return False, "Invalid hint index", None
        
        # Get user progress
        if user_id not in self.user_progress or challenge_id not in self.user_progress[user_id]:
            return False, "Start the challenge first", None
        
        progress = self.user_progress[user_id][challenge_id]
        
        # Check if already solved
        if progress.state == ChallengeState.SOLVED:
            return False, "Challenge already solved", None
        
        # Check if hint already unlocked
        if hint_index < progress.hints_unlocked:
            return True, "Hint already unlocked", challenge.hints[hint_index]
        
        # Check if this is the next hint
        if hint_index != progress.hints_unlocked:
            return False, f"Unlock previous hints first (unlocked: {progress.hints_unlocked})", None
        
        return False, "Hint not unlocked. Use unlock endpoint to unlock this hint.", None
    
    def unlock_hint(self, challenge_id: str, user_id: str) -> Tuple[bool, str, Optional[Dict]]:
        """
        Unlock the next hint for a challenge (costs points).
        
        Args:
            challenge_id (str): Challenge identifier
            user_id (str): User identifier
            
        Returns:
            Tuple[bool, str, Optional[Dict]]:
                - Success flag
                - Message
                - Hint data including cost and text
        """
        # Validate challenge exists
        if challenge_id not in self.challenges:
            return False, "Challenge not found", None
        
        challenge = self.challenges[challenge_id]
        
        # Get user progress
        if user_id not in self.user_progress or challenge_id not in self.user_progress[user_id]:
            return False, "Start the challenge first", None
        
        progress = self.user_progress[user_id][challenge_id]
        
        # Check if already solved
        if progress.state == ChallengeState.SOLVED:
            return False, "Challenge already solved", None
        
        # Check if more hints available
        if progress.hints_unlocked >= len(challenge.hints):
            return False, "No more hints available", None
        
        # Get hint cost
        hint_index = progress.hints_unlocked
        hint_cost = self.hint_system.hint_costs[min(hint_index, len(self.hint_system.hint_costs) - 1)]
        
        # Check if user has enough points
        user_stats = self.leaderboard.users.get(user_id)
        current_points = user_stats.total_points if user_stats else 0
        
        if current_points < hint_cost:
            return False, f"Not enough points. Need {hint_cost}, have {current_points}", None
        
        # Unlock hint
        progress.hints_unlocked += 1
        progress.points_spent += hint_cost
        
        # Deduct points from leaderboard (directly modify user stats)
        if user_stats:
            user_stats.total_points -= hint_cost
        
        # Get the hint text
        hint_text = challenge.hints[hint_index]
        
        return True, "Hint unlocked successfully", {
            'hint_index': hint_index,
            'hint_text': hint_text,
            'cost': hint_cost,
            'hints_unlocked': progress.hints_unlocked,
            'hints_remaining': len(challenge.hints) - progress.hints_unlocked,
            'points_remaining': current_points - hint_cost
        }
    
    def get_leaderboard(self, limit: int = 10) -> List[Dict]:
        """
        Get the current leaderboard.
        
        Args:
            limit (int): Number of top users to return
            
        Returns:
            List[Dict]: Leaderboard entries
        """
        return self.leaderboard.get_leaderboard(limit=limit)
    
    def get_user_achievements(self, user_id: str) -> Dict:
        """
        Get all achievements for a user.
        
        Args:
            user_id (str): User identifier
            
        Returns:
            Dict: User achievements including earned and available
        """
        earned = self.achievement_system.get_user_achievements(user_id)
        available = self.achievement_system.get_available_achievements(user_id)
        
        return {
            'user_id': user_id,
            'earned': earned,
            'available': available,
            'total_earned': len(earned),
            'total_points': sum(a['points'] for a in earned)
        }


def main():
    """Example usage and testing of CTF Manager."""
    print("=== AegisForge CTF Manager - Test Suite ===\n")
    
    # Initialize manager
    manager = CTFManager()
    
    # Add sample challenges
    sample_challenges = [
        Challenge(
            id="web_sqli_1",
            title="SQL Injection Basics",
            description="Find the hidden admin password using SQL injection",
            category="web",
            difficulty="easy",
            points=100,
            flag_template="admin_password_12345",
            hints=[
                "Check the login form for SQL injection vulnerabilities",
                "Try using ' OR '1'='1 in the username field",
                "Look for the admin table in the database"
            ],
            files=["http://challenge.local:8080"],
            tags=["sql", "injection", "web"]
        ),
        Challenge(
            id="crypto_xor_1",
            title="XOR Encryption",
            description="Decrypt the XOR encrypted message",
            category="crypto",
            difficulty="medium",
            points=200,
            flag_template="secret_key_xyz",
            hints=[
                "XOR encryption uses the same key for encryption and decryption",
                "Try common keys like 'A', '0', or single bytes"
            ],
            tags=["xor", "encryption", "crypto"]
        )
    ]
    
    for challenge in sample_challenges:
        manager.challenges[challenge.id] = challenge
    
    print(f"✓ Loaded {len(manager.challenges)} challenges\n")
    
    # Test 1: List all challenges
    print("Test 1: Get all challenges")
    challenges = manager.get_all_challenges()
    for c in challenges:
        print(f"  - {c['title']} ({c['category']}/{c['difficulty']}) - {c['points']} points")
    print()
    
    # Test 2: Start a challenge
    print("Test 2: Start challenge")
    success, msg, data = manager.start_challenge("web_sqli_1", "user_001")
    print(f"  Status: {msg}")
    print(f"  State: {data['state']}")
    print()
    
    # Test 3: Submit wrong flag
    print("Test 3: Submit incorrect flag")
    success, msg, data = manager.submit_flag("web_sqli_1", "user_001", "HQX{wrong_flag}")
    print(f"  Correct: {success}")
    print(f"  Message: {msg}")
    print(f"  Attempts: {data['attempts']}")
    print()
    
    # Test 4: Unlock a hint
    print("Test 4: Unlock hint")
    success, msg, data = manager.unlock_hint("web_sqli_1", "user_001")
    if success:
        print(f"  {msg}")
        print(f"  Hint: {data['hint_text']}")
        print(f"  Cost: {data['cost']} points")
    else:
        print(f"  {msg} (Expected - user has no points yet)")
    print()
    
    # Test 5: Submit correct flag
    print("Test 5: Submit correct flag")
    correct_flag = manager.flag_generator.generate_user_flag(
        "web_sqli_1", "user_001", "admin_password_12345"
    )
    print(f"  Generated flag: {correct_flag}")
    success, msg, data = manager.submit_flag("web_sqli_1", "user_001", correct_flag)
    print(f"  Correct: {success}")
    print(f"  Message: {msg}")
    print(f"  Points earned: {data['points_earned']}")
    print(f"  First blood: {data['is_first_blood']}")
    print()
    
    # Test 6: Get user progress
    print("Test 6: Get user progress")
    progress = manager.get_user_progress("user_001")
    print(f"  User: {progress['user_id']}")
    print(f"  Challenges solved: {progress['challenges_solved']}/{progress['challenges_started']}")
    print(f"  Total points: {progress['total_points']}")
    print(f"  Rank: {progress['stats']['rank'] if progress['stats'] else 'N/A'}")
    print()
    
    # Test 7: Another user solves (no first blood)
    print("Test 7: Second user solves same challenge")
    manager.start_challenge("web_sqli_1", "user_002")
    correct_flag_2 = manager.flag_generator.generate_user_flag(
        "web_sqli_1", "user_002", "admin_password_12345"
    )
    success, msg, data = manager.submit_flag("web_sqli_1", "user_002", correct_flag_2)
    print(f"  First blood: {data['is_first_blood']} (Expected: False)")
    print(f"  Points earned: {data['points_earned']}")
    print()
    
    # Test 8: Get leaderboard
    print("Test 8: Get leaderboard")
    leaderboard = manager.get_leaderboard(limit=5)
    for i, entry in enumerate(leaderboard, 1):
        print(f"  {i}. {entry['user_id']}: {entry['points']} points ({entry['solves']} solves)")
    print()
    
    # Test 9: Get challenge status
    print("Test 9: Get challenge status")
    status = manager.get_challenge_status("web_sqli_1", "user_001")
    print(f"  Challenge: {status['challenge']['title']}")
    print(f"  State: {status['state']}")
    print(f"  User's flag: {status['user_flag']}")
    print()
    
    print("=== All tests completed successfully! ===")


if __name__ == "__main__":
    main()
