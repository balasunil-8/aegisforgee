"""
Progressive Hint System for CTF Challenges

This module provides a hint management system for CTF challenges that:
- Delivers hints progressively (users unlock hints one by one)
- Charges points for each hint (increasing costs)
- Tracks which hints users have unlocked
- Loads hint data from JSON files

Author: AegisForge CTF Platform
"""

import json
from typing import Dict, List, Optional, Tuple
from datetime import datetime


class HintSystem:
    """
    Manages progressive hints for CTF challenges.
    
    The hint system allows users to unlock hints one at a time, with each hint
    costing progressively more points. This encourages users to try solving
    challenges independently before requesting hints.
    
    Attributes:
        hints_data (Dict): Dictionary mapping challenge IDs to their hints
        user_hints (Dict): Tracks which hints each user has unlocked
        hint_costs (List[int]): Point costs for each hint level (default: [10, 20, 30, 50, 100])
    """
    
    def __init__(self, hints_file: Optional[str] = None, hint_costs: Optional[List[int]] = None):
        """
        Initialize the hint system.
        
        Args:
            hints_file (str, optional): Path to JSON file containing hint data
            hint_costs (List[int], optional): Custom point costs for hints
        """
        self.hints_data: Dict[str, List[Dict]] = {}
        self.user_hints: Dict[str, Dict[str, List[int]]] = {}  # {user_id: {challenge_id: [hint_indices]}}
        self.hint_costs: List[int] = hint_costs or [10, 20, 30, 50, 100]
        
        if hints_file:
            self.load_hints(hints_file)
    
    def load_hints(self, hints_file: str) -> bool:
        """
        Load hints from a JSON file.
        
        Expected JSON format:
        {
            "challenge_id": [
                {"text": "First hint", "cost": 10},
                {"text": "Second hint", "cost": 20}
            ]
        }
        
        Args:
            hints_file (str): Path to the JSON file
            
        Returns:
            bool: True if loaded successfully, False otherwise
        """
        try:
            with open(hints_file, 'r', encoding='utf-8') as f:
                self.hints_data = json.load(f)
            return True
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading hints file: {e}")
            return False
    
    def add_hints(self, challenge_id: str, hints: List[Dict]) -> None:
        """
        Add hints for a specific challenge.
        
        Args:
            challenge_id (str): Unique identifier for the challenge
            hints (List[Dict]): List of hint dictionaries with 'text' and optional 'cost'
        """
        # Ensure each hint has a cost
        for i, hint in enumerate(hints):
            if 'cost' not in hint:
                # Use default cost based on hint index
                hint['cost'] = self.hint_costs[i] if i < len(self.hint_costs) else self.hint_costs[-1]
        
        self.hints_data[challenge_id] = hints
    
    def get_hint(self, user_id: str, challenge_id: str) -> Tuple[Optional[Dict], str]:
        """
        Get the next available hint for a user on a specific challenge.
        
        This method returns the next hint in sequence that the user hasn't unlocked yet.
        Users must unlock hints in order (can't skip ahead).
        
        Args:
            user_id (str): Unique identifier for the user
            challenge_id (str): Unique identifier for the challenge
            
        Returns:
            Tuple[Optional[Dict], str]: 
                - Hint dictionary with 'text' and 'cost', or None if no hints available
                - Status message explaining the result
        """
        # Check if challenge has hints
        if challenge_id not in self.hints_data:
            return None, "No hints available for this challenge"
        
        challenge_hints = self.hints_data[challenge_id]
        
        if not challenge_hints:
            return None, "No hints available for this challenge"
        
        # Initialize user's hint tracking if needed
        if user_id not in self.user_hints:
            self.user_hints[user_id] = {}
        
        if challenge_id not in self.user_hints[user_id]:
            self.user_hints[user_id][challenge_id] = []
        
        # Get the next hint index
        unlocked_hints = self.user_hints[user_id][challenge_id]
        next_hint_index = len(unlocked_hints)
        
        # Check if all hints have been unlocked
        if next_hint_index >= len(challenge_hints):
            return None, "All hints have been unlocked"
        
        # Return the next hint
        next_hint = challenge_hints[next_hint_index].copy()
        next_hint['hint_number'] = next_hint_index + 1
        next_hint['total_hints'] = len(challenge_hints)
        
        return next_hint, f"Hint {next_hint_index + 1} of {len(challenge_hints)}"
    
    def unlock_hint(self, user_id: str, challenge_id: str) -> Tuple[bool, str, int]:
        """
        Unlock the next hint for a user (after verifying they have enough points).
        
        Args:
            user_id (str): Unique identifier for the user
            challenge_id (str): Unique identifier for the challenge
            
        Returns:
            Tuple[bool, str, int]:
                - Success status (True if hint was unlocked)
                - Status message
                - Point cost of the hint (0 if unsuccessful)
        """
        hint, message = self.get_hint(user_id, challenge_id)
        
        if hint is None:
            return False, message, 0
        
        # Record that the user unlocked this hint
        hint_index = len(self.user_hints[user_id][challenge_id])
        self.user_hints[user_id][challenge_id].append(hint_index)
        
        return True, f"Hint unlocked: {hint['text']}", hint['cost']
    
    def get_unlocked_hints(self, user_id: str, challenge_id: str) -> List[Dict]:
        """
        Get all hints that a user has unlocked for a challenge.
        
        Args:
            user_id (str): Unique identifier for the user
            challenge_id (str): Unique identifier for the challenge
            
        Returns:
            List[Dict]: List of unlocked hint dictionaries
        """
        if user_id not in self.user_hints:
            return []
        
        if challenge_id not in self.user_hints[user_id]:
            return []
        
        if challenge_id not in self.hints_data:
            return []
        
        unlocked_indices = self.user_hints[user_id][challenge_id]
        challenge_hints = self.hints_data[challenge_id]
        
        return [challenge_hints[i] for i in unlocked_indices if i < len(challenge_hints)]
    
    def get_hint_count(self, challenge_id: str) -> int:
        """
        Get the total number of hints available for a challenge.
        
        Args:
            challenge_id (str): Unique identifier for the challenge
            
        Returns:
            int: Number of hints available
        """
        return len(self.hints_data.get(challenge_id, []))
    
    def get_unlocked_count(self, user_id: str, challenge_id: str) -> int:
        """
        Get the number of hints a user has unlocked for a challenge.
        
        Args:
            user_id (str): Unique identifier for the user
            challenge_id (str): Unique identifier for the challenge
            
        Returns:
            int: Number of hints unlocked
        """
        if user_id not in self.user_hints:
            return 0
        
        return len(self.user_hints[user_id].get(challenge_id, []))
    
    def calculate_total_hint_cost(self, user_id: str, challenge_id: str) -> int:
        """
        Calculate the total points spent on hints for a challenge.
        
        Args:
            user_id (str): Unique identifier for the user
            challenge_id (str): Unique identifier for the challenge
            
        Returns:
            int: Total points spent on hints
        """
        unlocked_hints = self.get_unlocked_hints(user_id, challenge_id)
        return sum(hint.get('cost', 0) for hint in unlocked_hints)
    
    def reset_user_hints(self, user_id: str, challenge_id: Optional[str] = None) -> None:
        """
        Reset hint progress for a user (useful for practice mode or retries).
        
        Args:
            user_id (str): Unique identifier for the user
            challenge_id (str, optional): Specific challenge to reset, or None for all
        """
        if user_id not in self.user_hints:
            return
        
        if challenge_id:
            # Reset specific challenge
            if challenge_id in self.user_hints[user_id]:
                del self.user_hints[user_id][challenge_id]
        else:
            # Reset all challenges for user
            del self.user_hints[user_id]


def main():
    """Example usage of the HintSystem class."""
    print("=== CTF Hint System Demo ===\n")
    
    # Initialize the hint system
    hint_system = HintSystem()
    
    # Add hints for a sample challenge
    sql_injection_hints = [
        {"text": "Try looking at the SQL query structure", "cost": 10},
        {"text": "The login form might be vulnerable to ' OR '1'='1", "cost": 20},
        {"text": "Use UNION SELECT to extract data from other tables", "cost": 30},
        {"text": "The flag is in the 'secrets' table", "cost": 50}
    ]
    
    hint_system.add_hints("sql_injection_1", sql_injection_hints)
    
    print("Challenge: SQL Injection #1")
    print(f"Total hints available: {hint_system.get_hint_count('sql_injection_1')}\n")
    
    # Simulate a user requesting hints
    user_id = "player_123"
    challenge_id = "sql_injection_1"
    
    # Get first hint
    hint, message = hint_system.get_hint(user_id, challenge_id)
    if hint:
        print(f"Preview - {message}")
        print(f"  Cost: {hint['cost']} points")
        print(f"  Text: {hint['text']}\n")
        
        # Unlock the hint
        success, unlock_msg, cost = hint_system.unlock_hint(user_id, challenge_id)
        print(f"Unlocked: {success} - {unlock_msg}")
        print(f"Points deducted: {cost}\n")
    
    # Get second hint
    hint, message = hint_system.get_hint(user_id, challenge_id)
    if hint:
        print(f"Preview - {message}")
        print(f"  Cost: {hint['cost']} points")
        print(f"  Text: {hint['text']}\n")
        
        success, unlock_msg, cost = hint_system.unlock_hint(user_id, challenge_id)
        print(f"Unlocked: {success} - {unlock_msg}")
        print(f"Points deducted: {cost}\n")
    
    # Show summary
    unlocked = hint_system.get_unlocked_count(user_id, challenge_id)
    total_hints = hint_system.get_hint_count(challenge_id)
    total_cost = hint_system.calculate_total_hint_cost(user_id, challenge_id)
    
    print(f"Summary:")
    print(f"  Hints unlocked: {unlocked}/{total_hints}")
    print(f"  Total points spent: {total_cost}")
    
    # Show all unlocked hints
    print(f"\nAll unlocked hints:")
    for i, hint in enumerate(hint_system.get_unlocked_hints(user_id, challenge_id), 1):
        print(f"  {i}. {hint['text']} (cost: {hint['cost']})")


if __name__ == "__main__":
    main()
