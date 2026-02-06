"""
AegisForge CTF - Database Seed Data

This script seeds the database with initial CTF challenges and sample data.
Includes the 5 AI detection challenges: area64, smalle, hidden_layers,
paper_script, and synthetic_stacks.

Usage:
    python seed_data.py [--database-url DATABASE_URL]

Author: AegisForge CTF Platform
"""

import json
import sys
import os
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from database.ctf_models import (
    Base, Challenge, UserChallenge, Solve, HintUsed, 
    Achievement, LeaderboardEntry, init_db
)


def get_database_url():
    """
    Get database URL from environment or use default SQLite.
    
    Returns:
        Database connection string
    """
    return os.environ.get(
        'DATABASE_URL',
        'sqlite:///ctf_database.db'
    )


def seed_challenges(session):
    """
    Seed the database with the 5 AI detection CTF challenges.
    
    Args:
        session: SQLAlchemy session
    """
    challenges = [
        {
            'id': 'area64',
            'name': 'Area64 Detection',
            'category': 'ai-detection',
            'difficulty': 'easy',
            'points': 100,
            'description': '''Your mission is to identify AI-generated text hidden in a series of messages.
            
The challenge uses base64 encoding to obfuscate the content. Your task is to:
1. Decode the base64 messages
2. Use the AI detection endpoint at /api/ai-detection/detect
3. Find which messages are AI-generated
4. Locate the flag hidden in the AI content

**Endpoint:** POST /api/ai-detection/detect
**Payload:** {"text": "your decoded text here"}

The flag format is: `AEGIS{area64_decoded_success}`

**Skills:** Base64 decoding, API interaction, AI detection''',
            'flag_template': 'AEGIS{{area64_{user_id}_decoded}}',
            'hints': json.dumps([
                'Start by base64 decoding the suspicious messages.',
                'The AI detection API returns a confidence score - look for high scores.',
                'The flag is embedded in one of the AI-generated messages.'
            ]),
            'files': json.dumps([
                '/challenges/area64/messages.txt',
                '/api/ai-detection/detect'
            ]),
            'author': 'AegisForge Team',
            'tags': json.dumps(['base64', 'encoding', 'ai-detection', 'api'])
        },
        {
            'id': 'smalle',
            'name': 'Small Language Model Exploit',
            'category': 'ai-detection',
            'difficulty': 'medium',
            'points': 200,
            'description': '''Exploit a small language model to extract sensitive information.

The challenge provides a chat interface powered by a small AI model. Your task is to:
1. Craft prompts that make the model reveal hidden information
2. Use prompt injection techniques to bypass filters
3. Extract the secret flag from the model's training data

**Interface:** /challenges/smalle/chat
**Technique:** Prompt engineering and injection

The flag format is: `AEGIS{smalle_prompt_injection_success}`

**Skills:** Prompt engineering, injection attacks, AI model exploitation''',
            'flag_template': 'AEGIS{{smalle_{user_id}_prompt_injection}}',
            'hints': json.dumps([
                'Try asking the model to "ignore previous instructions".',
                'The model has been trained with the flag - ask it to recall training data.',
                'Use role-playing to make the model think it should reveal secrets.'
            ]),
            'files': json.dumps([
                '/challenges/smalle/chat',
                '/challenges/smalle/model-info.txt'
            ]),
            'author': 'AegisForge Team',
            'tags': json.dumps(['llm', 'prompt-injection', 'ai-exploitation', 'chat'])
        },
        {
            'id': 'hidden_layers',
            'name': 'Hidden Layers Discovery',
            'category': 'ai-detection',
            'difficulty': 'medium',
            'points': 250,
            'description': '''Analyze a neural network to discover hidden information in its layers.

You're given access to a neural network model file. Your challenge is to:
1. Load and inspect the model architecture
2. Examine the weights and biases in hidden layers
3. Decode the steganographic message hidden in the model weights
4. Extract the flag from layer activation patterns

**Files:** model.h5 or model.pth
**Tools:** TensorFlow/PyTorch, numpy

The flag format is: `AEGIS{hidden_layers_revealed}`

**Skills:** Neural network analysis, steganography, model inspection, Python''',
            'flag_template': 'AEGIS{{hidden_layers_{user_id}_revealed}}',
            'hints': json.dumps([
                'Start by loading the model and printing its layer structure.',
                'Look at the weight matrices - are there any unusual patterns?',
                'Try converting weight values to ASCII characters.',
                'The flag is encoded in the bias values of layer 3.'
            ]),
            'files': json.dumps([
                '/challenges/hidden_layers/model.h5',
                '/challenges/hidden_layers/requirements.txt'
            ]),
            'author': 'AegisForge Team',
            'tags': json.dumps(['neural-networks', 'steganography', 'model-analysis', 'python'])
        },
        {
            'id': 'paper_script',
            'name': 'Paper Trail Script Analysis',
            'category': 'ai-detection',
            'difficulty': 'hard',
            'points': 350,
            'description': '''Reverse engineer an obfuscated script that uses AI to generate fake research papers.

The challenge provides a heavily obfuscated Python script. Your mission:
1. De-obfuscate the code to understand its functionality
2. Identify the AI model and API being used
3. Intercept or reverse the paper generation process
4. Extract the authentication token hidden in the generated papers
5. Use the token to access the flag endpoint

**Files:** paper_generator.pyc (compiled Python)
**Endpoint:** /api/papers/flag (requires token)

The flag format is: `AEGIS{paper_trail_followed}`

**Skills:** Reverse engineering, Python decompilation, AI API analysis, token extraction''',
            'flag_template': 'AEGIS{{paper_trail_{user_id}_followed}}',
            'hints': json.dumps([
                'Use a Python decompiler like uncompyle6 or decompyle3.',
                'The script makes API calls to an external AI service - intercept them.',
                'Look for base64 or hex encoded strings in the generated papers.',
                'The token is hidden in the paper metadata, not the content.',
                'The flag endpoint expects a header: Authorization: Bearer <token>'
            ]),
            'files': json.dumps([
                '/challenges/paper_script/paper_generator.pyc',
                '/challenges/paper_script/sample_output.pdf',
                '/api/papers/flag'
            ]),
            'author': 'AegisForge Team',
            'tags': json.dumps(['reverse-engineering', 'python', 'obfuscation', 'ai-api', 'tokens'])
        },
        {
            'id': 'synthetic_stacks',
            'name': 'Synthetic Stack Traces',
            'category': 'ai-detection',
            'difficulty': 'hard',
            'points': 400,
            'description': '''Analyze AI-generated vs real stack traces to find anomalies and extract the flag.

You're given a collection of error logs and stack traces. Your challenge:
1. Identify which stack traces are AI-generated fakes
2. Find the patterns that distinguish real from synthetic traces
3. Use statistical analysis and the AI detection API
4. Locate the flag hidden in the anomalous patterns
5. Decode the flag from stack frame memory addresses

**Dataset:** 1000+ stack traces (mix of real and AI-generated)
**Tools:** Python, statistical analysis, pattern recognition

The flag format is: `AEGIS{synthetic_stacks_decoded}`

**Skills:** Log analysis, pattern recognition, statistical analysis, AI detection, forensics''',
            'flag_template': 'AEGIS{{synthetic_stacks_{user_id}_decoded}}',
            'hints': json.dumps([
                'Real stack traces have consistent memory address patterns.',
                'AI-generated traces often have impossible function call sequences.',
                'Look for traces with suspiciously round memory addresses.',
                'The memory addresses in fake traces encode the flag in hex.',
                'Sort by AI confidence score and analyze the top 10 synthetic traces.'
            ]),
            'files': json.dumps([
                '/challenges/synthetic_stacks/stack_traces.json',
                '/challenges/synthetic_stacks/analysis_tools.py',
                '/api/ai-detection/batch-detect'
            ]),
            'author': 'AegisForge Team',
            'tags': json.dumps(['forensics', 'log-analysis', 'pattern-recognition', 'statistics', 'ai-detection'])
        }
    ]
    
    print("Seeding challenges...")
    for challenge_data in challenges:
        challenge = Challenge(**challenge_data)
        session.merge(challenge)  # Insert or update
        print(f"  ✓ Added challenge: {challenge.name} ({challenge.difficulty}, {challenge.points} pts)")
    
    session.commit()
    print(f"Successfully seeded {len(challenges)} challenges!")


def seed_sample_users(session):
    """
    Seed sample users for testing purposes.
    
    Args:
        session: SQLAlchemy session
    """
    sample_users = [
        {
            'user_id': 'demo_user_1',
            'username': 'alice',
            'total_points': 0,
            'challenges_solved': 0,
            'hints_used': 0,
            'achievements_earned': 0,
            'rank': None
        },
        {
            'user_id': 'demo_user_2',
            'username': 'bob',
            'total_points': 0,
            'challenges_solved': 0,
            'hints_used': 0,
            'achievements_earned': 0,
            'rank': None
        },
        {
            'user_id': 'demo_user_3',
            'username': 'charlie',
            'total_points': 0,
            'challenges_solved': 0,
            'hints_used': 0,
            'achievements_earned': 0,
            'rank': None
        }
    ]
    
    print("\nSeeding sample users...")
    for user_data in sample_users:
        user = LeaderboardEntry(**user_data)
        session.merge(user)  # Insert or update
        print(f"  ✓ Added user: {user.username}")
    
    session.commit()
    print(f"Successfully seeded {len(sample_users)} sample users!")


def seed_sample_progress(session):
    """
    Seed some sample progress data for demonstration.
    
    Args:
        session: SQLAlchemy session
    """
    # Create sample progress for alice
    progress_data = [
        {
            'user_id': 'demo_user_1',
            'challenge_id': 'area64',
            'flag': 'AEGIS{area64_demo_user_1_decoded}',
            'state': 'solved',
            'started_at': datetime.utcnow(),
            'solved_at': datetime.utcnow(),
            'attempts': 3,
            'hints_used': 1,
            'points_earned': 90,  # 100 - 10 for hint
            'points_spent': 10
        },
        {
            'user_id': 'demo_user_1',
            'challenge_id': 'smalle',
            'flag': 'AEGIS{smalle_demo_user_1_prompt_injection}',
            'state': 'in_progress',
            'started_at': datetime.utcnow(),
            'attempts': 5,
            'hints_used': 0,
            'points_earned': 0,
            'points_spent': 0
        }
    ]
    
    print("\nSeeding sample progress...")
    for progress in progress_data:
        uc = UserChallenge(**progress)
        session.add(uc)
        print(f"  ✓ Added progress: {progress['user_id']} on {progress['challenge_id']} ({progress['state']})")
    
    # Create corresponding solve record for completed challenge
    solve = Solve(
        user_id='demo_user_1',
        challenge_id='area64',
        solve_time=datetime.utcnow(),
        time_taken=450,  # 7.5 minutes
        points=90,
        first_blood=True
    )
    session.add(solve)
    print("  ✓ Added solve record for alice's area64 completion")
    
    # Update leaderboard for alice
    alice = session.query(LeaderboardEntry).filter_by(user_id='demo_user_1').first()
    if alice:
        alice.total_points = 90
        alice.challenges_solved = 1
        alice.hints_used = 1
        alice.last_solve_time = datetime.utcnow()
        alice.rank = 1
        print("  ✓ Updated leaderboard for alice")
    
    session.commit()
    print("Successfully seeded sample progress!")


def clear_database(session):
    """
    Clear all data from the database (useful for testing).
    
    Args:
        session: SQLAlchemy session
    """
    print("\nClearing existing data...")
    session.query(Achievement).delete()
    session.query(HintUsed).delete()
    session.query(Solve).delete()
    session.query(UserChallenge).delete()
    session.query(LeaderboardEntry).delete()
    session.query(Challenge).delete()
    session.commit()
    print("Database cleared!")


def main():
    """
    Main entry point for database seeding.
    """
    print("=" * 70)
    print("AegisForge CTF Database Seeder")
    print("=" * 70)
    
    # Get database URL
    database_url = get_database_url()
    print(f"\nDatabase: {database_url}")
    
    # Create engine and session
    engine = create_engine(database_url, echo=False)
    Session = sessionmaker(bind=engine)
    session = Session()
    
    try:
        # Initialize database schema
        print("\nInitializing database schema...")
        init_db(engine)
        print("Schema initialized!")
        
        # Optional: Clear existing data (uncomment if needed)
        # clear_database(session)
        
        # Seed challenges
        seed_challenges(session)
        
        # Seed sample users
        seed_sample_users(session)
        
        # Seed sample progress (optional)
        seed_sample_progress(session)
        
        print("\n" + "=" * 70)
        print("✓ Database seeding completed successfully!")
        print("=" * 70)
        
        # Print summary
        challenge_count = session.query(Challenge).count()
        user_count = session.query(LeaderboardEntry).count()
        print(f"\nSummary:")
        print(f"  Challenges: {challenge_count}")
        print(f"  Users: {user_count}")
        print(f"  Solves: {session.query(Solve).count()}")
        print(f"  Active progress: {session.query(UserChallenge).count()}")
        
    except Exception as e:
        print(f"\n✗ Error during seeding: {e}")
        session.rollback()
        raise
    finally:
        session.close()


if __name__ == '__main__':
    main()
