# AegisForge CTF Database Documentation

This directory contains the database schema, models, and seeding scripts for the AegisForge CTF platform.

## Files

### 1. `ctf_schema.sql`
Complete PostgreSQL/SQLite database schema with:
- **challenges** - Challenge definitions with metadata
- **user_challenges** - User progress tracking per challenge
- **solves** - Successful challenge completions
- **hints_used** - Hint usage tracking for penalties
- **achievements** - User achievements and badges
- **leaderboard** - Materialized leaderboard for performance

Features:
- Proper foreign keys and constraints
- Optimized indexes for common queries
- Triggers for automatic timestamp updates
- Helper views for statistics
- Comprehensive documentation

### 2. `ctf_models.py`
SQLAlchemy ORM models matching the schema:
- `Challenge` - CTF challenge model
- `UserChallenge` - User progress model
- `Solve` - Challenge solve records
- `HintUsed` - Hint usage tracking
- `Achievement` - Achievement tracking
- `LeaderboardEntry` - Leaderboard entries

Features:
- Full ORM relationships
- `to_dict()` methods for JSON serialization
- Helper methods (e.g., `time_taken()`)
- Type hints and comprehensive docstrings
- Proper constraints and validation

### 3. `seed_data.py`
Database seeding script with initial data:
- 5 AI detection CTF challenges:
  - `area64` - Base64 + AI detection (easy, 100 pts)
  - `smalle` - LLM prompt injection (medium, 200 pts)
  - `hidden_layers` - Neural network analysis (medium, 250 pts)
  - `paper_script` - Reverse engineering (hard, 350 pts)
  - `synthetic_stacks` - Log forensics (hard, 400 pts)
- Sample users for testing
- Sample progress data

## Usage

### Initialize Database Schema

**Using SQL directly (PostgreSQL):**
```bash
psql -U your_user -d your_database -f ctf_schema.sql
```

**Using SQLAlchemy (Python):**
```python
from sqlalchemy import create_engine
from ctf.database.ctf_models import init_db

engine = create_engine('postgresql://user:pass@localhost/dbname')
init_db(engine)
```

### Seed Initial Data

**Default (SQLite):**
```bash
python seed_data.py
```

**With PostgreSQL:**
```bash
export DATABASE_URL="postgresql://user:pass@localhost/dbname"
python seed_data.py
```

**From Python code:**
```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from ctf.database.seed_data import seed_challenges, seed_sample_users

engine = create_engine('your-database-url')
Session = sessionmaker(bind=engine)
session = Session()

seed_challenges(session)
seed_sample_users(session)
```

### Using the Models

**Import models:**
```python
from ctf.database.ctf_models import (
    Challenge, UserChallenge, Solve, 
    HintUsed, Achievement, LeaderboardEntry
)
```

**Create a session:**
```python
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

engine = create_engine('sqlite:///ctf_database.db')
Session = sessionmaker(bind=engine)
session = Session()
```

**Query challenges:**
```python
# Get all challenges
challenges = session.query(Challenge).all()

# Get challenges by difficulty
easy_challenges = session.query(Challenge).filter_by(difficulty='easy').all()

# Get challenge by ID
challenge = session.query(Challenge).filter_by(id='area64').first()
print(challenge.to_dict())
```

**Track user progress:**
```python
from datetime import datetime

# Start a challenge
progress = UserChallenge(
    user_id='user123',
    challenge_id='area64',
    flag='AEGIS{area64_user123_decoded}',
    state='in_progress',
    started_at=datetime.utcnow()
)
session.add(progress)
session.commit()

# Record a solve
progress.state = 'solved'
progress.solved_at = datetime.utcnow()
progress.points_earned = 100

solve = Solve(
    user_id='user123',
    challenge_id='area64',
    solve_time=datetime.utcnow(),
    time_taken=progress.time_taken(),
    points=100,
    first_blood=False
)
session.add(solve)
session.commit()
```

**Update leaderboard:**
```python
from sqlalchemy import func

# Get or create leaderboard entry
entry = session.query(LeaderboardEntry).filter_by(user_id='user123').first()
if not entry:
    entry = LeaderboardEntry(user_id='user123', username='john')
    session.add(entry)

# Update stats
entry.total_points = session.query(func.sum(Solve.points)).filter_by(user_id='user123').scalar() or 0
entry.challenges_solved = session.query(Solve).filter_by(user_id='user123').count()
entry.last_solve_time = session.query(func.max(Solve.solve_time)).filter_by(user_id='user123').scalar()
session.commit()
```

**Query leaderboard:**
```python
# Top 10 users
top_users = session.query(LeaderboardEntry)\
    .order_by(LeaderboardEntry.total_points.desc(), 
              LeaderboardEntry.last_solve_time.asc())\
    .limit(10).all()

for user in top_users:
    print(f"{user.rank}. {user.username} - {user.total_points} pts")
```

## Database Configuration

### SQLite (Development)
```python
DATABASE_URL = 'sqlite:///ctf_database.db'
```

### PostgreSQL (Production)
```python
DATABASE_URL = 'postgresql://username:password@localhost:5432/aegisforge_ctf'
```

### Environment Variables
```bash
export DATABASE_URL="postgresql://user:pass@localhost/dbname"
```

## Schema Diagram

```
challenges
  ├── user_challenges (FK: challenge_id)
  │   └── user_id (references user system)
  ├── solves (FK: challenge_id)
  │   └── user_id
  └── hints_used (FK: challenge_id)
      └── user_id

achievements
  └── user_id

leaderboard
  └── user_id (PK)
```

## Indexes

Performance-critical indexes:
- `idx_user_challenges_user` - User progress queries
- `idx_solves_user` - User solve history
- `idx_leaderboard_points` - Leaderboard ranking
- `idx_challenges_category` - Category filtering

## Testing

Run tests to verify database functionality:
```bash
# Compile Python modules
python -m py_compile ctf_models.py seed_data.py

# Test seeding
python seed_data.py

# Verify tables created
python -c "from sqlalchemy import create_engine, inspect; \
engine = create_engine('sqlite:///ctf_database.db'); \
print(inspect(engine).get_table_names())"
```

## Maintenance

**Clear all data:**
```python
from ctf.database.seed_data import clear_database
clear_database(session)
```

**Reset and re-seed:**
```python
from ctf.database.ctf_models import drop_all_tables, init_db
drop_all_tables(engine)
init_db(engine)
# Then run seed_data.py
```

## Notes

- All timestamps use UTC
- User IDs reference the main authentication system
- Flags are generated per-user using `flag_template`
- Hints cost points, reducing final score
- First blood bonus tracked automatically
- Leaderboard is materialized for performance

## Support

For issues or questions, see the main project documentation or contact the AegisForge team.
