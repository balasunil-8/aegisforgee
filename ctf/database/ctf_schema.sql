-- ============================================================================
-- AegisForge CTF Database Schema
-- ============================================================================
-- Complete database schema for the AegisForge CTF platform
-- Includes tables for challenges, user progress, solves, hints, achievements,
-- and leaderboard functionality with proper relationships and constraints.
-- ============================================================================

-- Drop existing tables in reverse dependency order
DROP TABLE IF EXISTS leaderboard CASCADE;
DROP TABLE IF EXISTS achievements CASCADE;
DROP TABLE IF EXISTS hints_used CASCADE;
DROP TABLE IF EXISTS solves CASCADE;
DROP TABLE IF EXISTS user_challenges CASCADE;
DROP TABLE IF EXISTS challenges CASCADE;

-- ============================================================================
-- CHALLENGES TABLE
-- ============================================================================
-- Stores all CTF challenges with their metadata and configuration
CREATE TABLE challenges (
    id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(200) NOT NULL,
    category VARCHAR(50) NOT NULL,  -- e.g., 'ai-detection', 'web', 'crypto'
    difficulty VARCHAR(20) NOT NULL CHECK (difficulty IN ('easy', 'medium', 'hard', 'expert')),
    points INTEGER NOT NULL CHECK (points > 0),
    description TEXT NOT NULL,
    flag_template VARCHAR(500) NOT NULL,  -- Template for flag generation
    hints TEXT,  -- JSON array of hints
    files TEXT,  -- JSON array of file URLs/paths
    author VARCHAR(100) DEFAULT 'AegisForge Team',
    tags TEXT,  -- JSON array of searchable tags
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index for filtering and searching
CREATE INDEX idx_challenges_category ON challenges(category);
CREATE INDEX idx_challenges_difficulty ON challenges(difficulty);
CREATE INDEX idx_challenges_points ON challenges(points);

-- Comments
COMMENT ON TABLE challenges IS 'CTF challenges with metadata and configuration';
COMMENT ON COLUMN challenges.flag_template IS 'Template for dynamic flag generation per user';
COMMENT ON COLUMN challenges.hints IS 'JSON array of hint strings';

-- ============================================================================
-- USER_CHALLENGES TABLE
-- ============================================================================
-- Tracks each user's progress on individual challenges
CREATE TABLE user_challenges (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(100) NOT NULL,  -- References user from main system
    challenge_id VARCHAR(50) NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    flag VARCHAR(500),  -- User-specific generated flag
    state VARCHAR(20) NOT NULL DEFAULT 'not_started' 
        CHECK (state IN ('not_started', 'in_progress', 'solved')),
    started_at TIMESTAMP,
    solved_at TIMESTAMP,
    attempts INTEGER DEFAULT 0 CHECK (attempts >= 0),
    hints_used INTEGER DEFAULT 0 CHECK (hints_used >= 0),
    points_earned INTEGER DEFAULT 0 CHECK (points_earned >= 0),
    points_spent INTEGER DEFAULT 0 CHECK (points_spent >= 0),  -- On hints
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    -- Ensure one record per user-challenge combination
    UNIQUE(user_id, challenge_id)
);

-- Indexes for performance
CREATE INDEX idx_user_challenges_user ON user_challenges(user_id);
CREATE INDEX idx_user_challenges_challenge ON user_challenges(challenge_id);
CREATE INDEX idx_user_challenges_state ON user_challenges(state);
CREATE INDEX idx_user_challenges_solved ON user_challenges(user_id, solved_at) WHERE solved_at IS NOT NULL;

-- Comments
COMMENT ON TABLE user_challenges IS 'Tracks individual user progress on each challenge';
COMMENT ON COLUMN user_challenges.flag IS 'Dynamically generated flag specific to this user';
COMMENT ON COLUMN user_challenges.points_spent IS 'Points spent on hints for this challenge';

-- ============================================================================
-- SOLVES TABLE
-- ============================================================================
-- Records each successful challenge solve with timing information
CREATE TABLE solves (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(100) NOT NULL,
    challenge_id VARCHAR(50) NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    solve_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    time_taken INTEGER,  -- Seconds from start to solve
    points INTEGER NOT NULL CHECK (points >= 0),
    first_blood BOOLEAN DEFAULT FALSE,  -- First person to solve this challenge
    
    -- Ensure one solve per user-challenge
    UNIQUE(user_id, challenge_id)
);

-- Indexes for leaderboard and analytics
CREATE INDEX idx_solves_user ON solves(user_id);
CREATE INDEX idx_solves_challenge ON solves(challenge_id);
CREATE INDEX idx_solves_time ON solves(solve_time DESC);
CREATE INDEX idx_solves_first_blood ON solves(challenge_id, solve_time) WHERE first_blood = TRUE;

-- Comments
COMMENT ON TABLE solves IS 'Records all successful challenge solves';
COMMENT ON COLUMN solves.first_blood IS 'TRUE if this was the first solve for this challenge';
COMMENT ON COLUMN solves.time_taken IS 'Time in seconds from challenge start to solve';

-- ============================================================================
-- HINTS_USED TABLE
-- ============================================================================
-- Tracks hint usage by users for penalty calculation
CREATE TABLE hints_used (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(100) NOT NULL,
    challenge_id VARCHAR(50) NOT NULL REFERENCES challenges(id) ON DELETE CASCADE,
    hint_level INTEGER NOT NULL CHECK (hint_level > 0),  -- Which hint (1, 2, 3, etc.)
    points_spent INTEGER NOT NULL CHECK (points_spent >= 0),
    used_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    
    -- Prevent unlocking the same hint twice
    UNIQUE(user_id, challenge_id, hint_level)
);

-- Indexes for analytics
CREATE INDEX idx_hints_user ON hints_used(user_id);
CREATE INDEX idx_hints_challenge ON hints_used(challenge_id);
CREATE INDEX idx_hints_time ON hints_used(used_at DESC);

-- Comments
COMMENT ON TABLE hints_used IS 'Tracks which hints users have unlocked and their cost';
COMMENT ON COLUMN hints_used.hint_level IS 'Sequential hint number (1 for first hint, 2 for second, etc.)';

-- ============================================================================
-- ACHIEVEMENTS TABLE
-- ============================================================================
-- Records user achievements and badges earned
CREATE TABLE achievements (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(100) NOT NULL,
    achievement_key VARCHAR(100) NOT NULL,  -- Unique identifier for the achievement type
    earned_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    points_awarded INTEGER DEFAULT 0 CHECK (points_awarded >= 0),
    metadata TEXT,  -- JSON for additional achievement context
    
    -- Prevent earning same achievement twice
    UNIQUE(user_id, achievement_key)
);

-- Indexes
CREATE INDEX idx_achievements_user ON achievements(user_id);
CREATE INDEX idx_achievements_key ON achievements(achievement_key);
CREATE INDEX idx_achievements_time ON achievements(earned_at DESC);

-- Comments
COMMENT ON TABLE achievements IS 'User achievements and badges earned during CTF';
COMMENT ON COLUMN achievements.achievement_key IS 'Unique key like "first_blood", "category_master", "speed_demon"';
COMMENT ON COLUMN achievements.metadata IS 'JSON data with achievement-specific context';

-- ============================================================================
-- LEADERBOARD TABLE (Materialized View)
-- ============================================================================
-- Aggregated leaderboard data for performance
CREATE TABLE leaderboard (
    user_id VARCHAR(100) PRIMARY KEY,
    username VARCHAR(100) NOT NULL,
    total_points INTEGER DEFAULT 0 CHECK (total_points >= 0),
    challenges_solved INTEGER DEFAULT 0 CHECK (challenges_solved >= 0),
    hints_used INTEGER DEFAULT 0 CHECK (hints_used >= 0),
    achievements_earned INTEGER DEFAULT 0 CHECK (achievements_earned >= 0),
    last_solve_time TIMESTAMP,
    rank INTEGER,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for leaderboard queries
CREATE INDEX idx_leaderboard_points ON leaderboard(total_points DESC);
CREATE INDEX idx_leaderboard_rank ON leaderboard(rank);
CREATE INDEX idx_leaderboard_last_solve ON leaderboard(last_solve_time DESC);

-- Comments
COMMENT ON TABLE leaderboard IS 'Materialized leaderboard view for performance';
COMMENT ON COLUMN leaderboard.rank IS 'User rank based on points and solve time tiebreaker';

-- ============================================================================
-- FUNCTIONS AND TRIGGERS
-- ============================================================================

-- Function to update timestamps
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Triggers for automatic timestamp updates
CREATE TRIGGER update_challenges_updated_at
    BEFORE UPDATE ON challenges
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_user_challenges_updated_at
    BEFORE UPDATE ON user_challenges
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_leaderboard_updated_at
    BEFORE UPDATE ON leaderboard
    FOR EACH ROW
    EXECUTE FUNCTION update_updated_at_column();

-- ============================================================================
-- HELPER VIEWS
-- ============================================================================

-- View: Challenge statistics
CREATE OR REPLACE VIEW challenge_stats AS
SELECT 
    c.id,
    c.name,
    c.category,
    c.difficulty,
    c.points,
    COUNT(DISTINCT s.user_id) as solve_count,
    AVG(s.time_taken) as avg_solve_time,
    MIN(s.solve_time) as first_solve_time,
    COUNT(DISTINCT uc.user_id) as attempt_count
FROM challenges c
LEFT JOIN solves s ON c.id = s.challenge_id
LEFT JOIN user_challenges uc ON c.id = uc.challenge_id
GROUP BY c.id, c.name, c.category, c.difficulty, c.points;

COMMENT ON VIEW challenge_stats IS 'Aggregated statistics for each challenge';

-- View: User statistics
CREATE OR REPLACE VIEW user_stats AS
SELECT 
    uc.user_id,
    COUNT(DISTINCT uc.challenge_id) as challenges_attempted,
    COUNT(DISTINCT CASE WHEN uc.state = 'solved' THEN uc.challenge_id END) as challenges_solved,
    SUM(uc.points_earned) as total_points,
    SUM(uc.points_spent) as total_points_spent,
    SUM(uc.attempts) as total_attempts,
    COUNT(DISTINCT h.id) as total_hints_used,
    COUNT(DISTINCT a.id) as total_achievements
FROM user_challenges uc
LEFT JOIN hints_used h ON uc.user_id = h.user_id
LEFT JOIN achievements a ON uc.user_id = a.user_id
GROUP BY uc.user_id;

COMMENT ON VIEW user_stats IS 'Aggregated statistics for each user';

-- ============================================================================
-- SAMPLE QUERIES (For Documentation)
-- ============================================================================

-- Get user's active challenges:
-- SELECT c.* FROM challenges c
-- JOIN user_challenges uc ON c.id = uc.challenge_id
-- WHERE uc.user_id = 'user123' AND uc.state = 'in_progress';

-- Get leaderboard with tiebreakers:
-- SELECT * FROM leaderboard
-- ORDER BY total_points DESC, last_solve_time ASC, challenges_solved DESC
-- LIMIT 100;

-- Get first blood solves:
-- SELECT s.*, c.name, c.points
-- FROM solves s
-- JOIN challenges c ON s.challenge_id = c.id
-- WHERE s.first_blood = TRUE
-- ORDER BY s.solve_time;

-- ============================================================================
-- END OF SCHEMA
-- ============================================================================
