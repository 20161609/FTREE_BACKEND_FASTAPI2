-- -- Check if the user already exists before creating
-- DO
-- $$
-- BEGIN
--     IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = ${DB_USER}) THEN
--         CREATE USER ${DB_USER} WITH PASSWORD ${DB_PASSWORD};
--     END IF;
-- END
-- $$;

-- -- Check if the database already exists before creating
-- DO
-- $$
-- BEGIN
--     IF NOT EXISTS (SELECT 1 FROM pg_database WHERE datname = '${DB_NAME}') THEN
--         CREATE DATABASE ${DB_NAME};
--     END IF;
-- END
-- $$;

-- -- Grant privileges on the database to the user
-- GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};

-- -- Create Auth table
-- CREATE TABLE IF NOT EXISTS auth (
--     uid SERIAL PRIMARY KEY,
--     username VARCHAR(255) NOT NULL,
--     email VARCHAR(255) UNIQUE NOT NULL,
--     password VARCHAR(255) NOT NULL,
--     is_active BOOLEAN DEFAULT TRUE,
--     create_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
--     update_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
--     useai BOOLEAN DEFAULT FALSE
-- );

-- -- Create Role table
-- CREATE TABLE IF NOT EXISTS role (
--     role_id SERIAL PRIMARY KEY,
--     role_name VARCHAR(50) UNIQUE NOT NULL
-- );

-- -- Create EmailVerification table
-- CREATE TABLE IF NOT EXISTS email_verification (
--     code VARCHAR(255) PRIMARY KEY,
--     email VARCHAR(255) UNIQUE NOT NULL,
--     verified TIMESTAMP,
--     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
-- );

-- -- Create Token table
-- CREATE TABLE IF NOT EXISTS token (
--     token_id SERIAL PRIMARY KEY,
--     uid INTEGER NOT NULL,
--     access_token TEXT NOT NULL,
--     refresh_token TEXT,
--     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
--     expires_at TIMESTAMP NOT NULL,
--     CONSTRAINT token_uid_fkey FOREIGN KEY (uid) REFERENCES auth(uid) ON DELETE CASCADE
-- );

-- -- Create Branch table
-- CREATE TABLE IF NOT EXISTS branch (
--     bid SERIAL PRIMARY KEY,
--     uid INTEGER NOT NULL,
--     path VARCHAR(255) NOT NULL,
--     CONSTRAINT branch_uid_fkey FOREIGN KEY (uid) REFERENCES auth(uid) ON DELETE CASCADE
-- );

-- -- Create Transaction table
-- CREATE TABLE IF NOT EXISTS transaction (
--     tid SERIAL PRIMARY KEY,
--     t_date DATE NOT NULL,
--     branch VARCHAR(255) NOT NULL,
--     cashflow INTEGER NOT NULL,
--     description TEXT,
--     c_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
--     uid INTEGER NOT NULL,
--     receipt VARCHAR(255),
--     CONSTRAINT transaction_uid_fkey FOREIGN KEY (uid) REFERENCES auth(uid) ON DELETE CASCADE
-- );

-- -- Create UserRole table for many-to-many relationship between users and roles
-- CREATE TABLE IF NOT EXISTS user_role (
--     user_role_id SERIAL PRIMARY KEY,
--     uid INTEGER NOT NULL,
--     role_id INTEGER NOT NULL,
--     CONSTRAINT user_role_uid_fkey FOREIGN KEY (uid) REFERENCES auth(uid) ON DELETE CASCADE,
--     CONSTRAINT user_role_role_id_fkey FOREIGN KEY (role_id) REFERENCES role(role_id) ON DELETE CASCADE
-- );

-- -- init.sql