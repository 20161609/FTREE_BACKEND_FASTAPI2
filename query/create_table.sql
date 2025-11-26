-- Auth table
CREATE TABLE auth (
    uid SERIAL PRIMARY KEY,
    username VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    create_time TIMESTAMP DEFAULT NOW(),
    update_time TIMESTAMP DEFAULT NOW(),
    useai BOOLEAN DEFAULT FALSE
);

-- Role table
CREATE TABLE role (
    role_id SERIAL PRIMARY KEY,
    role_name VARCHAR(50) UNIQUE NOT NULL
);

-- EmailVerification table
CREATE TABLE email_verification (
    code VARCHAR(255) PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    verified TIMESTAMP DEFAULT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Branch table
CREATE TABLE branch (
    bid SERIAL PRIMARY KEY,
    uid INTEGER NOT NULL,
    path VARCHAR(255) NOT NULL,
    FOREIGN KEY (uid) REFERENCES auth(uid)
);

-- Transaction table
CREATE TABLE transaction (
    tid SERIAL PRIMARY KEY,
    t_date DATE NOT NULL,
    branch VARCHAR(255) NOT NULL,
    cashflow INTEGER NOT NULL,
    description TEXT,
    c_date TIMESTAMP DEFAULT NOW(),
    uid INTEGER NOT NULL,
    receipt VARCHAR(255),
    FOREIGN KEY (uid) REFERENCES auth(uid)
);

-- UserRole table
CREATE TABLE user_role (
    user_role_id SERIAL PRIMARY KEY,
    uid INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    FOREIGN KEY (uid) REFERENCES auth(uid),
    FOREIGN KEY (role_id) REFERENCES role(role_id)
);

-- Token table
CREATE TABLE token (
    token_id SERIAL PRIMARY KEY,
    uid INTEGER NOT NULL,
    access_token TEXT NOT NULL,
    refresh_token TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    expires_at TIMESTAMP NOT NULL,
    FOREIGN KEY (uid) REFERENCES auth(uid)
);
