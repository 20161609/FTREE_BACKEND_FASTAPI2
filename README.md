# 🌳 Finance Tree Backend - FastAPI Framework

Welcome to the **Finance Tree** backend service, a powerful and scalable platform for managing group-based finances efficiently. This backend is built using **FastAPI**, ensuring both speed and performance while handling various financial operations.

## ✨ Key Features

- **🔒 User Authentication**: Secure login, signup, and token management using JWT.
- **🏷️ Branch Management**: Create, edit, and delete financial branches to organize your data.
- **💰 Transaction Handling**: Comprehensive APIs for managing your financial transactions.
- **🧾 Receipt Management**: Store and manage transaction receipts with support for Firebase image handling.
- **🔑 Secure Token Management**: Robust handling of access and refresh tokens for user authentication.

## 📦 Technical Stack

- **FastAPI**: High-performance backend framework.
- **PostgreSQL**: Reliable and scalable database solution.
- **Firebase**: For authentication and receipt storage.
- **Docker**: Containerization for easy deployment.
- **Azure**: Cloud platform for hosting and deployment.

## 📂 Project Structure

Here's how the project is organized for clarity and modular development:

```
/app
├── db/          # Database models and initialization code
├── route/       # API route definitions (authentication, branches, transactions, etc.)
├── lib/         # Utility functions and helpers
├── firebase/    # Firebase integration and storage handling
└── main.py      # Entry point of the FastAPI application
```

## 🚀 API Flow

1. **🔑 User Authentication**: Users can sign up, verify their email, log in, and handle tokens with ease.
2. **📊 Branch & Transaction Management**: Organize your finances by creating and managing branches and transactions.
3. **🖼️ File Upload**: Upload and link receipts to your transactions, stored securely in Firebase Storage.
4. **⚠️ Error Handling**: Provides meaningful error messages and status codes for a smooth experience.

## 🔐 Security and Privacy

This backend service depends on sensitive information stored in environment variables:
- **Database Credentials**
- **JWT Keys**
- **Firebase Configuration**

⚠️ **Without the proper `.env` file, the service cannot be used.** For security reasons, we do not share details on how to configure these settings externally.

## 🌐 Deployment

The application is containerized with Docker for easy deployment to cloud platforms like **Azure**. We've included a `docker-compose.yml` file to streamline the setup process for both development and production environments.

### 🛠 Prerequisites

- **Docker**: Ensure Docker is installed on your system.
- **PostgreSQL**: Initialize the database using the provided `init.sql` file.
- **Environment Variables**: Set up the required `.env` file with all necessary configurations.

## 📋 Usage Instructions

The service is designed for environments that have the appropriate configuration in place. Please ensure you have access to the `.env` file before attempting to run the backend.