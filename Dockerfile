# Use image python:3.12.2-slim
FROM python:3.12.2-slim

# Setting Work Directory
WORKDIR /app

# Copy requirements.txt file to container and install required packages
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy all other application files to work directory
COPY . /app

# Expose Cloud Run default port (8080)
EXPOSE 8080

# Start the application on fixed port 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
