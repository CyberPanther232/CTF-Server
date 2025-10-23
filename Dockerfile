FROM python:3.13-slim

# Set working directory
WORKDIR /app

# Install system dependencies (git)
RUN apt-get update \
	&& apt-get install -y --no-install-recommends git \
	&& rm -rf /var/lib/apt/lists/*

# Copy application files
COPY app/ /app/
COPY requirements.txt /app/requirements.txt
COPY main.py /app/main.py

# Install dependencies
RUN pip install --no-cache-dir -r /app/requirements.txt

# Expose the port the app runs on
EXPOSE 443

# Run the application
CMD ["python3", "-m", "app"]