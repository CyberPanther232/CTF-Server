FROM python:3.13-slim

# Set working directory
WORKDIR /app

# Install system dependencies (git)
RUN apt-get update \
	&& apt-get install -y --no-install-recommends git \
	&& rm -rf /var/lib/apt/lists/*

# Environment tweaks for reliable Python behavior
ENV PYTHONUNBUFFERED=1 \
	PYTHONDONTWRITEBYTECODE=1 \
	PYTHONPATH=/app

# Install Python dependencies first for better Docker layer caching
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy the rest of the application (respects .dockerignore)
COPY . /app

# Expose the port the app runs on
EXPOSE 5000

# Run the application
CMD ["python3", "-m", "app"]