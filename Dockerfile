FROM python:3.9-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    wget \
    gnupg \
    unzip \
    curl \
    xvfb \
    libxss1 \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdbus-1-3 \
    libgdk-pixbuf2.0-0 \
    libnspr4 \
    libnss3 \
    libx11-xcb1 \
    libxcomposite1 \
    libxcursor1 \
    libxdamage1 \
    libxfixes3 \
    libxi6 \
    libxrandr2 \
    libxtst6 \
    xdg-utils \
    && rm -rf /var/lib/apt/lists/*


# Install Chrome
RUN wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google-chrome.list \
    && apt-get update \
    && apt-get install -y google-chrome-stable \
    && rm -rf /var/lib/apt/lists/*

# Install ChromeDriver manually
RUN wget -q https://chromedriver.storage.googleapis.com/114.0.5735.90/chromedriver_linux64.zip \
    && unzip chromedriver_linux64.zip -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/chromedriver \
    && rm chromedriver_linux64.zip


# Create app directory
WORKDIR /app


# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create directories first with explicit permissions
RUN mkdir -p /app/data /app/models \
    && chmod -R 755 /app/data /app/models

# Debug directory creation
RUN echo "Created directories:" && ls -la /app

# Copy data files with verification
COPY data/tld_freq.csv /app/data/tld_freq.csv
RUN test -f /app/data/tld_freq.csv || (echo "Failed to copy tld_freq.csv" && exit 1)
RUN echo "Data directory contents:" && ls -la /app/data

# Copy model files with verification
COPY models/model_RF.pkl /app/models/model_RF.pkl
RUN test -f /app/models/model_RF.pkl || (echo "Failed to copy model_RF.pkl" && exit 1)
RUN echo "Models directory contents:" && ls -la /app/models


# Copy the rest of the application
COPY . .

# Ensure directories exist and have correct permissions
RUN mkdir -p /app/data /app/models \
    && chmod -R 755 /app/data /app/models

# Create a symbolic link for ChromeDriver
RUN ln -sf /usr/local/bin/chromedriver /usr/bin/chromedriver

# Set display port for Xvfb (needed for Chrome in headless mode)
ENV DISPLAY=:99

# Add a healthcheck to ensure the app is running correctly
# HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
#     CMD python /app/healthcheck.py || exit 1

# Expose port
EXPOSE 7860

# Start the app with Xvfb support
CMD ["sh", "-c", "Xvfb :99 -screen 0 1280x1024x24 -ac +extension GLX +render -noreset & python Webapp/app.py"]