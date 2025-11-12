# Multi-stage build for optimized PHP Laravel application
# Stage 1: Build dependencies
FROM php:8.3-fpm AS builder

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    unzip \
    zip \
    && rm -rf /var/lib/apt/lists/*

# Install PHP extensions
# No PHP extensions needed for composer-only build stage

# Get latest Composer
COPY --from=composer:latest /usr/bin/composer /usr/bin/composer

# Set working directory
WORKDIR /var/www/html

# Copy composer files only to leverage layer caching
COPY composer.json composer.lock ./

# Install dependencies (production optimized)
RUN COMPOSER_ALLOW_SUPERUSER=1 composer install \
    --no-dev \
    --prefer-dist \
    --no-interaction \
    --no-progress \
    --no-plugins \
    --no-scripts \
    --optimize-autoloader

# Stage 2: Production runtime
FROM php:8.3-fpm

# Install runtime dependencies only
RUN apt-get update && apt-get install -y \
    gnupg2 \
    apt-transport-https \
    ca-certificates \
    libpng-dev \
    libonig-dev \
    libxml2-dev \
    unixodbc-dev \
    build-essential \
    autoconf \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Microsoft ODBC driver (msodbcsql18) for SQL Server
RUN set -eux; \
    curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-archive-keyring.gpg; \
    echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-archive-keyring.gpg] https://packages.microsoft.com/debian/12/prod bookworm main" > /etc/apt/sources.list.d/microsoft-prod.list; \
    apt-get update; \
    ACCEPT_EULA=Y apt-get install -y msodbcsql18; \
    rm -rf /var/lib/apt/lists/*

# Install PHP extensions
# Core PHP extensions
RUN docker-php-ext-install pdo mbstring exif pcntl bcmath gd

# Install and enable SQL Server extensions
RUN pecl install sqlsrv pdo_sqlsrv \
    && docker-php-ext-enable sqlsrv pdo_sqlsrv

# Set working directory
WORKDIR /var/www/html

# Copy dependencies from builder
COPY --from=builder /var/www/html/vendor ./vendor

# Copy application files
COPY . .

# Set proper permissions
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html/storage \
    && chmod -R 755 /var/www/html/bootstrap/cache

# Optimize Laravel for production
RUN php artisan config:cache || true \
    && php artisan route:cache || true \
    && php artisan view:cache || true

# Expose port 9000 for PHP-FPM
EXPOSE 9000

# Use PHP-FPM as the default command
CMD ["php-fpm"]
