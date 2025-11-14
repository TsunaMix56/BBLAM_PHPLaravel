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

# Install runtime dependencies for MySQL
RUN apt-get update && apt-get install -y \
    libpng-dev \
    libonig-dev \
    libxml2-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install MySQL client and dependencies
RUN apt-get update && apt-get install -y \
    default-mysql-client \
    && rm -rf /var/lib/apt/lists/*

# Install PHP extensions for MySQL
RUN docker-php-ext-install pdo pdo_mysql mysqli mbstring exif pcntl bcmath gd

# Set working directory
WORKDIR /var/www/html

# Copy dependencies from builder
COPY --from=builder /var/www/html/vendor ./vendor

# Copy application files
COPY . .

# Copy custom PHP-FPM configuration
COPY docker/php/www.conf /usr/local/etc/php-fpm.d/www.conf

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
