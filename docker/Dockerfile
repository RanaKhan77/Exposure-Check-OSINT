# =============================================================================
# Exposure-Check-OSINT — single-container PHP 8.3 Apache image
# =============================================================================
# Own-use Community Edition: Apache + mod_php + SQLite. One container, no
# nginx/mysql/redis required. Put it behind your own TLS reverse proxy if you
# expose it remotely (see docs/SELF-HOSTING.md).
#
# Build:  docker build -t exposure-check-osint -f docker/Dockerfile .
# Run:    docker run -p 8080:80 -v ec-data:/var/www/html/database \
#             -v ec-storage:/var/www/html/storage exposure-check-osint
# =============================================================================

FROM php:8.3-apache

LABEL org.opencontainers.image.title="Exposure-Check-OSINT"
LABEL org.opencontainers.image.description="Self-hosted personal exposure checker (email/username/phone/password/IP) — 19 keyless OSINT sources, no AI"
LABEL org.opencontainers.image.version="1.1.0"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/RanaKhan77/Exposure-Check-OSINT"

# ---- PHP extensions ---------------------------------------------------------
# pdo_sqlite + sqlite3 are compiled into the official php image by default
# (verified: `docker run --rm php:8.3-apache php -m | grep -i sqlite`).
# unzip: composer needs zip extraction for dist installs.
RUN apt-get update && apt-get install -y --no-install-recommends unzip \
    && rm -rf /var/lib/apt/lists/* \
    && php -m | grep -qi pdo_sqlite && php -m | grep -qi sqlite3

# ---- Apache: docroot -> /public, mod_rewrite, AllowOverride ----------------
ENV APACHE_DOCUMENT_ROOT=/var/www/html/public
RUN a2enmod rewrite headers \
    && sed -ri -e 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf /etc/apache2/apache2.conf 2>/dev/null \
    && printf '<Directory /var/www/html/public>\n    AllowOverride All\n    Require all granted\n</Directory>\n' \
        > /etc/apache2/conf-available/docroot.conf \
    && a2enconf docroot

WORKDIR /var/www/html

# ---- Composer layer (vendor cached separately from app code) ---------------
COPY --from=composer:2 /usr/bin/composer /usr/bin/composer
COPY composer.json composer.lock* ./
RUN composer install --no-dev --no-scripts --no-autoloader --prefer-dist

# ---- Application code ------------------------------------------------------
COPY . .
RUN composer dump-autoload --optimize \
    && php artisan config:clear || true

# ---- Runtime: storage dirs, sqlite file, permissions ------------------------
RUN mkdir -p storage/framework/{cache/data,sessions,views} storage/logs storage/app/maigret storage/app/env \
    && touch storage/app/database.sqlite \
    && chown -R www-data:www-data /var/www/html

COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
