# CertiVault — PHP 8.2 + Apache, serving only public/.
# Used by docker-compose.yml (app + MariaDB). See docs/10_RUNNING_AND_DEMO_GUIDE.md.
FROM php:8.2-apache

RUN apt-get update \
 && apt-get install -y --no-install-recommends libpng-dev libjpeg62-turbo-dev libfreetype6-dev libzip-dev unzip git \
 && docker-php-ext-configure gd --with-jpeg --with-freetype \
 && docker-php-ext-install pdo_mysql gd zip \
 && a2enmod rewrite headers \
 && rm -rf /var/lib/apt/lists/*

COPY --from=composer:2 /usr/bin/composer /usr/bin/composer

# Document root = public/ ; .htaccess files honoured.
ENV APACHE_DOCUMENT_ROOT=/var/www/html/public
RUN sed -ri 's!/var/www/html!${APACHE_DOCUMENT_ROOT}!g' /etc/apache2/sites-available/*.conf \
 && sed -ri 's!AllowOverride None!AllowOverride All!g' /etc/apache2/apache2.conf \
 && printf 'expose_php = Off\ndisplay_errors = Off\nlog_errors = On\nupload_max_filesize = 8M\npost_max_size = 10M\n' > /usr/local/etc/php/conf.d/certivault.ini

WORKDIR /var/www/html
COPY composer.json composer.lock ./
RUN composer install --no-dev --no-interaction --no-progress --prefer-dist
COPY . .
RUN mkdir -p private_data/uploads private_data/mail private_data/pins public/qrcodes public/checkpoints \
 && chown -R www-data:www-data private_data public/qrcodes public/checkpoints src/utils/phpqrcode/cache
