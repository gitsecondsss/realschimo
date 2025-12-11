# Use lightweight PHP + Apache image (serves HTML & PHP)
FROM php:8.2-apache

# Copy site files into Apache web root
COPY . /var/www/html

# Enable .htaccess + rewrites (optional)
RUN a2enmod rewrite

# Fix permissions on the app directory
RUN chown -R www-data:www-data /var/www/html

# -------------------------
# ENTRYPOINT: Fix /data perms (Railway volume)
# -------------------------
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

ENTRYPOINT ["docker-entrypoint.sh"]

# Apache starts normally after the entrypoint
CMD ["apache2-foreground"]

# Expose HTTP
EXPOSE 80
