# Site configuration for example.com
# Test fixture for stop-bots project

server {
    listen       80;
    listen       [::]:80;
    server_name  example.com www.example.com;

    access_log  /var/log/nginx/example.com.access.log;
    error_log   /var/log/nginx/example.com.error.log;

    root        /var/www/example.com/html;
    index       index.html;

    # Bot protection settings
    # These would be managed by stop-bots
    
    location / {
        try_files $uri $uri/ =404;
    }

    location /wp-admin/ {
        # Additional protection for admin area
        allow 192.168.1.0/24;
        deny all;
    }

    location = /favicon.ico {
        log_not_found off;
        access_log off;
    }

    location = /robots.txt {
        allow all;
        log_not_found off;
        access_log off;
    }

    # Deny access to hidden files
    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}
