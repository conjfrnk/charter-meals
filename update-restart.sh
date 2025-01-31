#!/bin/sh

# Eventually this script will be changed/removed in favor of running the
# newest release. But for now it's the easiest option

cd /var/www/htdocs/www.chartermeals.com

# Pull the latest changes from the Git repository
/usr/local/bin/git fetch origin
LOCAL=$(/usr/local/bin/git rev-parse @)
REMOTE=$(/usr/local/bin/git rev-parse @{u})

# Check if there are updates in the remote repository
if [ "$LOCAL" != "$REMOTE" ]; then
    echo "New changes detected. Pulling changes..."
    /usr/local/bin/git pull origin main

    echo "Fixing ownership..."
    chown -R connor /var/www/htdocs/www.chartermeals.com

    echo "Restarting Gunicorn for app and server..."
    rcctl restart gunicorn_charter
else
    echo "No changes detected. No restart needed."
fi
