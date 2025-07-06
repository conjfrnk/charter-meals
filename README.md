# Charter Meals

**Version:** v2.0.0

[Charter Meals](https://chartermeals.com) is a web application for managing meal sign-ups for the [Princeton Charter Club](https://charterclub.org). This project is built with Flask and includes many features, as detailed below:

## 🚀 New in v2.0.0

### Security & Performance Improvements
- **Enhanced Input Validation**: All user inputs are now properly validated and sanitized
- **Session Security**: 8-hour session timeout with automatic logout
- **Database Security**: Improved error handling and connection management
- **Rate Limiting**: Enhanced protection against brute force attacks
- **Error Handling**: Comprehensive error handling with user-friendly messages
- **Performance**: Optimized database queries and caching strategies

### Future-Proofing Features
- **Version Pinning**: All dependencies are now version-pinned for stability
- **Database Migrations**: Improved migration system for schema updates
- **Logging**: Enhanced logging for better debugging and monitoring
- **Edge Case Handling**: Better handling of edge cases and error conditions

## Features

- **User Login:** Users sign in with their NetID and can reserve meals.
- **Guest Login:** Limited-access guest login is available.
- **Meal Sign-ups:** Users may sign up for meals (with limits to ensure fairness).
- **Admin Dashboard:** Comprehensive admin interface for managing users, reservations, settings, and website content.
- **Content Management:** Dynamic website content management through the admin interface.
- **Semester Purge:** One-click semester cleanup functionality.
- **CSV Downloads:** Reservation data is downloadable in CSV format.
- **Responsive Design:** The interface works well on both desktop and mobile devices.
- **Security & Performance:** Built-in CSRF protection, rate limiting, and a strict Content Security Policy.

## 🔒 Security Features

### Authentication & Authorization
- **Session Management**: 8-hour session timeout with automatic logout
- **Input Validation**: All inputs are validated and sanitized
- **CSRF Protection**: Built-in CSRF protection on all forms
- **Rate Limiting**: Protection against brute force attacks
- **Secure Headers**: Content Security Policy and other security headers

### Data Protection
- **Password Hashing**: All passwords are hashed using pbkdf2:sha256
- **SQL Injection Protection**: Parameterized queries throughout
- **XSS Protection**: Input sanitization and output encoding
- **Session Security**: Secure, HTTP-only cookies with SameSite protection

## Admin Instructions

### Getting Started

1. **Default Admin Account:**
   - Username: `admin`
   - Password: `admin`
   - **Important:** Change this password immediately after first login

2. **Accessing the Admin Dashboard:**
   - Navigate to `/admin/login`
   - Use your admin credentials to log in

### Admin Dashboard Tabs

#### 1. Reservations Tab
- **Download CSV:** Download reservation data for specific weeks or all reservations
- **Daily Management:** View and manage reservations for each day of the week
- **Manual Reservations:** Add users to meal slots manually (bypasses capacity limits)

#### 2. Users Tab
- **Upload Users:** Upload CSV files with NetID and name pairs
- **Bulk Operations:** Add or remove multiple users at once
- **Individual Management:** Add or remove individual users
- **User Overview:** View all users and their current reservations

#### 3. Admins Tab
- **Admin Management:** Add or remove admin accounts
- **Super Admin:** Only the default "admin" account can add/remove other admins

#### 4. Settings Tab
- **Reservation Mode:** Choose between automatic, manually open, or manually closed
- **Automatic Settings:** Configure when reservations open and close
- **Time Zones:** All times are in US Eastern Time

#### 5. Content Tab (NEW)
- **Website Content Management:** Edit all text content on the main meal signup page
- **Dynamic Content:** Change welcome messages, meal rules, contact info, and more
- **No Code Editing:** All content changes can be made through the admin interface

**Available Content Keys:**
- `welcome_header`: Main page header
- `welcome_message`: Welcome message below header
- `contact_info`: Contact information text
- `feedback_link`: Feedback form URL
- `feedback_text`: Feedback text with link
- `meal_rules_title`: Title for meal rules section
- `meal_rules`: Meal signup rules (one rule per line, separated by \n)

#### 6. Purge Tab (UPDATED)
- **Archive & Purge:** Archive all data before deletion for sentimental purposes
- **Download Archive:** Download a CSV file containing all archived data
- **Clear Archive:** Remove archived data to free up storage space
- **Fresh Start:** Use at the beginning of each semester
- **Safety Warnings:** Multiple confirmation dialogs prevent accidental purges

### Semester Management Workflow

1. **Start of Semester:**
   - Use the **Purge** tab to archive and clear all old data
   - Download the archive file for sentimental purposes (optional)
   - Upload new user list via the **Users** tab
   - Configure reservation settings in the **Settings** tab
   - Update website content in the **Content** tab

2. **During Semester:**
   - Monitor reservations in the **Reservations** tab
   - Download CSV reports as needed
   - Manage users as they join/leave

3. **End of Semester:**
   - Download final CSV reports
   - Use **Purge** to archive and prepare for next semester
   - Consider downloading the archive file for sentimental purposes

### Content Management Best Practices

1. **Meal Rules:** Update rules in the Content tab when policies change
2. **Contact Info:** Keep kitchen manager contact information current
3. **Welcome Messages:** Customize messages for special events or announcements
4. **Feedback Links:** Update feedback form URLs as needed

### Security Notes

- **Password Security:** Use strong passwords for admin accounts
- **Access Control:** Limit admin access to trusted individuals
- **Data Backup:** Regularly download CSV reports for backup
- **Archive Safety:** Data is archived before deletion, but the purge function cannot be undone - use with caution
- **Session Timeout:** Sessions automatically expire after 8 hours for security

### Technical Support

- **Database Issues:** Use the `migrate-db` command to update schema
- **Cache Issues:** The system automatically clears cache during purge
- **Performance:** The system uses caching for optimal performance
- **Error Logs:** Check application logs for detailed error information

## 🛠️ Installation & Deployment

### Prerequisites
- Python 3.8 or higher
- Redis server (for rate limiting and caching)
- SQLite (included with Python)

### Installation

1. **Clone the repository:**
   ```bash
   git clone <repository-url>
   cd charter-meals
   ```

2. **Create virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Create secret key:**
   ```bash
   # Generate a secure secret key (at least 32 characters)
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```
   Create a `secrets.txt` file with the generated key.

5. **Initialize the database:**
   ```bash
   flask init-db
   ```

6. **Run the application:**
   ```bash
   flask run
   ```

### Production Deployment

1. **Set up Redis:**
   ```bash
   # Install Redis (Ubuntu/Debian)
   sudo apt-get install redis-server
   
   # Start Redis
   sudo systemctl start redis-server
   ```

2. **Configure environment:**
   ```bash
   export FLASK_ENV=production
   export FLASK_APP=app.py
   ```

3. **Run with Gunicorn:**
   ```bash
   gunicorn -w 4 -b 0.0.0.0:8000 app:app
   ```

### System Requirements

- **Memory:** Minimum 512MB RAM
- **Storage:** 1GB free space for database and logs
- **Network:** Internet access for external fonts and CDN resources

## 🔧 Troubleshooting

### Common Issues

1. **Database Connection Errors:**
   - Ensure the database directory has proper permissions
   - Check if SQLite is properly installed
   - Verify database file path in configuration

2. **Redis Connection Issues:**
   - Ensure Redis server is running: `redis-cli ping`
   - Check Redis configuration in app.py
   - Verify Redis port (default: 6379)

3. **Session Issues:**
   - Clear browser cookies and cache
   - Check if secret key is properly set
   - Verify session cookie settings

4. **Performance Issues:**
   - Check Redis cache status
   - Monitor database query performance
   - Review application logs for errors

### Logging

The application logs important events and errors. Check logs for:
- Database connection issues
- Authentication failures
- Cache errors
- General application errors

### Maintenance

- **Regular Backups:** Download CSV reports weekly
- **Database Maintenance:** Run `flask migrate-db` after updates
- **Cache Clearing:** System automatically clears cache during purge
- **Log Rotation:** Implement log rotation for production deployments

## 📋 Dependencies

### Core Dependencies
- **Flask 2.3+**: Web framework
- **Flask-WTF 1.1+**: CSRF protection and form handling
- **Flask-Limiter 3.4+**: Rate limiting
- **Flask-Talisman 1.0+**: Security headers
- **Redis 4.5+**: Caching and rate limiting storage
- **Flask-Compress 1.13+**: Response compression
- **Flask-Caching 2.0+**: Application caching
- **Gunicorn 21.0+**: WSGI server for production
- **Werkzeug 2.3+**: WSGI utilities

### Security Features
- CSRF protection on all forms
- Rate limiting for login attempts
- Secure session management
- Input validation and sanitization
- Content Security Policy headers

## 📄 License

This project is proprietary software for the Princeton Charter Club.

## 🤝 Contributing

For internal development and maintenance:
1. Follow the existing code style
2. Add comprehensive error handling
3. Update documentation for any new features
4. Test thoroughly before deployment
5. Consider security implications of changes

## 📞 Support

For technical support or questions:
- Check the troubleshooting section above
- Review application logs for error details
- Contact the development team for critical issues
