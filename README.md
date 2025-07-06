# Charter Meals

**Version:** v1.5.0

[Charter Meals](https://chartermeals.com) is a web application for managing meal sign-ups for the [Princeton Charter Club](https://charterclub.org). This project is built with Flask and includes many features, as detailed below:

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

#### 6. Purge Tab (NEW)
- **Semester Cleanup:** Delete all users, reservations, and meal slots
- **Fresh Start:** Use at the beginning of each semester
- **Safety Warnings:** Multiple confirmation dialogs prevent accidental purges

### Semester Management Workflow

1. **Start of Semester:**
   - Use the **Purge** tab to clear all old data
   - Upload new user list via the **Users** tab
   - Configure reservation settings in the **Settings** tab
   - Update website content in the **Content** tab

2. **During Semester:**
   - Monitor reservations in the **Reservations** tab
   - Download CSV reports as needed
   - Manage users as they join/leave

3. **End of Semester:**
   - Download final CSV reports
   - Use **Purge** to prepare for next semester

### Content Management Best Practices

1. **Meal Rules:** Update rules in the Content tab when policies change
2. **Contact Info:** Keep kitchen manager contact information current
3. **Welcome Messages:** Customize messages for special events or announcements
4. **Feedback Links:** Update feedback form URLs as needed

### Security Notes

- **Password Security:** Use strong passwords for admin accounts
- **Access Control:** Limit admin access to trusted individuals
- **Data Backup:** Regularly download CSV reports for backup
- **Purge Safety:** The purge function cannot be undone - use with caution

### Technical Support

- **Database Issues:** Use the `migrate-db` command to update schema
- **Cache Issues:** The system automatically clears cache during purge
- **Performance:** The system uses caching for optimal performance

## Installation

1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Create a `secrets.txt` file with a secure secret key
4. Initialize the database: `flask init-db`
5. Run the application: `flask run`

## Dependencies

See `requirements.txt` for the complete list of Python packages required.

## License

This project is proprietary software for the Princeton Charter Club.
