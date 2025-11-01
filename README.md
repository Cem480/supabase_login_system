# Supabase-Compatible Login System
## CS411 Software Architecture Design - Project 1


## ✨ **Features**

### Core Features 
- ✅ **Email/Password Authentication** - Traditional login with bcrypt password hashing
- ✅ **Protected Dashboard** - JWT-protected routes with session validation
- ✅ **Logout Functionality** - Single device and all devices logout
- ✅ **Comprehensive Error Handling** - User-friendly error messages
- ✅ **JWT Session Management** - Stateless authentication with database-backed sessions

### Enhanced Features
- ✅ **Client-Side Form Validation** - Real-time validation with visual feedback
- ✅ **Loading Indicators** - Smooth UX with loading states
- ✅ **"Remember Me" Functionality** - Extended sessions (30 days)
- ✅ **Password Strength Indicator** - Visual password strength meter
- ✅ **Responsive Design** - Mobile-friendly interface
- ✅ **Magic Link Login** - Passwordless authentication via email
- ✅ **OAuth Integration** - Google and GitHub social login

## 🛠️ **Technology Stack**

### Backend
- **Flask 3.0+** - Web framework
- **SQLAlchemy 2.0+** - ORM for PostgreSQL
- **Flask-Login** - Session management
- **Flask-WTF** - CSRF protection
- **Flask-Limiter** - Rate limiting
- **PyJWT** - JWT token handling
- **bcrypt** - Password hashing
- **psycopg2** - PostgreSQL driver
- **requests** - OAuth HTTP client
- **python-dotenv** - Environment variables

### Frontend
- **HTML5** - Semantic markup
- **CSS3** - Responsive styling (Grid + Flexbox)
- **Vanilla JavaScript** - No frameworks (lightweight)
- **Font Awesome** - Icons

### Database
- **PostgreSQL 15+** - Primary database
- **UUID** - Primary keys (Supabase standard)
- **JSONB** - Flexible metadata storage
- **Proper Indexing** - Optimized queries

---

## 🚀 **Setup Instructions**

### Prerequisites
- Python 3.9+
- PostgreSQL 15+
- pip (Python package manager)
- Virtual environment (recommended)

### 1. Clone or Extract Project

```bash
cd supabase_login
```

### 2. Create Virtual Environment

```bash
python -m venv venv

# On Windows
venv\Scripts\activate

# On macOS/Linux
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

### 4. Configure PostgreSQL

```bash
# Create database
createdb supabase_login

# Or using psql
psql -U postgres
CREATE DATABASE supabase_login;
\q
```

### 5. Set Environment Variables

Create a `.env` file in the project root:

```bash
# Flask Configuration
FLASK_APP=app.py
FLASK_ENV=development
SECRET_KEY=your-secret-key-here

# Database your db config
DATABASE_URL=postgresql://postgres:your_password@localhost:5432/supabase_login

# JWT
JWT_SECRET_KEY=your-jwt-secret-key

# OAuth (I put my own account infos please dont use it elswhere :))
GOOGLE_CLIENT_ID=your-google-client-id
GOOGLE_CLIENT_SECRET=your-google-client-secret
GITHUB_CLIENT_ID=your-github-client-id
GITHUB_CLIENT_SECRET=your-github-client-secret

# Email (Same as here)
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-app-password
```

### 6. Initialize Database

python init_db.py     

### 7. Run Application

```bash
python app.py

# Or using Flask CLI
flask run
```

The application will be available at `http://localhost:5000`

---

Note: maybe need to download email package seperately
pip install flask-mail


**Built with ❤️ for CS411 Software Architecture Design**
