# Expense Splitter

A web application for managing and splitting expenses among groups of people.

## Features

- User authentication (regular and Google OAuth)
- Create and manage expense groups
- Add and track expenses
- Split expenses equally or unequally
- View balances and settlements
- Responsive design

## Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd expense-splitter
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Set up environment variables:
   - Copy `.env.example` to `.env`
   - Fill in the required environment variables:
     - `SECRET_KEY`: A secure random string for Flask session management
     - `GOOGLE_OAUTH_CLIENT_ID`: Your Google OAuth client ID
     - `GOOGLE_OAUTH_CLIENT_SECRET`: Your Google OAuth client secret

5. Initialize the database:
```bash
python app.py
```

6. Run the application:
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## Environment Variables

- `SECRET_KEY`: Flask secret key for session management
- `GOOGLE_OAUTH_CLIENT_ID`: Google OAuth2 client ID
- `GOOGLE_OAUTH_CLIENT_SECRET`: Google OAuth2 client secret

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details. 