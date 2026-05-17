# Hospital Management System (HMS)

A web-based Hospital Management System built with Flask, SQLite, and Tailwind CSS.

## Tech Stack
- **Backend:** Python + Flask
- **Database:** SQLite
- **Frontend:** Tailwind CSS (via CDN)
- **Auth:** bcrypt password hashing + Flask sessions

## Features
- Role-based login (Admin, Doctor, Receptionist, Nurse, Staff)
- User, Department, Doctor & Staff Management
- Patient Registration & Search
- Appointment Scheduling with double-booking prevention
- Medical Records (linked to completed appointments)
- Billing with Paid/Unpaid tracking

## Setup & Run
1. Clone the repo
   git clone https://github.com/thrishavc/HMS.git
   cd HMS

2. Install dependencies
   pip install flask bcrypt

3. Initialize the database
   python db_init.py

4. Run the app
   python app.py

5. Open http://127.0.0.1:5000

## Default Login
Username: admin
Password: admin123