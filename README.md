# API Authentication and Role-Based Access Control System

This project implements API authentication and role-based access control (RBAC) using Laravel Passport for OAuth 2.0 authentication.

## Documentation

For detailed API testing documentation, please refer to the attached PDF file: [API TESTING DOCUMENTATION.pdf](./API%20TESTING%20DOCUMENTATION.pdf)

## API Testing

To facilitate API testing, we provide the following resources:

### Postman Collection
Join our Postman team to access the complete API collection:
[![Run in Postman](https://run.pstmn.io/button.svg)](https://app.getpostman.com/join-team?invite_code=cd5d006ea0a800415c045cf57311e9ad81f880542f72da769dde6416ef0f4915&target_code=122392285660bf247ae898dbef239a5c)

### GitHub Repository
The complete project source code is available at:
[https://github.com/Siz-An/oath_task](https://github.com/Siz-An/oath_task)

## Features

- Laravel Passport for OAuth 2.0 authentication
- Role-based access control (RBAC)
- API token management
- User authentication and authorization
- API testing documentation

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/Siz-An/oath_task.git
   ```

2. Install dependencies:
   ```bash
   composer install
   npm install
   ```

3. Configure your environment:
   ```bash
   cp .env.example .env
   php artisan key:generate
   ```

4. Set up the database and run migrations:
   ```bash
   php artisan migrate
   ```

5. Install Laravel Passport:
   ```bash
   php artisan passport:install
   ```

## API Testing

The system includes comprehensive API testing capabilities. For detailed testing procedures and endpoints documentation, please check the [API TESTING DOCUMENTATION.pdf](./API%20TESTING%20DOCUMENTATION.pdf) file.

## Contributing

Please read the API testing documentation for guidelines on contributing to this project.
