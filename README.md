A Django REST Framework-based authentication API providing user registration with email verification, secure JWT login, and password reset functionality. Features include token-based authentication, custom email workflows, and secure session management, built with Django, DRF, and SimpleJWT.








Core Technologies Used:

Django

Django REST Framework (DRF)

Django Allauth / Custom Email Verification Logic

Simple JWT (for token-based authentication)

Django's built-in Password Reset system (customized for APIs)

SMTP Email Server or services like SendGrid for sending emails

Features:

Secure password hashing and storage

Activation tokens for email confirmation

Password reset tokens for secure password changes

JSON Web Token (JWT) based session management

Custom user model (if implemented) for flexible user fields

Security Measures:

Email verification required before account activation

Password reset tokens expire after a set time

JWTs include expiration and refresh mechanisms


