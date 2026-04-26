# 🍳 Cloud Recipe Finder

## 📌 Project Overview

Cloud Recipe Finder is a web-based application designed to help users discover recipes based on ingredients they already have at home. The goal is to simplify meal planning by providing quick, relevant recipe suggestions along with cooking instructions, images, and nutritional information.

This project is being developed as a cloud-based full-stack application, integrating modern web development practices with scalable cloud infrastructure.

---

## 🎯 Purpose

Many people struggle with deciding what to cook using the ingredients they already have. This application solves that problem by:

- Allowing users to input available ingredients  
- Returning matching recipes instantly  
- Providing helpful cooking details and nutritional insights  

---

## 🚀 Features

### Core Features

- 🔍 Search recipes by ingredients  
- 📖 View recipe details (instructions, images)  
- 🥗 Display nutritional information  
- ⭐ Save favorite recipes  
- 💬 Comment and review recipes  

---

### User Management

- User registration and login  
- Secure authentication system  
- Password hashing for security  
- Email verification or multi-factor authentication (MFA)  

---

### Roles

#### Regular Users
- Manage their own comments  
- Save favorite recipes  

#### Admin Users
- Manage all comments  
- Moderate content  

---

## 🧠 APIs Used

The application integrates with external recipe APIs such as:

- Spoonacular API  
- Edamam Recipe API  

These APIs provide recipe data, ingredient matching, and nutrition information.

---

## ☁️ Cloud Architecture

This project is deployed using **Amazon Web Services (AWS)** and follows a scalable, secure cloud architecture.

### Infrastructure Design

- **Virtual Private Cloud (VPC)**
  - 2 Availability Zones for high availability  

- **Public Subnet**
  - Hosts frontend (web server)  

- **Private Subnets**
  - Backend services  
  - Database layer  

---

### Compute & Storage

- EC2 instances for frontend and backend services  

- S3 buckets for:
  - Static assets  
  - Backups  
  - Storage  

---

### Networking & Security

- Security Groups (firewalls between layers)  
- Elastic IP for public access  
- IAM Roles and Policies (no root usage)  

---

### Load Balancing & Scaling

- Application Load Balancer for distributing traffic across instances  

---

### Monitoring & Alerts

- CloudWatch for logging and monitoring  
- Billing alerts for cost control  
