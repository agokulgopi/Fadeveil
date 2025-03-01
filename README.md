## Introduction
This project is divided into two main parts: the frontend and the backend. Below are the instructions to set up and run both parts of the project.

## Prerequisites
- Node.js (v14 or higher)
- npm (v6 or higher)
- Python (v3.8 or higher)
- pip (latest version)
- MongoDB (latest version)

## Frontend

### Installation
1. Navigate to the frontend directory:
 ```bash
 cd /d:/My_final_project/Fadeveil_new_change/frontend
 ```
2. Install the dependencies:
 ```bash
 npm install
 ```

### Running the Frontend
1. Start the development server:
 ```bash
 npm start
 ```
2. Open your browser and navigate to `http://localhost:3000`.

## Backend

### Installation
1. Navigate to the backend directory:
 ```bash
 cd /d:/My_final_project/Fadeveil_new_change/backend
 ```
2. Create a virtual environment:
 ```bash
 python -m venv venv
 ```
3. Activate the virtual environment:
 - On Windows:
  ```bash
  venv\Scripts\activate
  ```
 - On macOS/Linux:
  ```bash
  source venv/bin/activate
  ```
4. Install the dependencies:
 ```bash
 pip install -r requirements.txt
 ```

### Running the Backend
1. Start the MongoDB server:
 ```bash
 mongod
 ```
2. Start the backend server:
 ```bash
 python app.py
 ```
3. The backend server will be running on `http://localhost:5000`.

## Environment Variables
Create a `.env` file in the backend directory and add the following variables:
```
MONGO_URI=mongodb://localhost:27017/fadeveil
SECRET_KEY=your_secret_key
```

## Conclusion
Follow the above steps to set up and run the frontend and backend of the Fadeveil project. If you encounter any issues, please refer to the documentation or contact the project maintainers.
# Fadeveil
# Fadeveil
