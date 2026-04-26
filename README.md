PhantomShield Phishing Detector

A cybersecurity web-based system designed to detect phishing and malicious URLs using heuristic analysis and AI reasoning.

Project Overview  
This system analyzes URLs and detects potential threats such as phishing attacks by evaluating multiple factors including URL structure, domain intelligence, and page behavior. It also provides AI-generated explanations for better understanding of risks.

Features  
- URL threat analysis using heuristic techniques  
- Detection of suspicious patterns (IP usage, @ symbols, redirects, etc.)  
- Domain intelligence (age, TLD, IP analysis)  
- Page content analysis (login forms, password fields, external actions)  
- AI reasoning for explaining threat decisions  
- Modern interactive frontend dashboard  

Technologies Used  
- Python (FastAPI backend)  
- HTML, CSS, JavaScript (Frontend)  
- LangChain + Google Generative AI  
- Requests, BeautifulSoup  
- Machine Learning (scikit-learn)  

Project Structure  

backend  
- main.py (API entry point)  
- detector.py (core detection logic)  
- reasoning_llm.py (AI explanation module)  
- evaluate.py (testing and evaluation)  
- utils.py (helper functions)  

frontend  
- index.html (user interface)  

Setup Instructions  

1. Install dependencies  
pip install -r requirements.txt  

2. Run backend server  
uvicorn main:app --reload  

3. Open frontend  
Open frontend/index.html in browser  

Important Note  
Ensure your .env file contains your API keys and is not uploaded to GitHub.

Author  
Raamesh Manirajan  
