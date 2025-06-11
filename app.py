import streamlit as st
import pandas as pd
from your_detector_module import SQLInjectionDetector
import random
import base64
import os

# Set page configuration
st.set_page_config(
    page_title="SQL Shield",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Load CSS
def load_css():
    with open('style.css') as f:
        css = f.read()
    return css

def local_css(file_name):
    try:
        with open(file_name) as f:
            st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)
    except Exception as e:
        st.error(f"Error loading CSS file: {e}")

# Apply CSS
local_css('style.css')

# Add a custom logo
def get_base64_encoded_image(image_path):
    with open(image_path, "rb") as img_file:
        return base64.b64encode(img_file.read()).decode()

# Add animations
animations_css = """
<style>
@keyframes fadeIn {
    from { opacity: 0; }
    to { opacity: 1; }
}

.fade-in {
    animation: fadeIn 1s ease-in-out;
}

@keyframes slideInLeft {
    from { transform: translateX(-50px); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
}

.slide-in-left {
    animation: slideInLeft 0.5s ease-out;
}

@keyframes slideInRight {
    from { transform: translateX(50px); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
}

.slide-in-right {
    animation: slideInRight 0.5s ease-out;
}

@keyframes zoomIn {
    from { transform: scale(0.8); opacity: 0; }
    to { transform: scale(1); opacity: 1; }
}

.zoom-in {
    animation: zoomIn 0.5s ease-out;
}

/* Add smooth transitions to cards and interactive elements */
.card, .safe-badge, .danger-badge, button {
    transition-property: all;
    transition-duration: 0.3s;
    transition-timing-function: ease;
}
</style>
"""

st.markdown(animations_css, unsafe_allow_html=True)

# Initialize session state
if "query_log" not in st.session_state:
    st.session_state.query_log = []

detector = SQLInjectionDetector()

# Enhanced Sidebar
with st.sidebar:
    st.markdown("""
    <div class="sidebar-header">
        <h1>🛡️ SQL Shield</h1>
        <p>Advanced SQL Injection Detection</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.sidebar.markdown("---")
    page = st.sidebar.radio("Navigation", 
                           ["Dashboard", "SQL Detector", "Query Log Viewer", "About Model", "Test Case Playground", "Help"],
    format_func=lambda x: f"{'📊' if x=='Dashboard' else '🛡️' if x=='SQL Detector' else '📁' if x=='Query Log Viewer' else 'ℹ️' if x=='About Model' else '🧪' if x=='Test Case Playground' else '❓'} {x}")
    
    st.sidebar.markdown("---")
    st.markdown('<div class="slide-in-left">', unsafe_allow_html=True)
    st.sidebar.markdown("### Stats")
    if "query_log" in st.session_state:
        total_queries = len(st.session_state.query_log)
        detected_threats = sum(1 for log in st.session_state.query_log if not log.get("Prediction") == "Safe")
        st.sidebar.metric("Total Queries", total_queries)
        st.sidebar.metric("Detected Threats", detected_threats)
    st.markdown('</div>', unsafe_allow_html=True)
    
    # Add sidebar footer
    st.sidebar.markdown("---")
    st.sidebar.markdown("""
    <div style="text-align: center; font-size: 0.8rem; color: #94a3b8;">
        <p>SQL Shield </p>
        <p>© 2025 SQL Shield Team</p>
    </div>
    """, unsafe_allow_html=True)

# Predefined queries for randomized test cases
test_case_queries = {
    "Classic Injection": [
        "SELECT * FROM users WHERE id = 1 OR 1=1",
        "SELECT name FROM students WHERE name = '' OR '1'='1'",
        "' OR '1'='1'; --",
        "SELECT * FROM login WHERE username = 'admin' --",
        "SELECT * FROM accounts WHERE user = 'admin' OR 1=1",
        "SELECT * FROM products WHERE id = '' OR 'x'='x'",
        "SELECT * FROM books WHERE title = 'abc' OR 1=1 --",
        "SELECT * FROM bank WHERE user='admin' AND pass='' OR '1'='1'",
        "SELECT * FROM staff WHERE role='manager' OR 1=1",
        "' OR 1=1 --"
    ],
    "Time-Based Attack": [
        "1'; WAITFOR DELAY '0:0:5' --",
        "'; IF (1=1) WAITFOR DELAY '00:00:05' --",
        "admin' WAITFOR DELAY '00:00:05'--",
        "test' OR SLEEP(5)--",
        "1 AND SLEEP(5)--",
        "' OR pg_sleep(5)--",
        "1); WAITFOR DELAY '0:0:5'--",
        "admin'; WAITFOR TIME '00:00:05'--",
        "SELECT * FROM users WHERE name = 'a' OR SLEEP(5)--",
        "' WAITFOR DELAY '00:00:05'--"
    ],
    "Union Select": [
        "SELECT * FROM users WHERE id = 1 UNION SELECT username, password FROM admin",
        "SELECT name FROM employees WHERE id = 10 UNION SELECT user, pass FROM users",
        "1 UNION SELECT null, version()--",
        "1 UNION SELECT table_name, column_name FROM information_schema.columns--",
        "1 UNION ALL SELECT username, password FROM members--",
        "SELECT id FROM data WHERE id = -1 UNION SELECT 1,2,3--",
        "SELECT * FROM students WHERE id=1 UNION SELECT name, age FROM teachers--",
        "SELECT email FROM users WHERE email = 'x' UNION SELECT credit_card, expiry FROM billing--",
        "1 UNION SELECT name, pass FROM login--",
        "' UNION SELECT null, null--"
    ]
}

def sql_detector_page():
    st.markdown('<div class="zoom-in">', unsafe_allow_html=True)
    st.markdown('<h1 class="main-header">🛡️ SQL Injection Detection</h1>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)
    
    with st.container():
        st.subheader("Enter SQL Query to Analyze")
        query = st.text_area("Query:", height=150)
        col1, col2 = st.columns([1, 6])
        scan_button = col1.button("🔍 Scan", use_container_width=True)
        st.markdown('</div>', unsafe_allow_html=True)
        
        if scan_button and query.strip():
            result = detector.detect(query)
            
            st.markdown('<h3 class="subheader">Analysis Results</h3>', unsafe_allow_html=True)
            
            col1, col2, col3 = st.columns(3)
            with col1:
                if result["is_safe"]:
                    st.markdown('<div class="safe-badge">✅ SAFE</div>', unsafe_allow_html=True)
                else:
                    st.markdown('<div class="danger-badge">⚠️ INJECTION DETECTED</div>', unsafe_allow_html=True)
            with col2:
                st.metric("Confidence", f"{result['confidence'] * 100:.2f}%")
            with col3:
                st.metric("Risk Score", result["risk_score"], 
                         delta=None if result["risk_score"] < 5 else result["risk_score"] - 5)
            
            st.markdown("---")
            tab1, tab2 = st.tabs(["Analysis Details", "Processed Query"])
            
            with tab1:
                col1, col2 = st.columns(2)
                with col1:
                    st.info(f"**Model Prediction:** {result['model_prediction']} ({result['model_confidence'] * 100:.2f}%)")
                with col2:
                    if result["rule_triggered"]:
                        st.warning("**Rule-Based Detection:** Triggered")
                    else:
                        st.success("**Rule-Based Detection:** Not Triggered")
            
            with tab2:
                st.code(result["processed_query"], language="sql")
            
            st.markdown('</div>', unsafe_allow_html=True)
            
            # Log the query
            st.session_state.query_log.append({
                "Query": query,
                "Prediction": result["prediction"],
                "Confidence": f"{result['confidence'] * 100:.2f}%",
                "Risk Score": result["risk_score"],
                "Rule Triggered": result["rule_triggered"]
            })

def query_log_page():
    st.markdown('<div class="zoom-in">', unsafe_allow_html=True)
    st.markdown('<h1 class="main-header">📁 Query Log Viewer</h1>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)
    
    log_df = pd.DataFrame(st.session_state.query_log)

    if log_df.empty:
        st.info("No queries logged yet.")
        st.markdown('</div>', unsafe_allow_html=True)
        return

    col1, col2 = st.columns([2, 1])
    with col1:
        search_keyword = st.text_input("🔍 Search by keyword")
    with col2:
        min_risk = st.slider("Minimum risk score", 0, 10, 0)
    st.markdown('</div>', unsafe_allow_html=True)

    filtered_df = log_df.copy()
    if search_keyword:
        filtered_df = filtered_df[filtered_df["Query"].str.contains(search_keyword, case=False)]
    filtered_df = filtered_df[filtered_df["Risk Score"] >= min_risk]

    # Style the dataframe
    def highlight_risk(val):
        if val == "Safe":
            color = 'rgba(16, 185, 129, 0.2)'  # Light green
        else:
            color = 'rgba(239, 68, 68, 0.2)'  # Light red
        return f'background-color: {color}'
    
    styled_df = filtered_df.style.applymap(highlight_risk, subset=['Prediction'])
    
    st.dataframe(styled_df, use_container_width=True, height=400)
    st.markdown('</div>', unsafe_allow_html=True)

    col1, col2 = st.columns(2)
    csv = filtered_df.to_csv(index=False).encode('utf-8')
    col1.download_button("📥 Download CSV", csv, "query_log.csv", "text/csv")
    if col2.button("🗑️ Clear Log"):
        st.session_state.query_log = []
        st.experimental_rerun()
    st.markdown('</div>', unsafe_allow_html=True)

def about_model_page():
    st.markdown('<div class="zoom-in">', unsafe_allow_html=True)
    st.markdown('<h1 class="main-header">ℹ️ About the SQL Injection Detection Model</h1>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown("""
    ### Overview
    This application uses a hybrid detection approach combining:
    - **BERT-based neural network model with CNN layers** for semantic understanding of queries
    - **Rule-based heuristics** for identifying known SQL injection patterns
    """)
    st.markdown('</div>', unsafe_allow_html=True)
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### Model Details
        - Pretrained model: `bert-base-uncased`
        - Additional CNN layers for pattern extraction (TextCNN)
        - Trained to classify queries as either safe or potential SQL injections
        """)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
        ### Detection Pipeline
        1. Query is preprocessed (decoded, cleaned, spaced)
        2. Rule-based risk score is calculated
        3. Tokenized query passed to model
        4. Predictions are combined with rule-based results
        """)
        st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown("""
    ### Confidence & Risk Score
    - **Confidence** reflects model certainty (softmax output)
    - **Risk Score** is based on regex matches to known attack patterns

    ### Notes
    - If model loading fails, an untrained model will be used and results may be unreliable
    - You can view detection logs and download results from the **Query Log Viewer**
    """)
    st.markdown('</div>', unsafe_allow_html=True)

def test_case_playground():
    st.markdown('<div class="zoom-in">', unsafe_allow_html=True)
    st.markdown('<h1 class="main-header">🧪 Test Case Playground</h1>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown("""
    <div class="card fade-in">
        <p>Test the detector against various SQL injection patterns. Choose a category or write your own query.</p>
    </div>
    """, unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        st.markdown("### Classic Injection")
        if st.button("Run Random Classic", use_container_width=True, key="classic_btn"):
            st.session_state.test_query = random.choice(test_case_queries["Classic Injection"])
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.markdown("### Time-Based Attack")
        if st.button("Run Random Time-Based", use_container_width=True, key="time_btn"):
            st.session_state.test_query = random.choice(test_case_queries["Time-Based Attack"])
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col3:
        st.markdown("### Union Select")
        if st.button("Run Random Union", use_container_width=True, key="union_btn"):
            st.session_state.test_query = random.choice(test_case_queries["Union Select"])
        st.markdown('</div>', unsafe_allow_html=True)

    query = st.text_area("Test Query", st.session_state.get("test_query", ""), height=150)
    test_button = st.button("🔍 Test Query", use_container_width=True)
    st.markdown('</div>', unsafe_allow_html=True)
    
    if test_button and query.strip():
        result = detector.detect(query)
        
        st.markdown('<div class="card zoom-in">', unsafe_allow_html=True)
        st.markdown('<h3 class="subheader">Detection Results</h3>', unsafe_allow_html=True)
        
        # Result Status with Badge
        if result["is_safe"]:
            st.markdown('<div class="safe-badge">✅ SAFE</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="danger-badge">⚠️ INJECTION DETECTED</div>', unsafe_allow_html=True)
        
        # Expected vs Actual
        expected = "Injection Detected" if any(query in qlist for qlist in test_case_queries.values()) else "Safe"
        actual = "Safe" if result["is_safe"] else "Injection Detected"
        
        col1, col2 = st.columns(2)
        with col1:
            st.info(f"**Expected Behavior:** {expected}")
        with col2:
            if expected == actual:
                st.success(f"**Actual Result:** {actual} ✓")
            else:
                st.error(f"**Actual Result:** {actual} ✗")
        
        # Detailed Analysis 
        st.markdown("### Detection Details")
        col1, col2, col3 = st.columns(3)
        
        with col1:
            st.metric("Confidence", f"{result['confidence'] * 100:.2f}%")
        with col2:
            st.metric("Risk Score", result["risk_score"])
        with col3:
            st.metric("Rule Triggers", "Yes" if result["rule_triggered"] else "No")
            
        st.markdown("### Query Analysis")
        st.code(result["processed_query"], language="sql")
        
        # Log the query
        st.session_state.query_log.append({
            "Query": query,
            "Prediction": result["prediction"],
            "Confidence": f"{result['confidence'] * 100:.2f}%",
            "Risk Score": result["risk_score"],
            "Rule Triggered": result["rule_triggered"]
        })
        
        st.markdown('</div>', unsafe_allow_html=True)

def dashboard_page():
    st.markdown('<div class="zoom-in">', unsafe_allow_html=True)
    st.markdown('<h1 class="main-header">📊 Dashboard</h1>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)
    
    if not st.session_state.query_log:
        st.info("No data available. Please analyze some SQL queries first.")
        st.markdown('</div>', unsafe_allow_html=True)
        return
    
    log_df = pd.DataFrame(st.session_state.query_log)
    
    # Convert string percentages to float values for analysis
    log_df["Confidence_Value"] = log_df["Confidence"].str.rstrip('%').astype(float)
    
    # Summary metrics
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("Total Queries", len(log_df))
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        safe_count = log_df[log_df["Prediction"] == "Safe"].shape[0]
        st.metric("Safe Queries", safe_count, f"{safe_count / len(log_df) * 100:.1f}%")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col3:
        threat_count = log_df[log_df["Prediction"] != "Safe"].shape[0]
        st.metric("Detected Threats", threat_count, f"{threat_count / len(log_df) * 100:.1f}%")
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col4:
        avg_risk = log_df["Risk Score"].mean()
        st.metric("Avg Risk Score", f"{avg_risk:.2f}")
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Charts
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Threat Distribution")
        prediction_counts = log_df["Prediction"].value_counts()
        st.bar_chart(prediction_counts)
        st.markdown('</div>', unsafe_allow_html=True)
    
    with col2:
        st.subheader("Risk Score Distribution")
        st.bar_chart(log_df["Risk Score"].value_counts().sort_index())
        st.markdown('</div>', unsafe_allow_html=True)
    
    # Recent Queries
    st.subheader("Recent Queries")
    recent_df = log_df.tail(5).sort_index(ascending=False)
    
    for _, row in recent_df.iterrows():
        col1, col2 = st.columns([3, 1])
        with col1:
            st.code(row["Query"], language="sql")
        with col2:
            if row["Prediction"] == "Safe":
                st.success(f"Safe (Confidence: {row['Confidence']})")
            else:
                st.error(f"Threat (Risk: {row['Risk Score']})")
    st.markdown('</div>', unsafe_allow_html=True)

def help_page():
    st.markdown('<div class="zoom-in">', unsafe_allow_html=True)
    st.markdown('<h1 class="main-header">❓ Help & Documentation</h1>', unsafe_allow_html=True)
    st.markdown('</div>', unsafe_allow_html=True)
    
    st.markdown("""
    ### Getting Started
    
    Welcome to SQL Injection Guardian! This application helps you detect potential SQL injection vulnerabilities in your queries.
    
    1. **SQL Detector**: Analyze individual SQL queries for potential injection vulnerabilities
    2. **Test Case Playground**: Test predefined injection patterns or your own test cases
    3. **Query Log Viewer**: Review your analysis history and export results
    4. **Dashboard**: View analytics of your query scanning activities
    """)
    st.markdown('</div>', unsafe_allow_html=True)
    
    with st.expander("Common SQL Injection Patterns"):
        st.markdown("""
        ### Common SQL Injection Patterns
        
        #### 1. Boolean-Based Attacks
        ```sql
        ' OR '1'='1
        ' OR 1=1 --
        ```
        
        #### 2. Union-Based Attacks
        ```sql
        ' UNION SELECT username, password FROM users --
        ' UNION SELECT null, table_name FROM information_schema.tables --
        ```
        
        #### 3. Time-Based Attacks
        ```sql
        ' OR SLEEP(5) --
        '; WAITFOR DELAY '0:0:5' --
        ```
        
        #### 4. Error-Based Attacks
        ```sql
        ' AND UPDATEXML(1, CONCAT(0x7e, (SELECT user()), 0x7e), 1) --
        ' AND extractvalue(1, concat(0x7e, (SELECT version()))) --
        ```
        """)
    
    with st.expander("Usage Tips"):
        st.markdown("""
        ### Usage Tips
        
        1. **Regular Testing**: Scan your application's SQL queries regularly to identify potential vulnerabilities
        2. **Export Logs**: Save query analysis results for security audits
        3. **Risk Score**: Pay special attention to queries with a risk score above 7
        4. **False Positives**: Some safe queries might be flagged - review them carefully
        5. **Model Confidence**: Higher confidence values mean more reliable predictions
        """)
    
    with st.expander("FAQ"):
        st.markdown("""
        ### Frequently Asked Questions
        
        #### Q: How accurate is the detection model?
        A: The model achieves approximately 95% accuracy on common SQL injection patterns. However, it may occasionally produce false positives or miss highly sophisticated attacks.
        
        #### Q: Can I use this tool for production applications?
        A: This tool is intended for educational and testing purposes. For production systems, consider a comprehensive security solution.
        
        #### Q: How is the risk score calculated?
        A: The risk score combines rule-based pattern matching and model confidence to provide a 0-10 score of potential threat level.
        
        #### Q: Do you store my queries?
        A: Queries are only stored locally in your browser session and are cleared when you close the browser or click "Clear Log".
        """)
    
    st.markdown("""
    ### About SQL Injection
    
    SQL injection is a code injection technique that exploits vulnerabilities in web applications that use SQL databases. 
    Attackers can insert malicious SQL statements that can:
    
    - Bypass authentication
    - Access, modify, or delete data
    - Execute administrative operations on the database
    
    This tool helps you identify potential vulnerabilities before they can be exploited.
    """)
    st.markdown('</div>', unsafe_allow_html=True)

# Main app logic
def main():
    if page == "Dashboard":
        dashboard_page()
    elif page == "SQL Detector":
        sql_detector_page()
    elif page == "Query Log Viewer":
        query_log_page()
    elif page == "About Model":
        about_model_page()
    elif page == "Test Case Playground":
        test_case_playground()
    elif page == "Help":
        help_page()

if __name__ == "__main__":
    main()