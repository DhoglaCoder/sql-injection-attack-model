import torch
import torch.nn as nn
from transformers import BertTokenizer, BertModel
import re
import urllib.parse
import base64
import json

# Define the BertTextCNNClassifier model class
class BertTextCNNClassifier(nn.Module):
    def __init__(self, bert_model, num_filters, filter_sizes, output_size):
        super(BertTextCNNClassifier, self).__init__()
        self.bert_model = bert_model
        self.num_filters = num_filters
        self.filter_sizes = filter_sizes
        self.conv_layers = nn.ModuleList([
            nn.Conv1d(in_channels=bert_model.config.hidden_size, out_channels=num_filters, kernel_size=fs)
            for fs in filter_sizes
        ])
        self.dropout = nn.Dropout(0.2)
        self.fc = nn.Linear(num_filters * len(filter_sizes), output_size)

    def forward(self, input_ids, attention_mask):
        with torch.no_grad():
            outputs = self.bert_model(input_ids=input_ids, attention_mask=attention_mask)

        embedded = outputs.last_hidden_state.transpose(1, 2)
        pooled_outputs = []
        for conv_layer in self.conv_layers:
            conv_out = nn.functional.relu(conv_layer(embedded))
            pooled_out, _ = torch.max(conv_out, dim=2)
            pooled_outputs.append(pooled_out)

        pooled_outputs = torch.cat(pooled_outputs, dim=1)
        pooled_outputs = self.dropout(pooled_outputs)
        logits = self.fc(pooled_outputs)
        return logits

# Enhanced preprocessing functions
def decode_sql(encoded_string):
    decoded_string = encoded_string
    try:
        decoded_string = bytes.fromhex(encoded_string).decode('ascii')
    except:
        pass
    try:
        decoded_string = bytes.fromhex(encoded_string).decode('unicode_escape')
    except:
        pass
    try:
        decoded_string = json.loads(encoded_string)
    except:
        pass
    try:
        decoded_string = urllib.parse.unquote(encoded_string)
    except:
        pass
    try:
        decoded_string = base64.b64decode(encoded_string).decode('utf-8')
    except:
        pass
    return decoded_string

def identify_sql_injection_patterns(query):
    """Check for common SQL injection patterns"""
    if not isinstance(query, str):
        return 0

    # Common SQL injection indicators - weight each pattern
    patterns = [
        (r'(\'|\").*(\-\-|#|\/\*)', 3),  # Comment sequences with quotes
        (r'\bunion\b.*\bselect\b', 5),   # UNION SELECT statements
        (r'\bor\b.*(\'|\")?\s*\d+\s*=\s*\d+', 4),  # OR conditions with numeric equality
        (r'\b(drop|delete|update|insert)\b.*\b(table|into|from|set)\b', 5),  # Data manipulation commands
        (r';.*(\bexec\b|\bxp_\w+\b)', 5),  # Stacked queries with command execution
        (r'\bwaitfor\b.*\bdelay\b', 5),  # Time-based attacks
        (r'\bconvert\b.*\bint\b', 3),  # Type conversion attacks
        (r'\bselect\b.*\bfrom\b.*\binformation_schema\b', 5),  # Schema discovery
        (r'(\%27|\%22|\%2D|\%23)', 3),  # URL encoded characters
        (r'\bchar\(\d+\)(\+char\(\d+\))*', 4),  # CHAR() function obfuscation
        (r'(\'|\").*(\'|\")\s*(and|or)\s*(\'|\").*(\'|\")', 3),  # Quote manipulation
        (r'(\bload_file\b|\binfile\b)', 5),  # File operations
        (r'\b(benchmark|sleep)\b.*\(\d+\)', 5),  # Timing functions
        (r'\b1\s*=\s*1\b', 2),  # Common tautology
        (r'(\blike\b|\bin\b).*(\%|_|\[|\])', 3),  # LIKE or IN with wildcards
        (r'\b(true|false)\b.*(\band\b|\bor\b)', 2),  # Boolean logic
    ]

    # Calculate a risk score based on pattern matches
    risk_score = 0
    for pattern, weight in patterns:
        if re.search(pattern, query, re.IGNORECASE):
            risk_score += weight

    return risk_score

def preprocess_query(query):
    """Apply all preprocessing steps to the input query"""
    processed = decode_sql(query)
    # Store original case for pattern matching
    original = processed
    # For BERT, we still use lowercase for better embedding lookup
    processed_lower = processed.lower() if isinstance(processed, str) else str(processed).lower()
    # Add spaces around special SQL characters to help with tokenization
    processed_spaced = re.sub(r'([<>=!;\'\")(])', r' \1 ', processed_lower)
    # Limit extra spaces
    processed_cleaned = re.sub(r'\s+', ' ', processed_spaced).strip()

    # Calculate risk score from original query
    risk_score = identify_sql_injection_patterns(original)

    return processed_cleaned, risk_score

class SQLInjectionDetector:
    def __init__(self, model_path='sql_injection_model-1.pth', risk_threshold=4):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.risk_threshold = risk_threshold

        # Initialize BERT
        self.bert_model_name = 'bert-base-uncased'
        self.tokenizer = BertTokenizer.from_pretrained(self.bert_model_name)
        self.bert_model = BertModel.from_pretrained(self.bert_model_name)

        # Initialize the classification model
        num_filters = 100
        filter_sizes = [2, 3, 4]
        output_size = 2
        self.max_length = 128

        # Create and load the model
        self.model = BertTextCNNClassifier(self.bert_model, num_filters, filter_sizes, output_size)

        try:
            self.model.load_state_dict(torch.load(model_path, map_location=self.device))
            print(f"Model loaded successfully from {model_path}")
        except Exception as e:
            print(f"Warning: Could not load model from {model_path}. Using untrained model.")
            print(f"Error: {str(e)}")

        self.model.to(self.device)
        self.model.eval()
        print(f"Model running on {self.device}")

    def rule_based_detection(self, query, risk_score):
        """Apply rule-based detection as a secondary measure"""
        # Combine pattern-based risk score with specific checks

        # Check for specific dangerous patterns
        danger_patterns = [
            # Union-based injections
            r'\bunion\s+(all\s+)?select\b',
            # Comment operator to terminate original query
            r'(\-\-|#|\/\*|\*\/)\s*$',
            # Stacked queries
            r';\s*(select|insert|update|delete|drop|alter|create)\b',
            # OR/AND-based boolean injections with tautologies
            r'(\bor\b|\band\b)\s+[\'\"]?\s*\d+\s*=\s*\d+\s*[\'\"]?',
            # Quote escaping
            r'[\'\"]\s*\+\s*[\'\"]',
            # Time-based blind injection
            r'\b(waitfor|sleep|delay|benchmark)\b',
        ]

        # Check if any dangerous pattern is found
        for pattern in danger_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                return True

        # Return true if risk score is above threshold
        return risk_score >= self.risk_threshold

    def detect(self, query):
        """Detect if a query is a SQL injection attempt using both model and rules"""
        # Preprocess the query
        processed_query, risk_score = preprocess_query(query)

        # Apply rule-based detection first
        rule_detection = self.rule_based_detection(query, risk_score)

        # Tokenize for the model
        encoding = self.tokenizer(
            processed_query,
            truncation=True,
            padding='max_length',
            max_length=self.max_length,
            return_tensors='pt'
        )

        # Move to the correct device
        input_ids = encoding['input_ids'].to(self.device)
        attention_mask = encoding['attention_mask'].to(self.device)

        # Get prediction from model
        with torch.no_grad():
            logits = self.model(input_ids, attention_mask)
            probabilities = torch.softmax(logits, dim=1)[0]
            model_prediction = torch.argmax(logits, dim=1).item()
            model_confidence = probabilities[model_prediction].item()

        # Combine rule-based and model-based detection
        # Model prediction: 0 = safe, 1 = injection
        is_injection = model_prediction == 1 or rule_detection

        # If the rule-based detection triggered, we're very confident
        confidence = max(model_confidence, 0.95 if rule_detection else 0)

        # For analysis purposes, return both signals
        return {
            "is_safe": not is_injection,
            "prediction": "Safe Query" if not is_injection else "SQL Injection Detected",
            "confidence": confidence,
            "processed_query": processed_query,
            "risk_score": risk_score,
            "model_prediction": "Injection" if model_prediction == 1 else "Safe",
            "model_confidence": model_confidence,
            "rule_triggered": rule_detection,
        }

# Example usage with improved CLI interface
if __name__ == "__main__":
    try:
        print("Loading SQL Injection Detection System...")
        detector = SQLInjectionDetector()

        print("\nSQL Injection Detection System")
        print("Type 'exit' to quit, 'test' to run predefined test cases")
        print("-" * 50)

        # Predefined test cases to verify detector functionality
        test_cases = [
            ("SELECT * FROM users WHERE id = 1", False),  # Safe
            ("SELECT * FROM users WHERE id = 1 OR 1=1", True),  # Basic injection
            ("SELECT * FROM users WHERE id = 1; DROP TABLE users;", True),  # Stacked query
            ("SELECT * FROM users WHERE username = 'admin' -- ' AND password = 'anything'", True),  # Comment injection
            ("SELECT * FROM users WHERE id = 1 UNION SELECT username, password FROM admin", True),  # Union based
            ("1'; WAITFOR DELAY '0:0:5' --", True),  # Time-based
            ("SELECT * FROM users WHERE name LIKE '%John%'", False),  # Safe with wildcards
            ("SELECT * FROM users WHERE id = (SELECT MAX(id) FROM users)", False),  # Safe subquery
        ]

        while True:
            query = input("\nEnter a SQL query to check (or 'test', 'exit'): ")

            if query.lower() == 'exit':
                print("Exiting the system. Goodbye!")
                break

            if query.lower() == 'test':
                print("\nRunning test cases to verify detector functionality:")
                for i, (test_query, expected) in enumerate(test_cases):
                    result = detector.detect(test_query)
                    is_correct = (not result["is_safe"]) == expected
                    status = "✓" if is_correct else "✗"
                    print(f"{status} Test {i+1}: {'INJECTION' if expected else 'SAFE'} - {test_query[:50]}...")
                    if not is_correct:
                        print(f"   Expected: {'Injection' if expected else 'Safe'}, Got: {result['prediction']}")
                continue

            if not query.strip():
                continue

            result = detector.detect(query)

            if result["is_safe"]:
                print("\n✅ SAFE: This query appears to be legitimate")
            else:
                print("\n⚠️ ALERT: SQL Injection attempt detected!")

            print(f"Confidence: {result['confidence'] * 100:.2f}%")
            print(f"Risk score: {result['risk_score']}")
            print(f"Model prediction: {result['model_prediction']} (confidence: {result['model_confidence'] * 100:.2f}%)")
            print(f"Rule-based detection: {'Triggered' if result['rule_triggered'] else 'Not triggered'}")
            print(f"Processed query: {result['processed_query']}")

    except Exception as e:
        print(f"An error occurred: {str(e)}")
        import traceback
        traceback.print_exc()