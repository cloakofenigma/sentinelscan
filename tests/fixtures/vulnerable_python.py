import os
import pickle
import subprocess

def run_command(user_input):
    """Command injection vulnerability."""
    os.system("ls " + user_input)

def evaluate_expression(data):
    """Code execution via eval."""
    result = eval(data)
    return result

def load_data(serialized_bytes):
    """Insecure deserialization."""
    return pickle.loads(serialized_bytes)

def read_file(filename):
    """Path traversal."""
    with open("/data/" + filename) as f:
        return f.read()

def execute_query(db, table_name):
    """SQL injection."""
    db.execute("SELECT * FROM " + table_name)

# Safe function
def safe_function():
    """No vulnerabilities here."""
    items = [1, 2, 3]
    return sum(items)
