#!/usr/bin/env python3
"""
Test script for Indian-specific PII detection and anonymization
Tests the enhanced compliance features
"""

import json
import requests

# Test data
TEST_DATA = {
    "text": """Rahul Mehta is a 34-year-old software consultant living at Flat 502, Blue Orchid Residency, Near Sunrise Mall, Satellite Road, Ahmedabad, Gujarat 380015, India. He was born on 12 August 1991 and holds an Indian passport numbered ZX4589217, with Aadhaar number 1234-5678-9012 and PAN card number ACBPM9988K. Rahul can be contacted via his personal email rahul.mehta.personal@examplemail.com or his work email rahul.mehta@cloudworks.io, and his primary mobile number is +91-98765-43210 with an alternate number +91-91234-56789. He works as a senior backend engineer at CloudWorks Technologies Pvt. Ltd., earning an annual salary of ₹28,50,000, which is credited monthly to his HDFC Bank savings account ending in 4421, IFSC code HDFC0001873. Rahul is married to Ananya Mehta, born 3 March 1993, and they have a daughter named Ira Mehta, aged 5, who attends Little Stars International School. His medical history includes mild asthma and a previous knee ligament surgery in 2019 at CarePlus Hospital, and he is currently insured under HealthSecure Gold Plan policy number HS-IND-992311. Rahul frequently travels for work, prefers vegetarian meals, owns a white Hyundai Creta with registration GJ-01-AB-7788, and uses online services such as Google Drive, GitHub (username: rahulmehta91), and multiple AI tools for daily productivity and coding assistance.""",
    "pseudonym": "Patient_001"
}

EXPECTED_DETECTIONS = {
    "Aadhaar Number": "1234-5678-9012",
    "PAN Number": "ACBPM9988K",
    "Indian Passport": "ZX4589217",
    "Username": "rahulmehta91",
    "Company Name": "CloudWorks Technologies Pvt. Ltd.",
    "Vehicle Registration": "GJ-01-AB-7788",
    "Insurance Policy Number": "HS-IND-992311",
    "Institution Name": "Little Stars International School",
    "Hospital Name": "CarePlus Hospital",
    "Email": "rahul.mehta@cloudworks.io",
    "Phone": "+91-98765-43210",
    "Full Name": "Rahul Mehta",
    "Birth Date": "12 August 1991",
    "Address": "Ahmedabad, Gujarat",
    "Bank Account": "4421",
}

def test_detect():
    """Test the /detect endpoint"""
    print("\n" + "="*80)
    print("TEST 1: PII DETECTION (/detect endpoint)")
    print("="*80)
    
    try:
        response = requests.post("http://localhost:8080/detect", json=TEST_DATA)
        result = response.json()
        
        print(f"Status Code: {response.status_code}")
        print(f"\nDetected {len(result['entities'])} entities:")
        
        detected_types = {}
        for entity in result['entities']:
            entity_type = entity['type']
            if entity_type not in detected_types:
                detected_types[entity_type] = []
            detected_types[entity_type].append({
                'text': entity['text'],
                'score': entity['score'],
                'method': entity.get('method', 'unknown')
            })
        
        for entity_type, instances in sorted(detected_types.items()):
            print(f"\n  {entity_type}:")
            for inst in instances:
                print(f"    - '{inst['text']}' (score: {inst['score']}, method: {inst['method']})")
        
        return result
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

def test_anonymize():
    """Test the /anonymize endpoint"""
    print("\n" + "="*80)
    print("TEST 2: PII ANONYMIZATION (/anonymize endpoint)")
    print("="*80)
    
    try:
        response = requests.post("http://localhost:8080/anonymize", json=TEST_DATA)
        result = response.json()
        
        print(f"Status Code: {response.status_code}")
        print(f"\nAnonymized {len(result['anonymized_spans'])} PII instances")
        print(f"Pseudonym Preserved: {result.get('pseudonym_preserved', 'N/A')}")
        
        print("\nAnonymized Text (excerpt):")
        anon_text = result['anonymized_text']
        print("-" * 80)
        # Show first 500 chars
        preview = anon_text[:500] + ("..." if len(anon_text) > 500 else "")
        print(preview)
        print("-" * 80)
        
        print("\nAnonymized Spans:")
        for span in result['anonymized_spans'][:10]:  # Show first 10
            print(f"\n  Type: {span['entity_type']}")
            print(f"  Original: '{span['original']}'")
            print(f"  Replacement: '{span['replacement']}'")
        
        if len(result['anonymized_spans']) > 10:
            print(f"\n  ... and {len(result['anonymized_spans']) - 10} more")
        
        return result
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

def test_health():
    """Test the /health endpoint"""
    print("\n" + "="*80)
    print("TEST 0: HEALTH CHECK (/health endpoint)")
    print("="*80)
    
    try:
        response = requests.get("http://localhost:8080/health")
        result = response.json()
        
        print(f"Status Code: {response.status_code}")
        print(f"Status: {result.get('status', 'unknown')}")
        print(f"ML Analyzer: {result.get('ml_analyzer', 'unknown')}")
        print(f"ML Anonymizer: {result.get('ml_anonymizer', 'unknown')}")
        print(f"Detection Mode: {result.get('detection_mode', 'unknown')}")
        
        return result
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return None

def main():
    print("\n" + "#"*80)
    print("# COMPLIANCE TEST SUITE - Indian PII Data")
    print("#"*80)
    
    # Test health first
    health = test_health()
    
    if not health:
        print("\n❌ Service is not running. Please start it with: python main.py")
        return
    
    # Run detection test
    detect_result = test_detect()
    
    # Run anonymization test
    anon_result = test_anonymize()
    
    # Validation
    print("\n" + "="*80)
    print("TEST 3: COMPLIANCE VALIDATION")
    print("="*80)
    
    if detect_result and anon_result:
        detected_entities = detect_result['entities']
        
        print("\nExpected PII Types to Detect:")
        for pii_name, pii_value in EXPECTED_DETECTIONS.items():
            print(f"  - {pii_name}: {pii_value}")
        
        print("\n✅ Checking for Indian-specific identifiers:")
        
        critical_pii = [
            ("Aadhaar", "1234-5678-9012"),
            ("PAN", "ACBPM9988K"),
            ("Passport", "ZX4589217"),
        ]
        
        found_critical = {name: False for name, _ in critical_pii}
        
        for entity in detected_entities:
            text = entity['text'].strip()
            for name, expected_value in critical_pii:
                if expected_value in text:
                    found_critical[name] = True
        
        for name, found in found_critical.items():
            status = "✅" if found else "❌"
            print(f"  {status} {name} Number")
        
        print("\n✅ Checking for organizational data:")
        org_data = [
            ("Company", "CloudWorks"),
            ("Institution", "Little"),
            ("Hospital", "CarePlus"),
            ("Vehicle", "GJ-01-AB"),
            ("Policy", "HS-IND-992311"),
            ("Username", "rahulmehta91"),
        ]
        
        found_org = {name: False for name, _ in org_data}
        
        for entity in detected_entities:
            text = entity['text'].strip()
            for name, search_term in org_data:
                if search_term in text:
                    found_org[name] = True
        
        for name, found in found_org.items():
            status = "✅" if found else "❌"
            print(f"  {status} {name} detected")
        
        print("\n✅ Checking anonymization safety:")
        anon_text = anon_result['anonymized_text']
        
        safety_checks = [
            ("Aadhaar number", "1234-5678-9012"),
            ("PAN number", "ACBPM9988K"),
            ("Passport", "ZX4589217"),
            ("Username", "rahulmehta91"),
            ("Email", "rahul.mehta"),
            ("Phone", "98765-43210"),
        ]
        
        all_safe = True
        for check_name, pii_value in safety_checks:
            is_safe = pii_value not in anon_text
            status = "✅" if is_safe else "❌"
            print(f"  {status} Original {check_name} NOT in output")
            if not is_safe:
                all_safe = False
        
        print("\n" + "="*80)
        if all_safe:
            print("✅ COMPLIANCE TEST PASSED - All PII properly anonymized")
        else:
            print("❌ COMPLIANCE TEST FAILED - Some PII remains in output")
        print("="*80)
    
    print("\n\nNote: For full compliance verification, check COMPLIANCE_ANALYSIS.md")

if __name__ == "__main__":
    main()
