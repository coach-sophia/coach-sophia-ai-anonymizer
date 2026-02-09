"""
Test file demonstrating HIPAA, ISO 27001, and SOC 2 compliance
Tests comprehensive PII/PHI detection and anonymization

KEY BEHAVIOR:
- Birth dates (DOB, date of birth, born on) ARE anonymized
- Other dates (appointment dates, event dates, etc.) are PRESERVED
- Replacements use [redacted X] format (e.g., [redacted name], [redacted location])
- PERSON entities use first initial (e.g., "John Smith" -> "J")
- ORG entities with school keywords use [redacted school]
"""

import requests
import json

# API endpoint (update when deployed)
API_URL = "http://localhost:8080"

# Test cases covering HIPAA, ISO, SOC2 requirements
test_cases = [
    {
        "name": "CRITICAL: Birth Date vs Other Dates - Only DOB should be anonymized",
        "text": """
        Patient: John Smith
        DOB: 05/15/1980
        Appointment Date: 03/20/2024
        Last Visit: 01/15/2024
        Next Appointment: 04/10/2024
        Born on 05/15/1980 in New York
        Email: john@example.com
        """,
        "expected_behavior": "ONLY DOB and 'Born on' date should be anonymized. Appointment dates should be preserved.",
        "expected_entities": ["PERSON", "DATE_OF_BIRTH", "EMAIL_ADDRESS"],
        "should_preserve": ["03/20/2024", "01/15/2024", "04/10/2024"],
        "expected_replacements": ["[redacted email]"]
    },
    {
        "name": "HIPAA PHI - Medical Record with DOB and Age",
        "text": """
        Patient: John Smith
        DOB: 05/15/1980
        Age: 43 years
        Medical Record Number: MRN#12345678
        Health Plan: Insurance#ABC123456789
        Phone: 555-123-4567
        Email: john.smith@email.com
        """,
        "expected_entities": ["PERSON", "DATE_OF_BIRTH", "AGE", "MEDICAL_RECORD_NUMBER", 
                            "HEALTH_PLAN_NUMBER", "PHONE_NUMBER", "EMAIL_ADDRESS"]
    },
    {
        "name": "HIPAA - Elderly Patient (Age > 89)",
        "text": """
        Patient Sarah Johnson, aged 92 years, admitted on 03/15/2024.
        SSN: 123-45-6789
        Address: 123 Main Street, Springfield
        """,
        "expected_entities": ["PERSON", "AGE_OVER_89", "SSN", "LOCATION"],
        "expected_replacements": ["[redacted SSN]", "[redacted location]"]
    },
    {
        "name": "Gender and Demographics (Sensitive Personal Data)",
        "text": """
        Name: Alex Martinez
        Gender: Non-binary
        Date of Birth: 08/22/1995
        Phone: (555) 987-6543
        """,
        "expected_entities": ["PERSON", "GENDER", "DATE_OF_BIRTH", "PHONE_NUMBER"]
    },
    {
        "name": "Financial Data (SOC 2)",
        "text": """
        Credit Card: 4532-1234-5678-9010
        Account Number: Account#987654321012
        Routing Number: 123456789
        Bank: Chase Bank
        """,
        "expected_entities": ["CREDIT_CARD", "ACCOUNT_NUMBER", "ROUTING_NUMBER", "ORGANIZATION"]
    },
    {
        "name": "Device and Vehicle Identifiers (HIPAA)",
        "text": """
        Vehicle: VIN 1HGBH41JXMN109186
        Device Serial: Device#ABC123XYZ789
        IMEI: IMEI:123456789012345
        MAC Address: 00:1B:44:11:3A:B7
        """,
        "expected_entities": ["VIN", "DEVICE_ID", "MAC_ADDRESS"]
    },
    {
        "name": "Credentials and API Keys (SOC 2)",
        "text": """
        API Key: api_key_1234567890abcdefghijklmnop
        Password: MySecurePassword123!
        Access Token: access_token_xyz789abc456def
        """,
        "expected_entities": ["API_KEY", "PASSWORD"]
    },
    {
        "name": "Biometric Data (HIPAA)",
        "text": """
        Patient: Robert Lee
        Fingerprint ID: Fingerprint#FP123456789
        DNA Sample: DNA#GEN987654321ABC
        Facial Recognition: Biometric#FR555888999
        """,
        "expected_entities": ["PERSON", "BIOMETRIC_ID", "GENETIC_MARKER"]
    },
    {
        "name": "CRITICAL: Only Birth Dates Anonymized - Other Dates Preserved",
        "text": """
        Admission Date: 01/15/2024
        Discharge Date: 01/20/2024
        Follow-up: 02/15/2024
        Birth Date: 06/12/1975
        Date of Birth: 1990-03-25
        The event is scheduled for 12/25/2024
        Meeting on 2024-06-15 at 3pm
        """,
        "expected_behavior": "ONLY 'Birth Date' and 'Date of Birth' should be anonymized. All other dates preserved.",
        "should_preserve": ["01/15/2024", "01/20/2024", "02/15/2024", "12/25/2024", "2024-06-15"],
        "should_anonymize": ["06/12/1975", "1990-03-25"]
    },
    {
        "name": "Complex Medical Record (Full PHI)",
        "text": """
        Patient Name: Dr. Emily Chen
        DOB: 11/30/1988
        Age: 35
        Gender: Female
        SSN: 987-65-4321
        MRN: MRN#MED987654
        Insurance: Policy#INS123456789
        Email: emily.chen@hospital.org
        Phone: 555-444-3333
        Prescription: RX#789456123
        Provider NPI: 1234567890
        """,
        "expected_entities": ["PERSON", "DATE_OF_BIRTH", "AGE", "GENDER", "SSN", 
                            "MEDICAL_RECORD_NUMBER", "HEALTH_PLAN_NUMBER", 
                            "EMAIL_ADDRESS", "PHONE_NUMBER", "PRESCRIPTION_NUMBER", "NPI_NUMBER"]
    },
    {
        "name": "Pseudonym Preservation Test",
        "text": """
        User user123 reported: My name is Jane Doe, DOB: 03/15/1990
        Email: jane.doe@example.com
        user123 also mentioned their SSN: 111-22-3333
        """,
        "pseudonym": "user123",
        "expected_behavior": "user123 should NOT be anonymized"
    },
    {
        "name": "CRITICAL: Common Words Should NOT Be Detected as Company/Org",
        "text": """
        Just sharing a bit about myself—I was born back on 12 March '92, so I've seen tech evolve quite a bit over the years.
        I work with software and data science.
        The technology has changed rapidly.
        """,
        "expected_behavior": "'tech', 'evolve', 'software', 'technology' should NOT be anonymized as company names",
        "should_preserve": ["tech", "evolve", "software", "technology", "data science"]
    },
    {
        "name": "Real Company Names SHOULD Be Anonymized",
        "text": """
        I work at Google Inc. and previously at Microsoft Corporation.
        My friend works at Tata Consultancy Services Ltd.
        """,
        "expected_behavior": "Real company names with legal suffixes should be anonymized",
        "should_anonymize": ["Google Inc.", "Microsoft Corporation", "Tata Consultancy Services Ltd."]
    },
    # ===== NEW TEST CASES for Presidio Full Power =====
    {
        "name": "ORG Detection - Schools via ML",
        "text": """
        My child attends Lincoln High School and previously went to St Mary's Academy.
        I graduated from Harvard University.
        """,
        "expected_behavior": "Schools should be detected as ORG and replaced with [redacted school]",
        "expected_replacements": ["[redacted school]"],
        "should_not_contain": ["Lincoln High School", "St Mary's Academy", "Harvard University"]
    },
    {
        "name": "ORG Detection - Companies via ML",
        "text": """
        I work at Amazon and my partner works at Goldman Sachs.
        """,
        "expected_behavior": "Company names should be detected as ORG and replaced with [redacted organization]",
        "expected_replacements": ["[redacted organization]"],
        "should_not_contain": ["Amazon", "Goldman Sachs"]
    },
    {
        "name": "LOCATION Detection - Cities and Addresses",
        "text": """
        I live in San Francisco and commute to Oakland.
        My address is 4217 Piedmont Avenue, Oakland, CA 94611.
        """,
        "expected_behavior": "Locations should be detected and replaced with [redacted location] or [redacted zip]",
        "expected_replacements": ["[redacted location]"],
        "should_not_contain": ["San Francisco", "Oakland", "4217 Piedmont Avenue"]
    },
    {
        "name": "PERSON Detection - First Initial Replacement",
        "text": """
        My therapist Dr. Sarah Williams recommended I talk to you.
        My friend Jose Garcia also suggested coaching.
        """,
        "expected_behavior": "Names should be replaced with first initial (S, J)",
        "should_not_contain": ["Sarah Williams", "Jose Garcia"]
    },
    {
        "name": "Supplementary Regex - ZIP Codes and City,State",
        "text": """
        Please send it to Oakland, CA 94611.
        My previous ZIP was 10001-1234.
        """,
        "expected_behavior": "ZIP codes and City,ST patterns should be detected by supplementary regex",
        "should_not_contain": ["94611", "10001-1234"]
    },
    {
        "name": "Supplementary Regex - Street Addresses",
        "text": """
        My office is at 123 Main Street.
        She lives at 4500 Broadway Avenue, Apt 3B.
        """,
        "expected_behavior": "Street addresses should be detected by supplementary regex",
        "should_not_contain": ["123 Main Street", "4500 Broadway Avenue"]
    },
    {
        "name": "Coaching Domain - Common Words Not PII",
        "text": """
        My coaching session was great today. The mindfulness practice really helped.
        I feel more resilience after therapy. My wellness has improved.
        """,
        "expected_behavior": "Coaching domain words should NOT be anonymized",
        "should_preserve": ["coaching", "mindfulness", "resilience", "therapy", "wellness"]
    },
    {
        "name": "[redacted X] Format Verification",
        "text": """
        John Smith lives at 123 Oak Drive, Oakland, CA 94612.
        Email: john@example.com, Phone: 555-123-4567, SSN: 123-45-6789
        He works at Acme Corp. and attended Stanford University.
        """,
        "expected_behavior": "All replacements should use [redacted X] format",
        "expected_replacements": [
            "[redacted email]", "[redacted phone]", "[redacted SSN]",
            "[redacted location]"
        ]
    },
]

def test_detect_endpoint():
    """Test the /detect endpoint"""
    print("\n" + "="*80)
    print("TESTING DETECTION ENDPOINT")
    print("="*80)
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n[Test {i}] {test_case['name']}")
        print("-" * 80)
        
        payload = {
            "text": test_case["text"],
            "language": "en"
        }
        
        if "pseudonym" in test_case:
            payload["pseudonym"] = test_case["pseudonym"]
        
        try:
            response = requests.post(f"{API_URL}/detect", json=payload)
            
            if response.status_code == 200:
                result = response.json()
                entities = result.get("entities", [])
                
                print(f"✅ Detected {len(entities)} entities:")
                for entity in entities:
                    print(f"   - {entity['type']}: '{entity['text']}' (score: {entity['score']}, method: {entity.get('method', 'N/A')})")
                
                if "expected_entities" in test_case:
                    detected_types = [e['type'] for e in entities]
                    print(f"\n   Expected types: {test_case['expected_entities']}")
                    print(f"   Detected types: {list(set(detected_types))}")
            else:
                print(f"❌ Error: {response.status_code} - {response.text}")
                
        except Exception as e:
            print(f"❌ Exception: {e}")

def test_anonymize_endpoint():
    """Test the /anonymize endpoint"""
    print("\n" + "="*80)
    print("TESTING ANONYMIZATION ENDPOINT")
    print("="*80)
    
    passed = 0
    failed = 0
    
    for i, test_case in enumerate(test_cases, 1):
        print(f"\n[Test {i}] {test_case['name']}")
        print("-" * 80)
        
        payload = {
            "text": test_case["text"],
            "language": "en"
        }
        
        if "pseudonym" in test_case:
            payload["pseudonym"] = test_case["pseudonym"]
        
        try:
            response = requests.post(f"{API_URL}/anonymize", json=payload)
            
            if response.status_code == 200:
                result = response.json()
                test_passed = True
                
                print(f"Original text (first 100 chars):")
                print(f"   {test_case['text'][:100]}...")
                
                print(f"\n   Anonymized text:")
                print(f"   {result['anonymized_text']}")
                
                print(f"\n   Anonymized {len(result['anonymized_spans'])} entities:")
                for span in result['anonymized_spans']:
                    print(f"   - {span['entity_type']}: '{span['original']}' -> '{span['replacement']}'")
                
                # Check for preserved content (should NOT be anonymized)
                if "should_preserve" in test_case:
                    print(f"\n   Checking preserved content:")
                    for text_str in test_case["should_preserve"]:
                        if text_str in result['anonymized_text']:
                            print(f"   PASS '{text_str}' correctly PRESERVED")
                        else:
                            print(f"   FAIL '{text_str}' was incorrectly anonymized!")
                            test_passed = False
                
                # Check for anonymized content (SHOULD be anonymized / removed)
                if "should_anonymize" in test_case:
                    print(f"\n   Checking anonymized content:")
                    for text_str in test_case["should_anonymize"]:
                        if text_str not in result['anonymized_text']:
                            print(f"   PASS '{text_str}' correctly ANONYMIZED")
                        else:
                            print(f"   FAIL '{text_str}' was NOT anonymized!")
                            test_passed = False
                
                # Check content that should NOT appear in anonymized output
                if "should_not_contain" in test_case:
                    print(f"\n   Checking removed PII:")
                    for text_str in test_case["should_not_contain"]:
                        if text_str not in result['anonymized_text']:
                            print(f"   PASS '{text_str}' correctly removed")
                        else:
                            print(f"   FAIL '{text_str}' still present in output!")
                            test_passed = False
                
                # Check that expected replacement formats appear
                if "expected_replacements" in test_case:
                    print(f"\n   Checking replacement formats:")
                    for repl in test_case["expected_replacements"]:
                        if repl in result['anonymized_text']:
                            print(f"   PASS '{repl}' found in output")
                        else:
                            # Also check spans for the replacement
                            span_repls = [s['replacement'] for s in result['anonymized_spans']]
                            if repl in span_repls:
                                print(f"   PASS '{repl}' found in spans")
                            else:
                                print(f"   FAIL '{repl}' not found in output or spans!")
                                test_passed = False
                
                if "pseudonym" in test_case:
                    pseudonym = test_case["pseudonym"]
                    if pseudonym in result['anonymized_text']:
                        print(f"\n   PASS Pseudonym '{pseudonym}' preserved successfully")
                    else:
                        print(f"\n   FAIL Pseudonym '{pseudonym}' not found in result")
                        test_passed = False
                
                if test_passed:
                    passed += 1
                    print(f"\n   === TEST PASSED ===")
                else:
                    failed += 1
                    print(f"\n   === TEST FAILED ===")
            else:
                print(f"FAIL Error: {response.status_code} - {response.text}")
                failed += 1
                
        except Exception as e:
            print(f"FAIL Exception: {e}")
            failed += 1
    
    print(f"\n{'='*80}")
    print(f"ANONYMIZATION RESULTS: {passed} passed, {failed} failed out of {len(test_cases)} tests")
    print(f"{'='*80}")

def test_health_endpoint():
    """Test the /health endpoint"""
    print("\n" + "="*80)
    print("TESTING HEALTH ENDPOINT")
    print("="*80)
    
    try:
        response = requests.get(f"{API_URL}/health")
        
        if response.status_code == 200:
            result = response.json()
            print("\n✅ Service Health:")
            print(json.dumps(result, indent=2))
        else:
            print(f"❌ Error: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"❌ Exception: {e}")

def test_root_endpoint():
    """Test the root endpoint to see compliance info"""
    print("\n" + "="*80)
    print("TESTING ROOT ENDPOINT (Compliance Information)")
    print("="*80)
    
    try:
        response = requests.get(f"{API_URL}/")
        
        if response.status_code == 200:
            result = response.json()
            print("\n✅ Service Information:")
            print(json.dumps(result, indent=2))
        else:
            print(f"❌ Error: {response.status_code} - {response.text}")
            
    except Exception as e:
        print(f"❌ Exception: {e}")

if __name__ == "__main__":
    print("\n" + "="*80)
    print("COMPLIANCE TEST SUITE - HIPAA, ISO 27001, SOC 2")
    print("="*80)
    print(f"API URL: {API_URL}")
    print("\nNOTE: Make sure the API is running before executing tests")
    print("      Start with: python main.py")
    print("="*80)
    
    # Test all endpoints
    test_root_endpoint()
    test_health_endpoint()
    test_detect_endpoint()
    test_anonymize_endpoint()
    
    print("\n" + "="*80)
    print("TEST SUITE COMPLETED")
    print("="*80)
