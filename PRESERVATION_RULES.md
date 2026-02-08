# Data Preservation Rules - AI/ML Engineer Review

## Overview

This document confirms which data points are **PRESERVED** (not anonymized) and which are **ANONYMIZED** (replaced with placeholders) by the anonymization API.

---

## ✅ DATA THAT IS PRESERVED (Not Anonymized)

### 1. Dates (Except Birth Dates)
| Data Type | Example | Status |
|-----------|---------|--------|
| Appointment dates | "Appointment: 03/20/2024" | ✅ PRESERVED |
| Event dates | "Meeting on 2024-06-15" | ✅ PRESERVED |
| Admission dates | "Admitted: 01/15/2024" | ✅ PRESERVED |
| Discharge dates | "Discharged: 01/20/2024" | ✅ PRESERVED |
| General dates | "The deadline is 12/31/2024" | ✅ PRESERVED |
| Timestamps | "Created at 2024-01-15 10:30:00" | ✅ PRESERVED |

### 2. Numbers & Quantities
| Data Type | Example | Status |
|-----------|---------|--------|
| Cardinal numbers | "5 items", "100 users" | ✅ PRESERVED |
| Ordinal numbers | "1st place", "2nd floor" | ✅ PRESERVED |
| Quantities | "5 kg", "10 miles" | ✅ PRESERVED |
| Money amounts | "$500", "€100", "₹5000" | ✅ PRESERVED |
| Percentages | "50%", "25 percent" | ✅ PRESERVED |
| Version numbers | "v2.0", "1.2.3" | ✅ PRESERVED |
| Short numbers | "5", "42", "100" | ✅ PRESERVED |

### 3. General Location Names
| Data Type | Example | Status |
|-----------|---------|--------|
| Country names | "United States", "India" | ✅ PRESERVED |
| State names | "California", "Maharashtra" | ✅ PRESERVED |
| City names | "New York", "Mumbai" | ✅ PRESERVED |
| Landmark names | "Eiffel Tower", "Taj Mahal" | ✅ PRESERVED |
| Facility names | "Empire State Building" | ✅ PRESERVED |

**Note**: Only specific **street addresses** with numbers are anonymized (e.g., "123 Main Street, Apt 4B")

### 4. General Context Information
| Data Type | Example | Status |
|-----------|---------|--------|
| Product names | "iPhone", "Windows 11" | ✅ PRESERVED |
| Event names | "Olympics 2024", "Tech Conference" | ✅ PRESERVED |
| Work of art titles | "Harry Potter", "Mona Lisa" | ✅ PRESERVED |
| Legal references | "HIPAA", "GDPR", "SOC 2" | ✅ PRESERVED |
| Languages | "English", "Spanish", "Hindi" | ✅ PRESERVED |
| Nationalities | "American", "Indian" | ✅ PRESERVED |

### 5. Common Words (Not Names)
| Data Type | Example | Status |
|-----------|---------|--------|
| Roles | "Patient", "Doctor", "Manager" | ✅ PRESERVED |
| Days | "Monday", "Friday" | ✅ PRESERVED |
| Months | "January", "December" | ✅ PRESERVED |
| Greetings | "Hello", "Thanks" | ✅ PRESERVED |

### 6. Standard/Non-PII Values
| Data Type | Example | Status |
|-----------|---------|--------|
| Localhost IP | "127.0.0.1" | ✅ PRESERVED |
| Broadcast IP | "255.255.255.255" | ✅ PRESERVED |
| Common router IPs | "192.168.0.1", "10.0.0.1" | ✅ PRESERVED |

---

## 🔒 DATA THAT IS ANONYMIZED

### 1. Personal Identifiers
| Data Type | Example | Replacement |
|-----------|---------|-------------|
| Person names | "John Smith" | `[Person]` |
| Patient names | "Patient: Jane Doe" | `[Patient]` |

### 2. Birth Dates ONLY
| Data Type | Example | Replacement |
|-----------|---------|-------------|
| DOB with keyword | "DOB: 05/15/1980" | `[birth date]` |
| Date of Birth | "Date of Birth: 1990-03-25" | `[birth date]` |
| Born on | "Born on 05/15/1980" | `[birth date]` |
| Birthday | "Birthday: 12/25/1995" | `[birth date]` |

**Key Point**: Generic dates without birth context are PRESERVED.

### 3. Contact Information
| Data Type | Example | Replacement |
|-----------|---------|-------------|
| Email addresses | "john@example.com" | `[email address]` |
| Phone numbers | "555-123-4567" | `[phone number]` |
| Fax numbers | "Fax: 555-987-6543" | `[fax number]` |
| URLs (personal) | "http://personal.site.com" | `[website]` |
| IP addresses (user) | "User IP: 203.45.67.89" | `[IP address]` |

### 4. Government IDs (High Confidence Patterns Only)
| Data Type | Example | Replacement |
|-----------|---------|-------------|
| SSN | "123-45-6789" | `[social security number]` |
| PAN (India) | "ABCDE1234F" | `[PAN number]` |
| Aadhaar (India) | "1234-5678-9012" | `[Aadhaar number]` |
| UK NINO | "AB 12 34 56 C" | `[national ID]` |
| Spanish DNI | "12345678-A" | `[national ID]` |
| Italian CF | "RSSMRA85M01H501Z" | `[national ID]` |
| Singapore NRIC | "S1234567A" | `[national ID]` |

### 5. Financial Information
| Data Type | Example | Replacement |
|-----------|---------|-------------|
| Credit card numbers | "4532-1234-5678-9010" | `[credit card number]` |
| Bank accounts | "Account#123456789" | `[account number]` |

### 6. Medical Identifiers
| Data Type | Example | Replacement |
|-----------|---------|-------------|
| Medical Record Number | "MRN#12345678" | `[medical record number]` |
| Health Plan ID | "Insurance#ABC123" | `[health plan ID]` |
| Prescription Number | "RX#789456" | `[prescription number]` |

### 7. Age Information
| Data Type | Example | Replacement |
|-----------|---------|-------------|
| Age with keyword | "Age: 43" | `[age]` |
| Ages over 89 | "Aged 92 years" | `[age]` |

### 8. Specific Street Addresses
| Data Type | Example | Replacement |
|-----------|---------|-------------|
| Full address | "123 Main Street, Apt 4B" | `[address]` |
| Street address | "456 Oak Avenue" | `[street address]` |

### 9. Credentials & Security
| Data Type | Example | Replacement |
|-----------|---------|-------------|
| API keys | "api_key_abc123def..." | `[API credential]` |
| Passwords | "Password: MyPass123" | `[password]` |
| Usernames | "Username: johndoe123" | `[username]` |

---

## 🛡️ Filtering Logic

### Entity Exclusion Rules

1. **Explicit Exclusion List**: The following spaCy entity types are always preserved:
   - `DATE`, `DATE_TIME`, `TIME` (generic dates)
   - `CARDINAL`, `ORDINAL`, `QUANTITY`, `MONEY`, `PERCENT` (numbers)
   - `EVENT`, `PRODUCT`, `WORK_OF_ART`, `LAW`, `LANGUAGE` (context)
   - `NORP` (nationalities, religions, political groups)
   - `FAC` (facilities/buildings)

2. **Birth Date Exception**: Even if a `DATE` entity is detected, it will be anonymized if the surrounding context contains birth keywords: `birth`, `born`, `dob`, `d.o.b`, `birthday`

3. **Context Window**: 50 characters before and after the entity are checked for context keywords.

### False Positive Prevention

1. **Short entities** (< 3 characters) are skipped
2. **Common words** detected as PERSON are skipped (e.g., "Patient", "Doctor", "Manager")
3. **Version numbers** (e.g., "1.2.3", "v2.0") are skipped
4. **Standard IPs** (localhost, broadcast) are skipped
5. **General locations** (countries, cities) without address format are skipped

### Removed Overly Broad Patterns

The following patterns were **removed** because they matched too many non-PII sequences:
- Patterns matching just N digits (e.g., `\b\d{9}\b`, `\b\d{11}\b`)
- Variable-length digit patterns (e.g., `\b\d{6,10}\b`)

**Kept patterns** require specific format characteristics:
- Letters + digits (e.g., UK NINO: `[A-Z]{2}\d{6}[A-Z]`)
- Specific prefixes (e.g., Singapore NRIC: `[STG]\d{7}[A-Z]`)
- Required separators (e.g., SSN: `\d{3}-\d{2}-\d{4}`)

---

## 📋 Test Scenarios

### Scenario 1: Mixed Dates
**Input:**
```
Patient John Smith, DOB: 05/15/1980
Appointment scheduled for 03/20/2024
Follow-up on 04/15/2024
```

**Expected Output:**
```
Patient [Person], DOB: [birth date]
Appointment scheduled for 03/20/2024    ← PRESERVED
Follow-up on 04/15/2024                 ← PRESERVED
```

### Scenario 2: Numbers and Quantities
**Input:**
```
Order #12345 contains 5 items
Total: $250.00
Version: 2.1.0
```

**Expected Output:**
```
Order #12345 contains 5 items           ← ALL PRESERVED
Total: $250.00                          ← PRESERVED
Version: 2.1.0                          ← PRESERVED
```

### Scenario 3: Locations
**Input:**
```
John lives in New York, USA
His address is 123 Main Street, Apt 5B
```

**Expected Output:**
```
[Person] lives in New York, USA         ← City/Country PRESERVED
His address is [address]                ← Street address ANONYMIZED
```

---

## ✔️ Compliance Confirmation

As an AI/ML Engineer, I confirm:

1. ✅ **Birth dates** are correctly anonymized when context indicates birth
2. ✅ **Other dates** (appointments, events, etc.) are preserved
3. ✅ **Numbers and quantities** are preserved for context
4. ✅ **General locations** (countries, cities) are preserved
5. ✅ **Specific addresses** with street numbers are anonymized
6. ✅ **Common words** are not misidentified as person names
7. ✅ **Version numbers** are not treated as PII
8. ✅ **Standard IP addresses** (localhost, etc.) are preserved
9. ✅ **Financial data** with specific patterns is anonymized
10. ✅ **Government IDs** with specific format requirements are anonymized

---

**Last Updated**: $(date)
**Reviewed By**: AI/ML Engineer (Senior)
