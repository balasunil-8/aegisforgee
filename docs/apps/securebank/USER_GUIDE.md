# SecureBank User Guide

Complete guide to using all features of SecureBank for both Red Team (vulnerable) and Blue Team (secure) environments.

---

## Table of Contents

1. [Getting Started](#getting-started)
2. [Login Process](#login-process)
3. [Dashboard Overview](#dashboard-overview)
4. [Navigation Guide](#navigation-guide)
5. [Account Management](#account-management)
6. [Money Transfers](#money-transfers)
7. [Transaction History](#transaction-history)
8. [Profile Management](#profile-management)
9. [Settings Configuration](#settings-configuration)
10. [Team Switching](#team-switching)
11. [Tips and Tricks](#tips-and-tricks)
12. [Common Tasks](#common-tasks)

---

## Getting Started

### Prerequisites

Before using SecureBank, ensure:
- ✅ Red Team API is running on port 5001
- ✅ Blue Team API is running on port 5002
- ✅ Frontend is accessible at http://localhost:8000
- ✅ You have test account credentials

### First Time Access

1. Open your web browser
2. Navigate to `http://localhost:8000`
3. You should see the SecureBank login page
4. Choose your team (Red Team or Blue Team)
5. Log in with test credentials

---

## Login Process

### Step-by-Step Login

#### 1. Access the Login Page

Open http://localhost:8000 in your browser.

**Login Screen Components:**
- **Team Selector**: Choose Red Team or Blue Team
- **Username Field**: Enter your username
- **Password Field**: Enter your password
- **Login Button**: Submit credentials

#### 2. Select Your Team

**Red Team (Vulnerable)**:
- Contains security vulnerabilities
- For learning exploitation techniques
- API runs on port 5001
- **Use for**: Security testing and learning

**Blue Team (Secure)**:
- Contains security protections
- Demonstrates secure coding
- API runs on port 5002
- **Use for**: Comparing secure implementations

#### 3. Enter Credentials

**Default Test Accounts:**

| Username | Password | Account Balance | Account Number |
|----------|----------|-----------------|----------------|
| alice    | alice123 | $5,000.00      | 1001          |
| bob      | bob123   | $3,000.00      | 1002          |
| charlie  | charlie123 | $7,500.00    | 1003          |
| david    | david123 | $2,000.00      | 1004          |

**Example Login:**
```
Team: Red Team
Username: alice
Password: alice123
```

#### 4. Click Login

After clicking login:
- System validates credentials
- Creates session
- Redirects to dashboard
- Displays welcome message

### Login Troubleshooting

**Problem**: Invalid credentials message

**Solution**:
- Verify username and password are correct
- Check caps lock is off
- Ensure no extra spaces
- Try default credentials: alice/alice123

**Problem**: Cannot connect to API

**Solution**:
- Check API is running
- Verify correct team selected
- Check browser console for errors
- Confirm API ports are correct

**Problem**: Login button not responding

**Solution**:
- Check JavaScript is enabled
- Try refreshing the page
- Clear browser cache
- Try different browser

---

## Dashboard Overview

After successful login, you'll see the main dashboard.

### Dashboard Components

#### 1. Header Section
- **Bank Logo**: SecureBank branding
- **Team Badge**: Shows current team (Red/Blue)
- **Navigation Menu**: Access different sections
- **Logout Button**: End your session

#### 2. Welcome Message
```
Welcome back, Alice!
```
- Personalized greeting
- Shows current username
- Confirms successful authentication

#### 3. Account Summary Card

**Displays:**
- **Account Number**: Your unique account ID (e.g., 1001)
- **Current Balance**: Available funds ($5,000.00)
- **Account Type**: Checking or Savings
- **Last Login**: Timestamp of previous login

**Example:**
```
┌─────────────────────────┐
│   Account Summary       │
├─────────────────────────┤
│ Account: 1001          │
│ Balance: $5,000.00     │
│ Type: Checking         │
│ Last Login: 2024-01-15 │
└─────────────────────────┘
```

#### 4. Quick Actions Panel

**Available Actions:**
- **Transfer Money**: Send funds to another account
- **View Transactions**: See transaction history
- **Edit Profile**: Update personal information
- **Settings**: Configure account preferences

#### 5. Recent Transactions

Shows last 5 transactions:
- Date and time
- Transaction type (debit/credit)
- Amount
- Recipient/sender
- Running balance

---

## Navigation Guide

### Main Navigation Menu

#### Home/Dashboard
- Click "Dashboard" to return to main page
- Shows account summary and quick actions
- Displays recent activity

#### Transfers
- Click "Transfer" to send money
- Access transfer form
- View transfer status

#### History
- Click "History" or "Transactions"
- View all past transactions
- Filter and search transactions

#### Profile
- Click "Profile" or username
- Edit personal information
- Change password
- View account details

#### Settings
- Click "Settings" gear icon
- Configure preferences
- Manage security settings
- Notification preferences

#### Logout
- Click "Logout" button
- Ends current session
- Returns to login page
- Clears session data

### Keyboard Shortcuts

- `Alt + D`: Go to Dashboard
- `Alt + T`: Open Transfer page
- `Alt + H`: View History
- `Alt + P`: Open Profile
- `Alt + L`: Logout

---

## Account Management

### Viewing Account Details

#### From Dashboard:
1. Account information is displayed prominently
2. Shows account number, balance, type
3. Updates in real-time

#### From Profile:
1. Click "Profile" in navigation
2. View detailed account information:
   - Full name
   - Email address
   - Phone number
   - Address
   - Account creation date
   - Account status

### Understanding Account Balance

**Balance Components:**
- **Available Balance**: Money you can spend
- **Pending Transactions**: Transfers in progress
- **Total Balance**: Available + Pending

**Balance Updates:**
- Immediate for completed transfers
- Real-time refresh on dashboard
- Historical balance in transaction history

### Account Limits

**Transfer Limits:**
- **Per Transaction**: $10,000
- **Daily Limit**: $50,000
- **Monthly Limit**: $200,000

**Note**: Limits may vary by account type and security level.

---

## Money Transfers

### Creating a Transfer

#### Step 1: Access Transfer Page
- Click "Transfer" in navigation
- Or click "Transfer Money" on dashboard

#### Step 2: Fill Transfer Form

**Required Fields:**
- **To Account**: Recipient account number (e.g., 1002)
- **Amount**: Transfer amount (e.g., 100.00)
- **Description** (optional): Purpose of transfer

**Example:**
```
To Account: 1002
Amount: $500.00
Description: Rent payment
```

#### Step 3: Review Transfer

**Verify Details:**
- Recipient account is correct
- Amount is accurate
- Sufficient funds available
- Description is clear

#### Step 4: Submit Transfer

- Click "Transfer" or "Submit" button
- Wait for confirmation
- Review success message
- New balance displayed

### Transfer Confirmation

**Success Message:**
```
✓ Transfer Successful!
$500.00 sent to account 1002
New Balance: $4,500.00
Transaction ID: TXN123456
```

**Failure Message:**
```
✗ Transfer Failed
Insufficient funds
Required: $500.00
Available: $450.00
```

### Transfer Types

#### Internal Transfer
- Between SecureBank accounts
- Instant processing
- No fees

#### External Transfer (if enabled)
- To accounts at other banks
- 1-3 day processing
- May include fees

### Transfer Limits and Validations

**Validations:**
- ✓ Sufficient balance
- ✓ Valid recipient account
- ✓ Amount within limits
- ✓ Positive amount
- ✓ Not transferring to self

**Common Errors:**

| Error | Meaning | Solution |
|-------|---------|----------|
| Insufficient funds | Balance too low | Add funds or reduce amount |
| Invalid account | Recipient doesn't exist | Check account number |
| Amount too high | Exceeds limit | Split into smaller transfers |
| Invalid amount | Not a valid number | Enter positive decimal |

---

## Transaction History

### Viewing Transactions

#### Access History:
1. Click "History" or "Transactions" in navigation
2. View all your transactions in chronological order
3. Most recent transactions appear first

#### Transaction Details

Each transaction shows:
- **Date/Time**: When transaction occurred
- **Type**: Credit (received) or Debit (sent)
- **Description**: Transaction purpose
- **Amount**: Transaction value
- **Balance**: Account balance after transaction
- **Transaction ID**: Unique identifier
- **Status**: Completed, Pending, Failed

**Example Transaction:**
```
┌────────────────────────────────────────┐
│ Date: 2024-01-15 10:30 AM             │
│ Type: Debit                            │
│ Description: Transfer to Bob           │
│ Amount: -$500.00                       │
│ Balance: $4,500.00                     │
│ ID: TXN123456                          │
│ Status: Completed                      │
└────────────────────────────────────────┘
```

### Filtering Transactions

#### By Date Range:
```
From: 2024-01-01
To: 2024-01-31
```

#### By Type:
- All Transactions
- Credits (received money)
- Debits (sent money)

#### By Amount Range:
```
Min: $100.00
Max: $1,000.00
```

#### By Search Term:
```
Search: "rent"
Results: Shows all transactions with "rent" in description
```

### Sorting Transactions

**Sort Options:**
- Date (newest first)
- Date (oldest first)
- Amount (highest first)
- Amount (lowest first)
- Type (credits first)
- Type (debits first)

### Exporting Transactions

#### Export as CSV:
1. Click "Export" button
2. Select date range
3. Choose "CSV" format
4. Download file

#### Export as PDF:
1. Click "Export" button
2. Select date range
3. Choose "PDF" format
4. View or download statement

### Understanding Transaction Status

**Completed**: ✓
- Transaction processed successfully
- Funds transferred
- Balance updated

**Pending**: ⏳
- Transaction submitted
- Awaiting processing
- May take 1-3 days

**Failed**: ✗
- Transaction unsuccessful
- Funds not transferred
- Check error message

---

## Profile Management

### Viewing Your Profile

1. Click "Profile" or your username
2. View personal information:
   - Full name
   - Username
   - Email address
   - Phone number
   - Mailing address
   - Account creation date

### Editing Profile Information

#### Step 1: Access Edit Mode
- Click "Edit Profile" button
- Form fields become editable

#### Step 2: Update Information

**Editable Fields:**
- Full Name
- Email Address
- Phone Number
- Street Address
- City
- State
- ZIP Code

**Example:**
```
Full Name: Alice Johnson
Email: alice.johnson@email.com
Phone: (555) 123-4567
Address: 123 Main Street
City: Springfield
State: IL
ZIP: 62701
```

#### Step 3: Save Changes
- Click "Save" or "Update Profile"
- Confirm changes
- View success message

### Changing Password

#### Step 1: Access Password Change
- Go to Profile page
- Click "Change Password"

#### Step 2: Enter Password Details

**Required:**
- Current Password
- New Password
- Confirm New Password

**Password Requirements:**
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

#### Step 3: Submit and Confirm
- Click "Change Password"
- Verify success message
- Use new password on next login

### Profile Security

**Security Tips:**
- Keep email address current
- Use strong, unique password
- Verify profile information regularly
- Report suspicious activity immediately

---

## Settings Configuration

### Account Preferences

#### Notification Settings:
- **Email Notifications**: On/Off
- **Transaction Alerts**: On/Off
- **Security Alerts**: On/Off
- **Monthly Statements**: On/Off

#### Display Preferences:
- **Theme**: Light/Dark mode
- **Language**: English (more coming soon)
- **Date Format**: MM/DD/YYYY or DD/MM/YYYY
- **Currency Display**: $1,000.00 or 1.000,00$

### Security Settings

#### Two-Factor Authentication (Blue Team):
- Enable/Disable 2FA
- SMS or Email verification
- Backup codes

#### Session Management:
- **Session Timeout**: 15, 30, 60 minutes
- **Remember Me**: On/Off
- **Auto Logout**: Enable/Disable

#### Login History:
- View past login attempts
- IP addresses
- Device information
- Login times

### Privacy Settings

#### Data Sharing:
- Marketing communications
- Third-party sharing
- Analytics

#### Account Visibility:
- Public profile
- Searchable account

---

## Team Switching

### Switching Between Red and Blue Team

#### Why Switch Teams?

**Red Team**:
- Test exploitation techniques
- Learn about vulnerabilities
- Practice security testing

**Blue Team**:
- See secure implementations
- Compare defenses
- Learn best practices

#### How to Switch:

**Method 1: Logout and Login**
1. Click "Logout"
2. Return to login page
3. Select different team
4. Login with same credentials

**Method 2: Team Selector (if available)**
1. Click team badge in header
2. Select different team
3. Page refreshes with new team

### Comparing Red vs Blue Team

#### Feature Comparison:

| Feature | Red Team | Blue Team |
|---------|----------|-----------|
| SQL Injection | ❌ Vulnerable | ✓ Protected |
| IDOR | ❌ Vulnerable | ✓ Protected |
| XSS | ❌ Vulnerable | ✓ Protected |
| CSRF | ❌ Vulnerable | ✓ Protected |
| Mass Assignment | ❌ Vulnerable | ✓ Protected |
| Race Conditions | ❌ Vulnerable | ✓ Protected |

#### Testing Workflow:

1. **Start with Red Team**
   - Perform action (e.g., transfer)
   - Note behavior
   - Test for vulnerabilities

2. **Switch to Blue Team**
   - Perform same action
   - Compare behavior
   - Observe security measures

3. **Compare Results**
   - What's different?
   - What protections were added?
   - How does it impact user experience?

---

## Tips and Tricks

### Efficiency Tips

1. **Use Keyboard Shortcuts**
   - Navigate faster with Alt key combinations
   - Tab through form fields

2. **Bookmark Common Tasks**
   - Create browser bookmarks for frequent actions
   - Save time navigating

3. **Use Search in History**
   - Quickly find specific transactions
   - Filter by description or amount

4. **Copy Account Numbers**
   - Use copy button for account numbers
   - Avoid typing errors

### Security Best Practices

1. **Always Logout**
   - End session when finished
   - Especially on shared computers

2. **Verify Transfers**
   - Double-check recipient account
   - Confirm amounts before submitting

3. **Regular Password Changes**
   - Update password periodically
   - Use strong, unique passwords

4. **Monitor Transactions**
   - Review history regularly
   - Report suspicious activity

### Learning Tips

1. **Compare Teams Side-by-Side**
   - Open two browser windows
   - One for Red Team, one for Blue Team
   - Compare same actions

2. **Use Developer Tools**
   - Press F12 to open console
   - Watch network requests
   - Inspect responses

3. **Document Findings**
   - Keep notes on differences
   - Record vulnerability discoveries
   - Track exploitation attempts

4. **Experiment Safely**
   - Red Team is safe to break
   - Try different inputs
   - Test edge cases

---

## Common Tasks

### Task 1: Check Your Balance

**Quick Method:**
1. Look at dashboard
2. Balance shown in Account Summary card

**Detailed Method:**
1. Go to Profile
2. View complete account details
3. See balance history

### Task 2: Send Money to Friend

**Steps:**
1. Click "Transfer" in navigation
2. Enter recipient's account number
3. Enter amount
4. Add description (optional)
5. Click "Transfer"
6. Verify confirmation message

### Task 3: Review Last Month's Transactions

**Steps:**
1. Click "History" in navigation
2. Set date range filter:
   - From: First day of last month
   - To: Last day of last month
3. Click "Apply Filter"
4. Review transactions
5. Export as PDF if needed

### Task 4: Update Email Address

**Steps:**
1. Click "Profile"
2. Click "Edit Profile"
3. Update email field
4. Click "Save"
5. Verify confirmation message

### Task 5: Change Password

**Steps:**
1. Go to Profile
2. Click "Change Password"
3. Enter current password
4. Enter new password (twice)
5. Click "Change Password"
6. Logout and login with new password

### Task 6: Find Specific Transaction

**Steps:**
1. Go to History
2. Use search box
3. Enter keyword (e.g., "rent")
4. Or filter by amount range
5. Review results

### Task 7: Export Statement

**Steps:**
1. Go to History
2. Set date range (e.g., last month)
3. Click "Export"
4. Choose format (PDF or CSV)
5. Download file

---

## Frequently Asked Questions

### Account Questions

**Q: Can I have multiple accounts?**
A: Currently, each user has one account. Contact support for business accounts.

**Q: What if I forget my password?**
A: Click "Forgot Password" on login page. For learning environment, see Setup Guide for default credentials.

**Q: Can I transfer money to external banks?**
A: Not in the current version. Only internal SecureBank transfers are supported.

### Transaction Questions

**Q: How long do transfers take?**
A: Internal transfers are instant. Balance updates immediately.

**Q: Can I cancel a transfer?**
A: Once submitted, transfers are immediate and cannot be cancelled.

**Q: What's the maximum transfer amount?**
A: $10,000 per transaction, $50,000 daily, $200,000 monthly.

### Security Questions

**Q: Is my data secure?**
A: Blue Team implementation uses industry-standard security practices. Red Team intentionally contains vulnerabilities for learning.

**Q: What should I do if I see suspicious activity?**
A: In a real application, contact security immediately. In SecureBank, this is expected for educational purposes.

**Q: Can others see my transactions?**
A: In Red Team, IDOR vulnerabilities may allow this. Blue Team properly restricts access.

---

## Getting Help

### In-App Help

- Look for "?" icons for tooltips
- Hover over elements for hints
- Check error messages for guidance

### Documentation

- **Setup Guide**: Installation and configuration
- **Vulnerability Guide**: Understanding security flaws
- **Exploitation Guide**: Testing vulnerabilities
- **Defense Guide**: Security implementations

### Community

- GitHub Issues for bug reports
- Discussion forums for questions
- Contributing guidelines for improvements

---

## Next Steps

Now that you know how to use SecureBank:

1. **Explore Features**: Try all functionality
2. **Study Vulnerabilities**: Learn about security flaws
3. **Practice Exploitation**: Test Red Team weaknesses
4. **Analyze Defenses**: Compare Blue Team protections
5. **Use Testing Tools**: Try Postman, Burp, SQLMap, ZAP

---

*Happy Banking! (Securely, we hope!)*

*Last Updated: 2024*
