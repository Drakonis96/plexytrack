#!/usr/bin/env python3
"""
Test script to verify 2FA error detection logic
"""

def test_2fa_detection():
    """Test the 2FA error detection logic"""
    
    # Test error messages that should trigger 2FA
    test_errors = [
        # Original error from user
        '(401) unauthorized; https://plex.tv/api/v2/users/signin <?xml version="1.0" encoding="UTF-8"?> <errors> <error code="1029" message="Please enter the verification code" status="401"/> </errors>',
        
        # Other possible variations
        'Two-factor authentication required',
        '2FA required',
        'verification code required',
        'Please enter the verification code',
        'Enter the verification code',
        'unauthorized verification',
        'code="1029"',
        '1029 unauthorized verification',
        'two-factor',
        '2fa',
    ]
    
    # Test error messages that should NOT trigger 2FA
    non_2fa_errors = [
        'Invalid username or password',
        'Network error',
        'Server not found',
        'Connection timeout',
        'unauthorized access denied',
        'forbidden',
    ]
    
    def check_requires_2fa(error_str):
        """Check if error requires 2FA using the same logic as the app"""
        error_str_lower = error_str.lower()
        return any([
            "two-factor" in error_str_lower,
            "2fa" in error_str_lower,
            "verification code" in error_str_lower,
            "code=\"1029\"" in error_str_lower,
            "1029" in error_str_lower and ("verification" in error_str_lower or "unauthorized" in error_str_lower),
            ("unauthorized" in error_str_lower and "verification" in error_str_lower),
            "please enter the verification" in error_str_lower,
            "enter the verification code" in error_str_lower
        ])
    
    print("Testing 2FA error detection...")
    print("=" * 50)
    
    print("\nTesting errors that SHOULD trigger 2FA:")
    for i, error in enumerate(test_errors, 1):
        result = check_requires_2fa(error)
        status = "✓ PASS" if result else "✗ FAIL"
        print(f"{i:2}. {status} - {error[:80]}{'...' if len(error) > 80 else ''}")
    
    print("\nTesting errors that should NOT trigger 2FA:")
    for i, error in enumerate(non_2fa_errors, 1):
        result = check_requires_2fa(error)
        status = "✓ PASS" if not result else "✗ FAIL"
        print(f"{i:2}. {status} - {error}")
    
    # Test the specific user error
    print("\n" + "=" * 50)
    print("Testing the specific user error:")
    user_error = '(401) unauthorized; https://plex.tv/api/v2/users/signin <?xml version="1.0" encoding="UTF-8"?> <errors> <error code="1029" message="Please enter the verification code" status="401"/> </errors>'
    result = check_requires_2fa(user_error)
    print(f"User error: {user_error}")
    print(f"Requires 2FA: {result}")
    print(f"Status: {'✓ SHOULD WORK' if result else '✗ NEEDS FIX'}")

if __name__ == "__main__":
    test_2fa_detection()
