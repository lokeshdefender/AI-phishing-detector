from app.analyzer import analyze_email


def test_extract_and_score():
    text = "From: PayPal <service@secure-paypal.com>\nHello, please verify your account: https://192.168.0.1/login or http://bit.ly/abc123. Please enter your password immediately!"
    res = analyze_email(text)
    assert isinstance(res['urls'], list)
    assert res['score'] > 0
    assert 'confidence' in res and 0 <= res['confidence'] <= 100
    indicators = [i['indicator'] for i in res['indicators']]
    assert 'ip_in_url' in indicators or 'url_shortener' in indicators or 'credential_harvest' in indicators

if __name__ == '__main__':
    print('Manual run: analyzing sample')
    print(analyze_email('Please click https://example.com to confirm your password'))
