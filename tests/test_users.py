def test_home_page(test_client):
    """
    GIVEN a Flask application
    WHEN the '/' page is requested (GET)
    THEN check the response is valid
    """
    response = test_client.get('/api/lists')
    assert response.status_code == 500


def test_login(test_client):
    response = test_client.post(
        '/api/login',
        data=dict(
            username='faker',
            password='default'
        )
    )
    assert response.data == 200
