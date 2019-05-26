import json


def test_login(test_client, init_database):
    response = test_client.post(
        '/api/login',
        data=json.dumps(dict(
            username='testuser',
            password='foobar'
        )),
        content_type='application/json'
    )
    json_data = response.get_json()
    assert json_data == {
        'message': 'Log in properly',
        'access_token': f"{json_data['access_token']}",
        'refresh_token': f"{json_data['refresh_token']}",
        'code': 200
    }

def test_get_lists(test_client, init_database, access_token):
    response = test_client.get(
        '/api/lists',
        headers={'Authorization': f'Bearer {access_token}'}
        )
    assert response.status_code == 200